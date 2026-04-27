"""API, доступное из JavaScript через window.pywebview.api."""

import json
import os
import re
import subprocess
import sys
import threading
import zipfile
from pathlib import Path
from typing import Optional

import webview

from nvd_vault.core.graph_builder import build_graph
from nvd_vault.core.search_index import SearchIndex
from nvd_vault.core.inventory import load_inventory
from nvd_vault.core.matcher import cpe_matches_version
from nvd_vault.core.nvd_client import NvdClient
from nvd_vault.core.vault_builder import VaultBuilder


class Api:
    def __init__(self) -> None:
        self._progress_log: list[str] = []
        self._build_running = False
        self._current_vault: Optional[Path] = None
        self._search_index: Optional[SearchIndex] = None

    # ---------- Утилиты ----------

    def ping(self) -> str:
        return "pong: связь с Python работает"

    def open_path_in_explorer(self, path: str) -> dict:
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.run(["open", path], check=True)
            else:
                subprocess.run(["xdg-open", path], check=True)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def select_inventory_file(self) -> dict:
        result = webview.windows[0].create_file_dialog(
            webview.OPEN_DIALOG,
            file_types=("JSON files (*.json)", "All files (*.*)"),
        )
        if not result:
            return {"ok": False, "error": "Файл не выбран"}
        return {"ok": True, "path": result[0]}

    def select_vault_folder(self) -> dict:
        result = webview.windows[0].create_file_dialog(webview.FOLDER_DIALOG)
        if not result:
            return {"ok": False, "error": "Папка не выбрана"}
        return {"ok": True, "path": result[0]}

    # ---------- Сканирование одного продукта ----------

    def scan_product(self, product: str, version: str,
                     vendor: str = None, api_key: str = None) -> dict:
        try:
            client = NvdClient(api_key=api_key or None)
            if not vendor:
                vendors = client.discover_vendors(product)
                if not vendors:
                    return {"ok": False, "error": f"Vendor для '{product}' не найден"}
                vendor = vendors[0]

            all_vulns = client.fetch_cves(vendor, product)
            matched = [v for v in all_vulns if cpe_matches_version(v, product, version)]

            return {
                "ok": True,
                "product": product,
                "version": version,
                "vendor": vendor,
                "total_in_db": len(all_vulns),
                "matched_count": len(matched),
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "severity": v.cvss_severity,
                        "score": v.cvss_score,
                        "description": v.description_en[:300],
                        "published": v.published,
                        "cisa_kev": v.cisa_kev,
                    }
                    for v in matched
                ],
            }
        except RuntimeError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            return {"ok": False, "error": f"Неожиданная ошибка: {e}"}

    # ---------- Vault build ----------

    def build_vault(self, inventory_path: str, vault_path: str,
                    api_key: str = None) -> dict:
        if self._build_running:
            return {"ok": False, "error": "Сборка уже запущена"}

        try:
            inventory = load_inventory(Path(inventory_path))
        except (FileNotFoundError, ValueError) as e:
            return {"ok": False, "error": str(e)}

        self._progress_log = []
        self._build_running = True

        def runner():
            try:
                builder = VaultBuilder(
                    Path(vault_path),
                    api_key=api_key or None,
                    progress_callback=lambda msg: self._progress_log.append(msg),
                )
                meta = builder.build(inventory)
                self._progress_log.append(
                    f"DONE::{meta['cves_count']}::{meta['products_count']}"
                )
            except Exception as e:
                self._progress_log.append(f"ERROR::{e}")
            finally:
                self._build_running = False

        threading.Thread(target=runner, daemon=True).start()
        return {"ok": True, "started": True}

    def get_build_progress(self) -> dict:
        return {
            "running": self._build_running,
            "messages": self._progress_log[:],
        }

    # ---------- Vault browser ----------

    def open_vault(self, vault_path: str) -> dict:
        """Открыть существующий vault для просмотра."""
        path = Path(vault_path)
        if not path.exists() or not path.is_dir():
            return {"ok": False, "error": "Папка не существует"}

        meta_file = path / "meta.json"
        if not meta_file.exists():
            return {"ok": False, "error": "Это не похоже на vault (нет meta.json)"}

        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        except Exception as e:
            return {"ok": False, "error": f"Не удалось прочитать meta.json: {e}"}

        self._current_vault = path

        # Перестраиваем индекс под новый vault
        if self._search_index:
            self._search_index.close()
        self._search_index = SearchIndex()
        try:
            stats = self._search_index.build(path)
            meta["indexed_notes"] = stats["indexed"]
        except Exception as e:
            meta["index_error"] = str(e)

        return {"ok": True, "meta": meta, "path": str(path)}

    def list_vault_notes(self) -> dict:
        """Вернуть список всех заметок vault, сгруппированных по типу."""
        if not self._current_vault:
            return {"ok": False, "error": "Vault не открыт"}

        result: dict[str, list[dict]] = {"products": [], "cves": [], "cwes": []}

        for subfolder in ("products", "cves", "cwes"):
            folder = self._current_vault / subfolder
            if not folder.exists():
                continue
            for f in sorted(folder.glob("*.md")):
                fm = _read_frontmatter(f)
                result[subfolder].append({
                    "name": f.stem,
                    "path": f.name,  # относительный
                    "frontmatter": fm,
                })

        return {"ok": True, "notes": result}

    def read_note(self, relative_path: str) -> dict:
        """Прочитать содержимое заметки."""
        if not self._current_vault:
            return {"ok": False, "error": "Vault не открыт"}

        # Безопасность: запрещаем выход за пределы vault
        target = (self._current_vault / relative_path).resolve()
        try:
            target.relative_to(self._current_vault.resolve())
        except ValueError:
            return {"ok": False, "error": "Недопустимый путь"}

        if not target.exists() or not target.is_file():
            return {"ok": False, "error": "Файл не найден"}

        try:
            content = target.read_text(encoding="utf-8")
        except Exception as e:
            return {"ok": False, "error": f"Не удалось прочитать: {e}"}

        return {
            "ok": True,
            "path": relative_path,
            "name": target.stem,
            "content": content,
            "frontmatter": _parse_frontmatter_block(content)[0],
        }

    def resolve_wikilink(self, link: str) -> dict:
        """Найти заметку по имени из [[wiki-link]]."""
        if not self._current_vault:
            return {"ok": False, "error": "Vault не открыт"}

        # Ищем во всех трёх папках
        for subfolder in ("products", "cves", "cwes"):
            candidate = self._current_vault / subfolder / f"{link}.md"
            if candidate.exists():
                return {
                    "ok": True,
                    "found": True,
                    "relative_path": f"{subfolder}/{candidate.name}",
                }

        return {"ok": True, "found": False}
    
    def search_vault(self, query: str) -> dict:
            """Полнотекстовый поиск по открытому vault."""
            if not self._current_vault:
                return {"ok": False, "error": "Vault не открыт"}
            if not self._search_index:
                return {"ok": False, "error": "Индекс не построен"}

            query = (query or "").strip()
            if len(query) < 2:
                return {"ok": True, "results": [], "query": query}

            results = self._search_index.search(query, limit=50)
            return {"ok": True, "results": results, "query": query}
    
    def get_graph_data(self) -> dict:
        """Собрать узлы и рёбра графа vault'а."""
        if not self._current_vault:
            return {"ok": False, "error": "Vault не открыт"}

        try:
            data = build_graph(self._current_vault)
            return {"ok": True, **data}
        except Exception as e:
            return {"ok": False, "error": f"Ошибка сборки графа: {e}"}

    

    # ---------- Экспорт ----------

    def select_export_zip_path(self, default_name: str = "vault.zip") -> dict:
        """Диалог сохранения файла для ZIP-архива."""
        result = webview.windows[0].create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=default_name,
            file_types=("ZIP archive (*.zip)", "All files (*.*)"),
        )
        if not result:
            return {"ok": False, "error": "Файл не выбран"}
        path = result if isinstance(result, str) else result[0]
        return {"ok": True, "path": path}

    def export_vault_zip(self, zip_path: str) -> dict:
        """Запаковать текущий открытый vault в ZIP."""
        if not self._current_vault:
            return {"ok": False, "error": "Vault не открыт"}

        vault = self._current_vault
        zip_target = Path(zip_path)

        try:
            files_added = 0
            with zipfile.ZipFile(zip_target, "w", zipfile.ZIP_DEFLATED) as zf:
                for file_path in vault.rglob("*"):
                    if not file_path.is_file():
                        continue
                    arcname = file_path.relative_to(vault)
                    zf.write(file_path, arcname=str(arcname))
                    files_added += 1

            size_mb = zip_target.stat().st_size / (1024 * 1024)
            return {
                "ok": True,
                "files_added": files_added,
                "size_mb": round(size_mb, 2),
                "path": str(zip_target),
            }
        except Exception as e:
            return {"ok": False, "error": f"Ошибка архивирования: {e}"}
        

        

# ---------- Утилиты модуля ----------

_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


def _parse_frontmatter_block(content: str) -> tuple[dict, str]:
    """Разбирает YAML frontmatter в начале файла. Возвращает (dict, body)."""
    match = _FRONTMATTER_RE.match(content)
    if not match:
        return {}, content

    yaml_text = match.group(1)
    body = content[match.end():]

    # Простой парсер строк "key: value"
    fm: dict = {}
    for line in yaml_text.split("\n"):
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        fm[key.strip()] = _parse_yaml_value(value.strip())

    return fm, body


def _parse_yaml_value(value: str):
    """Простейший парсер: списки [a, b], числа, bool, строки."""
    if not value:
        return None
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [item.strip() for item in inner.split(",")]
    if value in ("true", "false"):
        return value == "true"
    if value == "null":
        return None
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _read_frontmatter(path: Path) -> dict:
    """Читает только frontmatter, без тела (быстрее для списков)."""
    try:
        content = path.read_text(encoding="utf-8")
    except Exception:
        return {}
    fm, _ = _parse_frontmatter_block(content)
    return fm