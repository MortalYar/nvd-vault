"""API, доступное из JavaScript через window.pywebview.api."""

import json
import os
import re
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path
from typing import Optional

import webview

from nvd_vault.core.frontmatter import parse_frontmatter, read_frontmatter
from nvd_vault.core.remediation import build_remediation_plan
from nvd_vault.core.dashboard import build_dashboard
from nvd_vault.core.enrichment import EnrichmentClient, compute_risk_score
from nvd_vault.core.graph_builder import build_graph
from nvd_vault.core.search_index import SearchIndex
from nvd_vault.core.inventory import load_input
from nvd_vault.core.matcher import cpe_matches_version
from nvd_vault.core.nvd_client import NvdClient
from nvd_vault.core.vault_builder import VaultBuilder

class Api:
    def __init__(self) -> None:
        self._progress_log: list[str] = []
        self._build_running = False
        self._current_vault: Optional[Path] = None
        self._search_index: Optional[SearchIndex] = None
        self._kev_cache: Optional[dict] = None
        self._kev_cache_at: float = 0.0


    def _get_kev_data(self, ttl_seconds: int = 3600) -> dict:
        """Возвращает CISA KEV-каталог с кэшем (TTL по умолчанию — 1 час)."""
        now = time.monotonic()
        if (
            self._kev_cache is not None
            and (now - self._kev_cache_at) < ttl_seconds
        ):
            return self._kev_cache

        enricher = EnrichmentClient()
        self._kev_cache = enricher.fetch_kev_catalog()
        self._kev_cache_at = now
        return self._kev_cache
    
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

    def select_input_file(self) -> dict:
        """Диалог выбора входного файла для сборки vault (inventory или SBOM)."""
        result = webview.windows[0].create_file_dialog(
            webview.OPEN_DIALOG,
            file_types=("JSON files (*.json)", "All files (*.*)"),
        )
        if not result:
            return {"ok": False, "error": "Файл не выбран"}
        return {"ok": True, "path": result[0]}

    def save_inventory_dialog(self, default_name: str = "inventory.json") -> dict:
        """Диалог сохранения для inventory.json."""
        result = webview.windows[0].create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=default_name,
            file_types=("JSON files (*.json)", "All files (*.*)"),
        )
        if not result:
            return {"ok": False, "error": "Файл не выбран"}
        path = result if isinstance(result, str) else result[0]
        return {"ok": True, "path": path}

    def read_inventory(self, path: str) -> dict:
        """Прочитать inventory.json и вернуть его содержимое."""
        try:
            inventory_path = Path(path)
            if not inventory_path.exists():
                return {"ok": False, "error": "Файл не существует"}

            data = json.loads(inventory_path.read_text(encoding="utf-8"))

            # Валидация структуры
            if "products" not in data or not isinstance(data["products"], list):
                return {"ok": False, "error": "Некорректный inventory.json (нет массива products)"}

            return {
                "ok": True,
                "vault_name": data.get("vault_name", ""),
                "products": data["products"],
            }
        except json.JSONDecodeError as e:
            return {"ok": False, "error": f"Ошибка JSON: {e}"}
        except Exception as e:
            return {"ok": False, "error": f"Не удалось прочитать: {e}"}

    def write_inventory(self, path: str, vault_name: str,
                        products: list) -> dict:
        """Записать inventory.json на диск."""
        try:
            inventory_path = Path(path)

            # Минимальная валидация
            if not isinstance(products, list):
                return {"ok": False, "error": "products должен быть списком"}
            for i, item in enumerate(products):
                if not isinstance(item, dict):
                    return {"ok": False, "error": f"products[{i}] должен быть объектом"}
                if not item.get("name") or not item.get("version"):
                    return {
                        "ok": False,
                        "error": f"products[{i}]: обязательны поля 'name' и 'version'",
                    }

            data = {
                "vault_name": vault_name or "Untitled Vault",
                "products": products,
            }

            inventory_path.parent.mkdir(parents=True, exist_ok=True)
            inventory_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return {"ok": True, "path": str(inventory_path)}
        except Exception as e:
            return {"ok": False, "error": f"Не удалось сохранить: {e}"}

    def discover_vendor(self, product: str) -> dict:
        """Найти возможные vendor'ы для продукта через NVD."""
        if not product or not product.strip():
            return {"ok": False, "error": "Имя продукта пустое"}

        try:
            client = NvdClient()
            vendors = client.discover_vendors(product.strip())
            return {"ok": True, "vendors": vendors[:10]}
        except RuntimeError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            return {"ok": False, "error": f"Неожиданная ошибка: {e}"}

    def select_vault_folder(self) -> dict:
        result = webview.windows[0].create_file_dialog(webview.FOLDER_DIALOG)
        if not result:
            return {"ok": False, "error": "Папка не выбрана"}
        return {"ok": True, "path": result[0]}

    # ---------- Сканирование одного продукта ----------

    def scan_product(self, product: str, version: str,
                     vendor: Optional[str] = None,
                     api_key: Optional[str] = None) -> dict:
        try:
            client = NvdClient(api_key=api_key or None)
            if not vendor:
                vendors = client.discover_vendors(product)
                if not vendors:
                    return {"ok": False, "error": f"Vendor для '{product}' не найден"}
                vendor = vendors[0]

            all_vulns = client.fetch_cves(vendor, product)
            matched = [v for v in all_vulns if cpe_matches_version(v, product, version)]

            # Обогащение matched-результатов EPSS и KEV
            if matched:
                enricher = EnrichmentClient()
                cve_ids = [v.cve_id for v in matched]
                epss_data = enricher.fetch_epss_batch(cve_ids)
                kev_data = self._get_kev_data()

                for v in matched:
                    if v.cve_id in epss_data:
                        e = epss_data[v.cve_id]
                        v.epss_score = e["epss_score"]
                        v.epss_percentile = e["epss_percentile"]
                    if v.cve_id in kev_data:
                        k = kev_data[v.cve_id]
                        v.cisa_kev = True
                        v.kev_known_ransomware = k["kev_known_ransomware"]

                    risk = compute_risk_score(
                        cvss_score=v.cvss_score,
                        epss_score=v.epss_score,
                        is_kev=v.cisa_kev,
                        kev_known_ransomware=v.kev_known_ransomware,
                    )
                    v.risk_score = risk["score"]
                    v.risk_tier = risk["tier"]

                # Сортировка: critical_now → critical_likely → high → medium → low
                tier_order = {
                    "critical_now": 0, "critical_likely": 1,
                    "high": 2, "medium": 3, "low": 4
                }
                matched.sort(key=lambda v: (
                    tier_order.get(v.risk_tier or "low", 99),
                    -(v.risk_score or 0),
                ))

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
                        "epss_score": v.epss_score,
                        "epss_percentile": v.epss_percentile,
                        "risk_score": v.risk_score,
                        "risk_tier": v.risk_tier,
                        "kev_known_ransomware": v.kev_known_ransomware,
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
                    api_key: Optional[str] = None,
                    input_format: str = "auto") -> dict:
        if self._build_running:
            return {"ok": False, "error": "Сборка уже запущена"}

        try:
            inventory = load_input(Path(inventory_path), input_format)
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
                fm = read_frontmatter(f)
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
            "frontmatter": parse_frontmatter(content)[0],
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
    
    def resolve_wikilinks(self, links: list) -> dict:
        """Batch-вариант resolve_wikilink: разрешает сразу список ссылок.

        Один round-trip из JS → быстрее, чем N последовательных вызовов.

        Возвращает {ok: True, results: {link_name: relative_path or null}}.
        """
        if not self._current_vault:
            return {"ok": False, "error": "Vault не открыт"}

        results: dict[str, Optional[str]] = {}
        for link in links:
            if link in results:
                continue
            found_path: Optional[str] = None
            for subfolder in ("products", "cves", "cwes"):
                candidate = self._current_vault / subfolder / f"{link}.md"
                if candidate.exists():
                    found_path = f"{subfolder}/{candidate.name}"
                    break
            results[link] = found_path

        return {"ok": True, "results": results}
    
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
    
    def get_dashboard(self) -> dict:
        """Собрать данные для дашборда по открытому vault."""
        if not self._current_vault:
            return {"ok": False, "error": "Vault не открыт"}

        try:
            data = build_dashboard(self._current_vault)
            return {"ok": True, **data}
        except Exception as e:
            return {"ok": False, "error": f"Ошибка сборки дашборда: {e}"}
    
    def get_graph_data(self) -> dict:
        """Собрать узлы и рёбра графа vault'а."""
        if not self._current_vault:
            return {"ok": False, "error": "Vault не открыт"}

        try:
            data = build_graph(self._current_vault)
            return {"ok": True, **data}
        except Exception as e:
            return {"ok": False, "error": f"Ошибка сборки графа: {e}"}
        
    def get_remediation_plan(self) -> dict:
        """Построить план патчинга по открытому vault."""
        if not self._current_vault:
            return {"ok": False, "error": "Vault не открыт"}

        try:
            data = build_remediation_plan(self._current_vault)
            return {"ok": True, **data}
        except Exception as e:
            return {"ok": False, "error": f"Ошибка построения remediation plan: {e}"}

    

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
    
    def select_export_png_path(self, default_name: str = "graph.png") -> dict:
        """Диалог сохранения для PNG-экспорта графа."""
        result = webview.windows[0].create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=default_name,
            file_types=("PNG image (*.png)", "All files (*.*)"),
        )
        if not result:
            return {"ok": False, "error": "Файл не выбран"}
        path = result if isinstance(result, str) else result[0]
        return {"ok": True, "path": path}

    def save_graph_png(self, png_path: str, data_uri: str) -> dict:
        """Сохранить PNG-картинку графа на диск из Data URI."""
        import base64

        # Защита от мусорных входных данных (limit ~50 MB на data URI)
        if len(data_uri) > 50 * 1024 * 1024:
            return {"ok": False, "error": "Картинка слишком большая (>50 MB)"}

        try:
            # Data URI формата "data:image/png;base64,iVBORw0KG..."
            if "," not in data_uri:
                return {"ok": False, "error": "Некорректный формат картинки"}

            header, encoded = data_uri.split(",", 1)
            if "base64" not in header:
                return {"ok": False, "error": "Ожидается base64-encoded PNG"}

            try:
                png_bytes = base64.b64decode(encoded, validate=True)
            except (ValueError, base64.binascii.Error) as e:
                return {"ok": False, "error": f"Не удалось декодировать base64: {e}"}

            # Проверка PNG-сигнатуры
            if not png_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
                return {"ok": False, "error": "Декодированные данные — не PNG"}

            target = Path(png_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(png_bytes)

            size_kb = target.stat().st_size / 1024
            return {
                "ok": True,
                "path": str(target),
                "size_kb": round(size_kb, 1),
            }
        except Exception as e:
            return {"ok": False, "error": f"Ошибка сохранения: {e}"}

    def export_vault_zip(self, zip_path: str) -> dict:
        """Запаковать текущий открытый vault в ZIP."""
        if not self._current_vault:
            return {"ok": False, "error": "Vault не открыт"}

        vault = self._current_vault
        if not vault.exists():
            return {"ok": False, "error": f"Папка vault больше не существует: {vault}"}
        if not vault.is_dir():
            return {"ok": False, "error": f"Путь vault не является папкой: {vault}"}

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

            if files_added == 0:
                # Удалим пустой ZIP — пользователю он бесполезен
                zip_target.unlink(missing_ok=True)
                return {"ok": False, "error": "Vault пуст — нечего экспортировать"}

            size_mb = zip_target.stat().st_size / (1024 * 1024)
            return {
                "ok": True,
                "files_added": files_added,
                "size_mb": round(size_mb, 2),
                "path": str(zip_target),
            }
        except Exception as e:
            return {"ok": False, "error": f"Ошибка архивирования: {e}"}
   
    def preview_build_input(self, input_path: str, input_format: str = "auto") -> dict:
        try:
            inventory = load_input(Path(input_path), input_format)

            return {
                "ok": True,
                "vault_name": inventory.vault_name,
                "products_count": len(inventory.products),
                "products": [
                    {
                        "name": p.name,
                        "version": p.version,
                        "vendor": p.vendor,
                    }
                    for p in inventory.products[:10]
                ],
            }
        except Exception as e:
            return {"ok": False, "error": str(e)} 