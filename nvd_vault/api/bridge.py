"""API, доступное из JavaScript через window.pywebview.api."""

import base64
import binascii
import json
import os
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

import webview

from nvd_vault.core.dashboard import build_dashboard
from nvd_vault.core.enrichment import EnrichmentClient, compute_risk_score
from nvd_vault.core.frontmatter import parse_frontmatter, read_frontmatter
from nvd_vault.core.graph_builder import build_graph
from nvd_vault.core.inventory import load_input
from nvd_vault.core.matcher import cpe_matches_version
from nvd_vault.core.nvd_client import NvdClient
from nvd_vault.core.remediation import build_remediation_plan
from nvd_vault.core.search_index import SearchIndex
from nvd_vault.core.vault_builder import VaultBuilder

# ----- Конфигурация (для UI и API limits) -----

# Сколько кандидат-vendor'ов вернуть пользователю на выбор в UI
VENDOR_DISCOVERY_LIMIT = 10
# Сколько продуктов показать в превью inventory/SBOM перед полной сборкой
PREVIEW_PRODUCTS_LIMIT = 10
# Обрезание описания CVE для отображения в карточке (полный текст — в .md заметке)
CVE_DESCRIPTION_PREVIEW_CHARS = 300
# Минимальная длина поискового запроса (защита от пустых FTS-запросов)
SEARCH_MIN_QUERY_LENGTH = 2
# Сколько результатов поиска вернуть в UI за один запрос
SEARCH_RESULTS_LIMIT = 50
# Максимальная длина пользовательского имени vault (для UI и meta.json)
VAULT_NAME_MAX_LENGTH = 200
# Максимальный размер data URI для PNG-экспорта графа (защита от мусора из JS)
GRAPH_PNG_MAX_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
# TTL кэша CISA KEV-каталога в памяти Api
KEV_CACHE_TTL_SECONDS = 3600  # 1 час


class Api:
    def __init__(self) -> None:
        self._progress_log: list[str] = []
        self._build_running = False
        self._current_vault: Path | None = None
        self._search_index: SearchIndex | None = None
        self._kev_cache: dict | None = None
        self._kev_cache_at: float = 0.0
        self._kev_lock = threading.Lock()
        self._nvd_client: NvdClient | None = None
        self._nvd_client_key: str | None = None
        self._enricher: EnrichmentClient | None = None

    def _get_kev_data(self, ttl_seconds: int = KEV_CACHE_TTL_SECONDS) -> dict:
        """Возвращает CISA KEV-каталог с кэшем (TTL по умолчанию — 1 час)."""
        # Fast path: кэш ещё свежий, лок не нужен.
        now = time.monotonic()
        if self._kev_cache is not None and (now - self._kev_cache_at) < ttl_seconds:
            return self._kev_cache

        with self._kev_lock:
            # Double-check: другой поток мог уже обновить кэш пока мы ждали лок.
            now = time.monotonic()
            if self._kev_cache is not None and (now - self._kev_cache_at) < ttl_seconds:
                return self._kev_cache

            self._kev_cache = self._get_enricher().fetch_kev_catalog()
            self._kev_cache_at = now
            return self._kev_cache

    def _get_nvd_client(self, api_key: str | None = None) -> NvdClient:
        """Возвращает переиспользуемый NvdClient, пересоздаёт при смене ключа.

        Зачем: каждый NvdClient держит requests.Session с TCP keep-alive.
        Создавать новую сессию на каждый вызов = терять connection pooling.
        """
        if self._nvd_client is None or self._nvd_client_key != api_key:
            self._nvd_client = NvdClient(api_key=api_key)
            self._nvd_client_key = api_key
        return self._nvd_client

    def _get_enricher(self) -> EnrichmentClient:
        """Возвращает переиспользуемый EnrichmentClient (одна сессия на lifetime Api)."""
        if self._enricher is None:
            self._enricher = EnrichmentClient()
        return self._enricher

    # ---------- Утилиты ----------

    def ping(self) -> str:
        return "pong: связь с Python работает"

    @staticmethod
    def _normalize_dialog_result(result: object) -> str | None:
        """Pywebview create_file_dialog возвращает разные типы в зависимости от версии:
        tuple/list для OPEN, str для SAVE на части платформ. Нормализуем к str|None.
        """
        if not result:
            return None
        if isinstance(result, str):
            return result
        # tuple/list — берём первый элемент
        try:
            first = result[0]  # type: ignore[index]
        except (IndexError, TypeError, KeyError):
            return None
        return first if isinstance(first, str) else None

    # Расширения, которые могут привести к выполнению кода при "открытии"
    _EXECUTABLE_SUFFIXES = frozenset(
        {
            # Windows
            ".exe",
            ".bat",
            ".cmd",
            ".com",
            ".scr",
            ".pif",
            ".msi",
            ".msp",
            ".ps1",
            ".vbs",
            ".vbe",
            ".js",
            ".jse",
            ".wsf",
            ".wsh",
            ".hta",
            ".reg",
            ".lnk",
            # macOS / Linux
            ".app",
            ".command",
            ".sh",
            ".bash",
            ".zsh",
            ".desktop",
        }
    )

    def open_path_in_explorer(self, path: str) -> dict:
        if not self._current_vault:
            return {"ok": False, "error": "Vault не открыт"}

        try:
            target = Path(path).resolve(strict=True)
        except (FileNotFoundError, OSError) as e:
            return {"ok": False, "error": f"Путь не существует: {e}"}

        # Защита: путь должен находиться внутри открытого vault
        try:
            target.relative_to(self._current_vault.resolve())
        except ValueError:
            return {"ok": False, "error": "Путь вне vault"}

        # Защита: не открываем исполняемые файлы, даже внутри vault
        if target.suffix.lower() in self._EXECUTABLE_SUFFIXES:
            return {"ok": False, "error": "Открытие исполняемых файлов запрещено"}

        try:
            if sys.platform == "win32":
                os.startfile(str(target))
            elif sys.platform == "darwin":
                subprocess.run(["open", str(target)], check=True)
            else:
                subprocess.run(["xdg-open", str(target)], check=True)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def select_inventory_file(self) -> dict:
        result = webview.windows[0].create_file_dialog(
            webview.OPEN_DIALOG,
            file_types=("JSON files (*.json)", "All files (*.*)"),
        )
        path = self._normalize_dialog_result(result)
        if path is None:
            return {"ok": False, "error": "Файл не выбран"}
        return {"ok": True, "path": path}

    def select_input_file(self) -> dict:
        """Диалог выбора входного файла для сборки vault (inventory или SBOM)."""
        result = webview.windows[0].create_file_dialog(
            webview.OPEN_DIALOG,
            file_types=("JSON files (*.json)", "All files (*.*)"),
        )
        path = self._normalize_dialog_result(result)
        if path is None:
            return {"ok": False, "error": "Файл не выбран"}
        return {"ok": True, "path": path}

    def save_inventory_dialog(self, default_name: str = "inventory.json") -> dict:
        """Диалог сохранения для inventory.json."""
        result = webview.windows[0].create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=default_name,
            file_types=("JSON files (*.json)", "All files (*.*)"),
        )
        path = self._normalize_dialog_result(result)
        if path is None:
            return {"ok": False, "error": "Файл не выбран"}
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

    def write_inventory(self, path: str, vault_name: str, products: list) -> dict:
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
            client = self._get_nvd_client()
            vendors = client.discover_vendors(product.strip())
            return {"ok": True, "vendors": vendors[:VENDOR_DISCOVERY_LIMIT]}
        except RuntimeError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            return {"ok": False, "error": f"Неожиданная ошибка: {e}"}

    def select_vault_folder(self) -> dict:
        result = webview.windows[0].create_file_dialog(webview.FOLDER_DIALOG)
        path = self._normalize_dialog_result(result)
        if path is None:
            return {"ok": False, "error": "Папка не выбрана"}
        return {"ok": True, "path": path}

    # ---------- Сканирование одного продукта ----------

    def scan_product(
        self,
        product: str,
        version: str,
        vendor: str | None = None,
        api_key: str | None = None,
    ) -> dict:
        try:
            client = self._get_nvd_client(api_key=api_key or None)
            if not vendor:
                vendors = client.discover_vendors(product)
                if not vendors:
                    return {"ok": False, "error": f"Vendor для '{product}' не найден"}
                vendor = vendors[0]

            all_vulns = client.fetch_cves(vendor, product)
            matched = [v for v in all_vulns if cpe_matches_version(v, product, version)]

            # Обогащение matched-результатов EPSS и KEV
            if matched:
                enricher = self._get_enricher()
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
                    "critical_now": 0,
                    "critical_likely": 1,
                    "high": 2,
                    "medium": 3,
                    "low": 4,
                }
                matched.sort(
                    key=lambda v: (
                        tier_order.get(v.risk_tier or "low", 99),
                        -(v.risk_score or 0),
                    )
                )

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
                        "description": v.description_en[:CVE_DESCRIPTION_PREVIEW_CHARS],
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

    def build_vault(
        self,
        inventory_path: str,
        vault_path: str,
        api_key: str | None = None,
        input_format: str = "auto",
    ) -> dict:
        if self._build_running:
            return {"ok": False, "error": "Сборка уже запущена"}

        try:
            inventory = load_input(Path(inventory_path), input_format)
        except FileNotFoundError as e:
            return {"ok": False, "error": str(e)}
        except json.JSONDecodeError as e:
            return {"ok": False, "error": f"Битый JSON: {e}"}
        except ValueError as e:
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
                self._progress_log.append(f"DONE::{meta['cves_count']}::{meta['products_count']}")
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

    def rename_vault(self, new_name: str) -> dict:
        """Меняет vault_name в meta.json открытого vault."""
        if not self._current_vault:
            return {"ok": False, "error": "Vault не открыт"}

        new_name = (new_name or "").strip()
        if not new_name:
            return {"ok": False, "error": "Имя не может быть пустым"}
        if len(new_name) > VAULT_NAME_MAX_LENGTH:
            return {
                "ok": False,
                "error": f"Имя слишком длинное (>{VAULT_NAME_MAX_LENGTH} символов)",
            }

        meta_file = self._current_vault / "meta.json"
        if not meta_file.exists():
            return {"ok": False, "error": "meta.json не найден"}

        try:
            with meta_file.open(encoding="utf-8") as f:
                meta = json.load(f)

            old_name = meta.get("vault_name", "")
            meta["vault_name"] = new_name

            with meta_file.open("w", encoding="utf-8") as f:
                json.dump(meta, f, ensure_ascii=False, indent=2)

            return {
                "ok": True,
                "old_name": old_name,
                "new_name": new_name,
                "meta": meta,
            }
        except (OSError, json.JSONDecodeError) as e:
            return {"ok": False, "error": f"Ошибка записи meta.json: {e}"}

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
                result[subfolder].append(
                    {
                        "name": f.stem,
                        "path": f.name,  # относительный
                        "frontmatter": fm,
                    }
                )

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

        vault_root = self._current_vault.resolve()
        results: dict[str, str | None] = {}
        for link in links:
            if link in results:
                continue
            found_path: str | None = None
            for subfolder in ("products", "cves", "cwes"):
                candidate = (self._current_vault / subfolder / f"{link}.md").resolve()
                # Защита от path traversal: путь должен оставаться внутри vault
                try:
                    candidate.relative_to(vault_root)
                except ValueError:
                    continue
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
        if len(query) < SEARCH_MIN_QUERY_LENGTH:
            return {"ok": True, "results": [], "query": query}

        results = self._search_index.search(query, limit=SEARCH_RESULTS_LIMIT)
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
        path = self._normalize_dialog_result(result)
        if path is None:
            return {"ok": False, "error": "Файл не выбран"}
        return {"ok": True, "path": path}

    def select_export_png_path(self, default_name: str = "graph.png") -> dict:
        """Диалог сохранения для PNG-экспорта графа."""
        result = webview.windows[0].create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=default_name,
            file_types=("PNG image (*.png)", "All files (*.*)"),
        )
        path = self._normalize_dialog_result(result)
        if path is None:
            return {"ok": False, "error": "Файл не выбран"}
        return {"ok": True, "path": path}

    def save_graph_png(self, png_path: str, data_uri: str) -> dict:
        """Сохранить PNG-картинку графа на диск из Data URI."""

        # Защита от мусорных входных данных (limit ~50 MB на data URI)
        if len(data_uri) > GRAPH_PNG_MAX_SIZE_BYTES:
            mb = GRAPH_PNG_MAX_SIZE_BYTES // (1024 * 1024)
            return {"ok": False, "error": f"Картинка слишком большая (>{mb} MB)"}

        try:
            # Data URI формата "data:image/png;base64,iVBORw0KG..."
            if "," not in data_uri:
                return {"ok": False, "error": "Некорректный формат картинки"}

            header, encoded = data_uri.split(",", 1)
            if "base64" not in header:
                return {"ok": False, "error": "Ожидается base64-encoded PNG"}

            try:
                png_bytes = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as e:
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
        # Атомарная запись через .tmp: если прога упадёт посередине, целевой файл не появится.
        tmp_target = zip_target.with_suffix(zip_target.suffix + ".tmp")

        try:
            files_added = 0
            with zipfile.ZipFile(tmp_target, "w", zipfile.ZIP_DEFLATED) as zf:
                for file_path in vault.rglob("*"):
                    if not file_path.is_file():
                        continue
                    arcname = file_path.relative_to(vault)
                    zf.write(file_path, arcname=str(arcname))
                    files_added += 1

            if files_added == 0:
                tmp_target.unlink(missing_ok=True)
                return {"ok": False, "error": "Vault пуст — нечего экспортировать"}

            # Атомарный rename — целевой файл появляется только когда полностью готов
            tmp_target.replace(zip_target)

            size_mb = zip_target.stat().st_size / (1024 * 1024)
            return {
                "ok": True,
                "files_added": files_added,
                "size_mb": round(size_mb, 2),
                "path": str(zip_target),
            }
        except Exception as e:
            # Чистим временный файл если он успел создаться
            tmp_target.unlink(missing_ok=True)
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
                    for p in inventory.products[:PREVIEW_PRODUCTS_LIMIT]
                ],
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}
