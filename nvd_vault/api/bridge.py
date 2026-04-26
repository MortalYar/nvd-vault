"""API, доступное из JavaScript через window.pywebview.api."""

import os
import subprocess
import sys

import threading
from pathlib import Path

import webview

from nvd_vault.core.inventory import load_inventory
from nvd_vault.core.matcher import cpe_matches_version
from nvd_vault.core.nvd_client import NvdClient
from nvd_vault.core.vault_builder import VaultBuilder


class Api:
    def __init__(self) -> None:
        # Сюда складываем сообщения прогресса, фронт их забирает
        self._progress_log: list[str] = []
        self._build_running = False

    # ---------- Утилиты ----------

    def ping(self) -> str:
        return "pong: связь с Python работает"

    def select_inventory_file(self) -> dict:
        """Открывает диалог выбора inventory.json."""
        result = webview.windows[0].create_file_dialog(
            webview.OPEN_DIALOG,
            file_types=("JSON files (*.json)", "All files (*.*)"),
        )
        if not result:
            return {"ok": False, "error": "Файл не выбран"}
        return {"ok": True, "path": result[0]}

    def select_vault_folder(self) -> dict:
        """Открывает диалог выбора папки для vault'а."""
        result = webview.windows[0].create_file_dialog(
            webview.FOLDER_DIALOG,
        )
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
        """
        Запускает асинхронную сборку vault.
        Возвращает сразу, не блокируя UI.
        """
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
                self._progress_log.append(f"DONE::{meta['cves_count']}::{meta['products_count']}")
            except Exception as e:
                self._progress_log.append(f"ERROR::{e}")
            finally:
                self._build_running = False

        threading.Thread(target=runner, daemon=True).start()
        return {"ok": True, "started": True}

    def get_build_progress(self) -> dict:
        """Фронт периодически дёргает и забирает накопленные сообщения."""
        log = self._progress_log[:]
        return {
            "running": self._build_running,
            "messages": log,
        }
    
    def open_path_in_explorer(self, path: str) -> dict:
        """Открыть путь в системном файловом менеджере."""
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