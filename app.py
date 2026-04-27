"""
Точка входа NVD Vault.

Запуск: python app.py
"""

import sys
from pathlib import Path

import webview

from nvd_vault.api.bridge import Api


def setup_windows_app_id() -> None:
    """
    Устанавливает уникальный AppUserModelID и иконку для панели задач Windows.
    Без этого Windows показывает иконку pythonw.exe.
    """
    if sys.platform != "win32":
        return

    try:
        import ctypes

        # Уникальный ID приложения. Должен быть уникальным -- иначе Windows
        # сгруппирует наше окно с другими приложениями того же ID.
        app_id = "MortalYar.NvdVault.Desktop.1"
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    except Exception as e:
        print(f"[warn] не удалось установить AppUserModelID: {e}")


def main() -> None:
    setup_windows_app_id()

    api = Api()
    html_path = Path(__file__).parent / "nvd_vault" / "webui" / "index.html"
    icon_path = Path(__file__).parent / "nvd_vault" / "webui" / "assets" / "favicon.ico"

    webview.create_window(
        title="NVD Vault",
        url=str(html_path),
        js_api=api,
        width=1200,
        height=800,
        min_size=(800, 600),
    )
    webview.start(
        debug=True,
        icon=str(icon_path) if icon_path.exists() else None,
    )


if __name__ == "__main__":
    main()