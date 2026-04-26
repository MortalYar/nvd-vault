"""
Точка входа NVD Vault.

Запуск: python app.py
"""

from pathlib import Path

import webview

from nvd_vault.api.bridge import Api


def main() -> None:
    api = Api()
    html_path = Path(__file__).parent / "nvd_vault" / "webui" / "index.html"

    webview.create_window(
        title="NVD Vault",
        url=str(html_path),
        js_api=api,
        width=1200,
        height=800,
        min_size=(800, 600),
    )
    webview.start(debug=True)


if __name__ == "__main__":
    main()