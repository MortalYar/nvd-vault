"""
Точка входа NVD Vault.

Запуск GUI:
    python app.py
    nvd-vault

Запуск CLI:
    nvd-vault build examples/sample_inventory.json --out vault/
"""

import json
import logging
import argparse
import os
import sys
from pathlib import Path

from nvd_vault.core.sbom import load_sbom
from nvd_vault.core.logging_config import setup_logging
from nvd_vault.core.inventory import load_inventory
from nvd_vault.core.vault_builder import VaultBuilder

logger = logging.getLogger(__name__)

def setup_windows_app_id() -> None:
    """
    Устанавливает уникальный AppUserModelID и иконку для панели задач Windows.
    Без этого Windows показывает иконку pythonw.exe.
    """
    if sys.platform != "win32":
        return

    try:
        import ctypes

        app_id = "MortalYar.NvdVault.Desktop.1"
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    except Exception as e:
        logger.warning("Не удалось установить AppUserModelID: %s", e)


def run_gui() -> None:
    """Запустить desktop-интерфейс."""
    import webview

    from nvd_vault.api.bridge import Api

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

def validate_build_paths(inventory_path: Path, vault_path: Path) -> None:
    if not inventory_path.exists():
        raise FileNotFoundError(f"Inventory не найден: {inventory_path}")

    if not inventory_path.is_file():
        raise ValueError(f"Inventory должен быть файлом: {inventory_path}")

    if inventory_path.suffix.lower() != ".json":
        raise ValueError("Inventory должен быть JSON-файлом с расширением .json")

    if vault_path.exists() and not vault_path.is_dir():
        raise ValueError(f"Путь для vault уже существует и не является папкой: {vault_path}")

def load_build_input(input_path: Path, input_format: str):
    if input_format == "inventory":
        return load_inventory(input_path)

    if input_format == "sbom":
        return load_sbom(input_path)

    try:
        return load_inventory(input_path)
    except ValueError:
        return load_sbom(input_path)

def run_build_command(args: argparse.Namespace) -> int:
    """Собрать vault из inventory.json в CLI-режиме."""
    inventory_path = Path(args.inventory).expanduser().resolve()

    output_path = args.out
    if not output_path:
        output_path = input("Введите путь для сохранения vault: ").strip()

    if not output_path:
        logger.error("Путь для сохранения vault не может быть пустым")
        return 1

    vault_path = Path(output_path).expanduser().resolve()
    api_key = args.api_key or os.getenv("NVD_API_KEY")

    try:
        validate_build_paths(inventory_path, vault_path)
    except (FileNotFoundError, ValueError) as e:
        logger.error("%s", e)
        return 1

    try:
        inventory = load_build_input(inventory_path, args.input_format)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        logger.error("%s", e)
        return 1

    def show_progress(message: str) -> None:
        print(message, flush=True)

    try:
        builder = VaultBuilder(
            vault_path=vault_path,
            api_key=api_key,
            progress_callback=show_progress,
        )
        meta = builder.build(inventory)
    except RuntimeError as e:
        logger.error("Не удалось собрать vault: %s", e)
        return 1
    except Exception as e:
        logger.error("Неожиданная ошибка при сборке vault: %s", e)
        return 1

    print()
    print("Vault собран успешно:")
    print(f"  Путь: {vault_path}")
    print(f"  Products: {meta['products_count']}")
    print(f"  CVEs: {meta['cves_count']}")
    print(f"  CWEs: {meta['cwes_count']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nvd-vault",
        description="Build and browse a local vulnerability knowledge vault.",
    )
    subparsers = parser.add_subparsers(dest="command")

    build = subparsers.add_parser(
        "build",
        help="Build vault from inventory.json without opening the GUI.",
    )
    build.add_argument(
        "inventory",
        help="Path to inventory.json.",
    )
    build.add_argument(
        "--input-format",
        choices=["inventory", "sbom", "auto"],
        default="auto",
        help="Input format: inventory, sbom, or auto-detect. Default: auto.",
    )
    build.add_argument(
        "--out",
        required=False,
        help="Output folder for generated vault.",
    )
    build.add_argument(
        "--api-key",
        default=None,
        help="NVD API key. If omitted, NVD_API_KEY environment variable is used.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    setup_logging(debug=False)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "build":
        return run_build_command(args)

    run_gui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())