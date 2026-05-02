"""Парсинг и валидация inventory.json и SBOM."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class InventoryItem:
    name: str
    version: str
    vendor: Optional[str] = None


@dataclass
class Inventory:
    vault_name: str
    products: list[InventoryItem]


def load_inventory(path: Path) -> Inventory:
    """Загрузить и распарсить inventory.json."""
    if not path.exists():
        raise FileNotFoundError(f"Inventory не найден: {path}")

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if "products" not in data or not isinstance(data["products"], list):
        raise ValueError("inventory.json должен содержать массив 'products'")

    products = []
    for i, item in enumerate(data["products"]):
        if "name" not in item or "version" not in item:
            raise ValueError(
                f"products[{i}] должен иметь поля 'name' и 'version'"
            )
        products.append(InventoryItem(
            name=item["name"],
            version=item["version"],
            vendor=item.get("vendor"),
        ))

    return Inventory(
        vault_name=data.get("vault_name", "Untitled Vault"),
        products=products,
    )

def load_input(path: Path, input_format: str = "auto") -> "Inventory":
    """Загружает входной файл (inventory или SBOM) с авто-детектом по содержимому.

    input_format:
        "inventory" -- принудительно как inventory.json
        "sbom"      -- принудительно как SBOM (CycloneDX/SPDX)
        "auto"      -- определить по содержимому JSON

    Raises:
        FileNotFoundError, ValueError, json.JSONDecodeError -- при ошибках чтения/формата.
    """
    # Импорт внутри функции, чтобы избежать циклического импорта sbom -> inventory
    from .sbom import load_sbom

    if input_format == "inventory":
        return load_inventory(path)

    if input_format == "sbom":
        return load_sbom(path)

    if input_format == "auto":
        if not path.exists():
            raise FileNotFoundError(f"Файл не найден: {path}")

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        if data.get("bomFormat") == "CycloneDX" or "spdxVersion" in data:
            return load_sbom(path)

        return load_inventory(path)

    raise ValueError(f"Неизвестный формат входного файла: {input_format}")