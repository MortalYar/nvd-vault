"""Парсинг и валидация inventory.json."""

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