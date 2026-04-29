"""SBOM import support: CycloneDX JSON and SPDX JSON."""

import json
from pathlib import Path
from typing import Any

from nvd_vault.core.inventory import Inventory, InventoryItem


def load_sbom(path: Path) -> Inventory:
    if not path.exists():
        raise FileNotFoundError(f"SBOM не найден: {path}")

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if data.get("bomFormat") == "CycloneDX":
        return _load_cyclonedx(data, path)

    if "spdxVersion" in data:
        return _load_spdx(data, path)

    raise ValueError("Неизвестный SBOM формат. Поддерживаются CycloneDX JSON и SPDX JSON")


def _load_cyclonedx(data: dict[str, Any], path: Path) -> Inventory:
    products: list[InventoryItem] = []

    for component in data.get("components", []):
        name = component.get("name")
        version = component.get("version")

        if not name or not version:
            continue

        products.append(
            InventoryItem(
                name=name,
                version=version,
                vendor=_extract_cyclonedx_vendor(component),
            )
        )

    if not products:
        raise ValueError("CycloneDX SBOM не содержит компонентов с name и version")

    return Inventory(
        vault_name=data.get("metadata", {}).get("component", {}).get("name", path.stem),
        products=_deduplicate_products(products),
    )


def _load_spdx(data: dict[str, Any], path: Path) -> Inventory:
    products: list[InventoryItem] = []

    for package in data.get("packages", []):
        name = package.get("name")
        version = package.get("versionInfo")

        if not name or not version or version == "NOASSERTION":
            continue

        products.append(
            InventoryItem(
                name=name,
                version=version,
                vendor=_extract_spdx_vendor(package),
            )
        )

    if not products:
        raise ValueError("SPDX SBOM не содержит packages с name и versionInfo")

    return Inventory(
        vault_name=data.get("name", path.stem),
        products=_deduplicate_products(products),
    )


def _extract_cyclonedx_vendor(component: dict[str, Any]) -> str | None:
    supplier = component.get("supplier")

    if isinstance(supplier, dict):
        return supplier.get("name")

    if isinstance(supplier, str):
        return supplier

    group = component.get("group")
    if isinstance(group, str) and group:
        return group

    return None


def _extract_spdx_vendor(package: dict[str, Any]) -> str | None:
    supplier = package.get("supplier")

    if not supplier or supplier == "NOASSERTION":
        return None

    prefixes = ("Organization: ", "Person: ")
    for prefix in prefixes:
        if supplier.startswith(prefix):
            return supplier.removeprefix(prefix).strip()

    return supplier


def _deduplicate_products(products: list[InventoryItem]) -> list[InventoryItem]:
    seen = set()
    result = []

    for product in products:
        key = (
            product.name.lower(),
            product.version.lower(),
            (product.vendor or "").lower(),
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(product)

    return result