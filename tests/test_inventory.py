import json

import pytest

from nvd_vault.core.inventory import Inventory, InventoryItem, load_inventory


def test_load_inventory_valid_file(tmp_path):
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "vault_name": "Test Vault",
                "products": [
                    {
                        "name": "nginx",
                        "version": "1.24.0",
                        "vendor": "nginx",
                    },
                    {
                        "name": "openssl",
                        "version": "3.0.0",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    inventory = load_inventory(inventory_path)

    assert isinstance(inventory, Inventory)
    assert inventory.vault_name == "Test Vault"
    assert len(inventory.products) == 2

    assert inventory.products[0] == InventoryItem(
        name="nginx",
        version="1.24.0",
        vendor="nginx",
    )
    assert inventory.products[1] == InventoryItem(
        name="openssl",
        version="3.0.0",
        vendor=None,
    )


def test_load_inventory_uses_default_vault_name(tmp_path):
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "products": [
                    {
                        "name": "postgresql",
                        "version": "16.0",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    inventory = load_inventory(inventory_path)

    assert inventory.vault_name == "Untitled Vault"


def test_load_inventory_missing_file_raises_file_not_found(tmp_path):
    inventory_path = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError, match="Inventory не найден"):
        load_inventory(inventory_path)


def test_load_inventory_without_products_raises_value_error(tmp_path):
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps({"vault_name": "Broken Vault"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="массив 'products'"):
        load_inventory(inventory_path)


def test_load_inventory_products_must_be_list(tmp_path):
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "vault_name": "Broken Vault",
                "products": "not-a-list",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="массив 'products'"):
        load_inventory(inventory_path)


def test_load_inventory_product_requires_name(tmp_path):
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "products": [
                    {
                        "version": "1.0.0",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="products\\[0\\]"):
        load_inventory(inventory_path)


def test_load_inventory_product_requires_version(tmp_path):
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "products": [
                    {
                        "name": "nginx",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="products\\[0\\]"):
        load_inventory(inventory_path)