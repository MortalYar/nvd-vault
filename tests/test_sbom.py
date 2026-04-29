import json

import pytest

from nvd_vault.core.sbom import load_sbom


def test_load_cyclonedx_sbom(tmp_path):
    sbom_path = tmp_path / "bom.json"
    sbom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "metadata": {
                    "component": {
                        "name": "Test App"
                    }
                },
                "components": [
                    {
                        "type": "library",
                        "name": "nginx",
                        "version": "1.24.0",
                        "supplier": {
                            "name": "nginx"
                        },
                    },
                    {
                        "type": "library",
                        "name": "openssl",
                        "version": "3.0.0",
                    },
                    {
                        "type": "library",
                        "name": "no-version",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    inventory = load_sbom(sbom_path)

    assert inventory.vault_name == "Test App"
    assert len(inventory.products) == 2
    assert inventory.products[0].name == "nginx"
    assert inventory.products[0].version == "1.24.0"
    assert inventory.products[0].vendor == "nginx"
    assert inventory.products[1].name == "openssl"
    assert inventory.products[1].version == "3.0.0"
    assert inventory.products[1].vendor is None


def test_load_spdx_sbom(tmp_path):
    sbom_path = tmp_path / "spdx.json"
    sbom_path.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "name": "SPDX Test App",
                "packages": [
                    {
                        "name": "kibana",
                        "versionInfo": "8.19.9",
                        "supplier": "Organization: elastic",
                    },
                    {
                        "name": "logstash",
                        "versionInfo": "8.19.5",
                        "supplier": "NOASSERTION",
                    },
                    {
                        "name": "no-version",
                        "versionInfo": "NOASSERTION",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    inventory = load_sbom(sbom_path)

    assert inventory.vault_name == "SPDX Test App"
    assert len(inventory.products) == 2
    assert inventory.products[0].name == "kibana"
    assert inventory.products[0].version == "8.19.9"
    assert inventory.products[0].vendor == "elastic"
    assert inventory.products[1].name == "logstash"
    assert inventory.products[1].version == "8.19.5"
    assert inventory.products[1].vendor is None


def test_load_unknown_sbom_format_raises_value_error(tmp_path):
    sbom_path = tmp_path / "unknown.json"
    sbom_path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")

    with pytest.raises(ValueError, match="Неизвестный SBOM формат"):
        load_sbom(sbom_path)


def test_load_cyclonedx_deduplicates_components(tmp_path):
    sbom_path = tmp_path / "bom.json"
    sbom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"name": "nginx", "version": "1.24.0", "supplier": "nginx"},
                    {"name": "nginx", "version": "1.24.0", "supplier": "nginx"},
                ],
            }
        ),
        encoding="utf-8",
    )

    inventory = load_sbom(sbom_path)

    assert len(inventory.products) == 1