import json

from nvd_vault.core.inventory import Inventory, InventoryItem
from nvd_vault.core.models import CpeRange, Vulnerability
from nvd_vault.core.vault_builder import VaultBuilder


class FakeNvdClient:
    def discover_vendors(self, product_name):
        return ["nginx"]

    def fetch_cves(self, vendor, product):
        return [
            Vulnerability(
                cve_id="CVE-2024-TEST",
                description_en="Test vulnerability",
                cvss_score=9.8,
                cvss_severity="CRITICAL",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_version="3.1",
                published="2024-01-01T00:00:00.000",
                last_modified="2024-01-02T00:00:00.000",
                vuln_status="Analyzed",
                weaknesses=["CWE-79"],
                references=[
                    {
                        "url": "https://example.com/CVE-2024-TEST",
                        "tags": ["Exploit"],
                    }
                ],
                cpe_ranges=[
                    CpeRange(
                        criteria="cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
                    )
                ],
            )
        ]


class FakeEnrichmentClient:
    def fetch_kev_catalog(self):
        return {
            "CVE-2024-TEST": {
                "kev_added": "2024-01-10",
                "kev_due": "2024-02-10",
                "kev_action": "Apply updates",
                "kev_name": "Test KEV",
                "kev_known_ransomware": False,
            }
        }

    def fetch_epss_batch(self, cve_ids):
        return {
            "CVE-2024-TEST": {
                "epss_score": 0.75,
                "epss_percentile": 0.95,
                "epss_date": "2024-01-15",
            }
        }


def test_vault_builder_creates_expected_files(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "nvd_vault.core.vault_builder.EnrichmentClient",
        FakeEnrichmentClient,
    )

    inventory = Inventory(
        vault_name="Test Vault",
        products=[
            InventoryItem(
                name="nginx",
                version="1.24.0",
                vendor="nginx",
            )
        ],
    )

    progress_messages = []
    builder = VaultBuilder(
        vault_path=tmp_path,
        progress_callback=progress_messages.append,
    )
    builder.client = FakeNvdClient()

    meta = builder.build(inventory)

    assert meta["vault_name"] == "Test Vault"
    assert meta["products_count"] == 1
    assert meta["cves_count"] == 1
    assert meta["cwes_count"] == 1

    assert (tmp_path / "meta.json").exists()
    assert (tmp_path / "cves" / "CVE-2024-TEST.md").exists()
    assert (tmp_path / "products" / "nginx.md").exists()
    assert (tmp_path / "cwes" / "CWE-79.md").exists()

    meta_from_file = json.loads((tmp_path / "meta.json").read_text(encoding="utf-8"))
    assert meta_from_file["vault_name"] == "Test Vault"
    assert meta_from_file["products_count"] == 1
    assert meta_from_file["cves_count"] == 1
    assert meta_from_file["cwes_count"] == 1

    cve_note = (tmp_path / "cves" / "CVE-2024-TEST.md").read_text(encoding="utf-8")
    assert "# CVE-2024-TEST" in cve_note
    assert "Test vulnerability" in cve_note
    assert "epss: 0.7500" in cve_note
    assert "kev: true" in cve_note
    assert "[[nginx]]" in cve_note

    product_note = (tmp_path / "products" / "nginx.md").read_text(encoding="utf-8")
    assert "# nginx 1.24.0" in product_note
    assert "[[CVE-2024-TEST]]" in product_note

    cwe_note = (tmp_path / "cwes" / "CWE-79.md").read_text(encoding="utf-8")
    assert "# CWE-79" in cwe_note
    assert "[[CVE-2024-TEST]]" in cwe_note

    assert "Готово." in progress_messages