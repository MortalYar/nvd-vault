from unittest.mock import MagicMock

from nvd_vault.core.inventory import Inventory, InventoryItem
from nvd_vault.core.models import Vulnerability
from nvd_vault.core.vault_builder import VaultBuilder


class FakeNvdClient:
    """NVD-клиент возвращающий одну CVE."""

    def discover_vendors(self, name):
        return ["someorg"]

    def fetch_cves(self, vendor, name):
        return [
            Vulnerability(
                cve_id="CVE-2024-11111",
                description_en="From NVD",
                cvss_score=7.5,
                cvss_severity="HIGH",
                cvss_vector=None,
                cvss_version=None,
                published=None,
                last_modified=None,
                vuln_status=None,
                weaknesses=[],
                references=[],
            )
        ]


class FakeEnrichmentClient:
    def fetch_kev_catalog(self):
        return {}

    def fetch_epss_batch(self, cve_ids):
        return {}


def test_osv_disabled_by_default(tmp_path):
    """Без use_osv=True OSV-клиент не создаётся."""
    builder = VaultBuilder(vault_path=tmp_path)
    assert builder.osv_client is None


def test_osv_enabled_creates_client(tmp_path):
    builder = VaultBuilder(vault_path=tmp_path, use_osv=True)
    assert builder.osv_client is not None


def test_osv_skipped_when_no_ecosystem(tmp_path, monkeypatch):
    """Если ни у одного продукта нет ecosystem — OSV не запрашивается."""
    monkeypatch.setattr(
        "nvd_vault.core.vault_builder.EnrichmentClient",
        FakeEnrichmentClient,
    )

    inventory = Inventory(
        vault_name="Test",
        products=[InventoryItem(name="nginx", version="1.24.0", vendor="nginx")],
    )

    builder = VaultBuilder(vault_path=tmp_path, use_osv=True)
    builder.client = FakeNvdClient()
    # Замокаем OSV-клиент — должен НЕ вызываться
    builder.osv_client = MagicMock()
    builder.osv_client.query_package = MagicMock()

    builder.build(inventory)

    builder.osv_client.query_package.assert_not_called()


def test_osv_finds_additional_cve(tmp_path, monkeypatch):
    """OSV-уникальная CVE добавляется в vault."""
    monkeypatch.setattr(
        "nvd_vault.core.vault_builder.EnrichmentClient",
        FakeEnrichmentClient,
    )
    monkeypatch.setattr(
        "nvd_vault.core.vault_builder.cpe_matches_version",
        lambda v, name, version: True,
    )

    inventory = Inventory(
        vault_name="Test",
        products=[InventoryItem(name="django", version="3.2.0", vendor="django", ecosystem="PyPI")],
    )

    osv_only_vuln = Vulnerability(
        cve_id="GHSA-abcd-1234-efgh",
        description_en="From OSV only",
        cvss_score=8.0,
        cvss_severity="HIGH",
        cvss_vector=None,
        cvss_version=None,
        published=None,
        last_modified=None,
        vuln_status=None,
        weaknesses=[],
        references=[],
    )

    builder = VaultBuilder(vault_path=tmp_path, use_osv=True)
    builder.client = FakeNvdClient()
    builder.osv_client = MagicMock()
    builder.osv_client.query_package = MagicMock(return_value=[osv_only_vuln])

    meta = builder.build(inventory)

    # NVD дала 1 CVE, OSV дала ещё 1 уникальную = 2 в vault
    assert meta["cves_count"] == 2
    assert (tmp_path / "cves" / "CVE-2024-11111.md").exists()
    assert (tmp_path / "cves" / "GHSA-abcd-1234-efgh.md").exists()


def test_osv_dedups_with_nvd(tmp_path, monkeypatch):
    """Если OSV вернёт ту же CVE что и NVD — записывается одна заметка."""
    monkeypatch.setattr(
        "nvd_vault.core.vault_builder.EnrichmentClient",
        FakeEnrichmentClient,
    )
    monkeypatch.setattr(
        "nvd_vault.core.vault_builder.cpe_matches_version",
        lambda v, name, version: True,
    )

    inventory = Inventory(
        vault_name="Test",
        products=[InventoryItem(name="django", version="3.2.0", vendor="django", ecosystem="PyPI")],
    )

    # OSV возвращает ту же CVE-2024-11111 что и NVD-фейк
    duplicate = Vulnerability(
        cve_id="CVE-2024-11111",
        description_en="From OSV (will be ignored, NVD wins)",
        cvss_score=9.0,
        cvss_severity="CRITICAL",
        cvss_vector=None,
        cvss_version=None,
        published=None,
        last_modified=None,
        vuln_status=None,
        weaknesses=[],
        references=[],
    )

    builder = VaultBuilder(vault_path=tmp_path, use_osv=True)
    builder.client = FakeNvdClient()
    builder.osv_client = MagicMock()
    builder.osv_client.query_package = MagicMock(return_value=[duplicate])

    meta = builder.build(inventory)

    # Только одна CVE в vault
    assert meta["cves_count"] == 1
    # Источники для CVE-2024-11111 должны включать обе
    assert builder._sources["CVE-2024-11111"] == {"NVD", "OSV"}


def test_osv_failure_does_not_abort_build(tmp_path, monkeypatch):
    """Если OSV-запрос падает — сборка продолжается с NVD-данными."""
    monkeypatch.setattr(
        "nvd_vault.core.vault_builder.EnrichmentClient",
        FakeEnrichmentClient,
    )
    monkeypatch.setattr(
        "nvd_vault.core.vault_builder.cpe_matches_version",
        lambda v, name, version: True,
    )

    inventory = Inventory(
        vault_name="Test",
        products=[InventoryItem(name="django", version="3.2.0", vendor="django", ecosystem="PyPI")],
    )

    builder = VaultBuilder(vault_path=tmp_path, use_osv=True)
    builder.client = FakeNvdClient()
    builder.osv_client = MagicMock()
    builder.osv_client.query_package = MagicMock(side_effect=ConnectionError("OSV unavailable"))

    # Не падаем
    meta = builder.build(inventory)

    # NVD-данные доехали
    assert meta["cves_count"] == 1
