import sys
from unittest.mock import MagicMock

sys.modules.setdefault("webview", MagicMock())

from nvd_vault.api.bridge import Api  # noqa: E402


def test_open_path_rejects_when_no_vault(tmp_path):
    api = Api()
    result = api.open_path_in_explorer(str(tmp_path / "anything"))
    assert result["ok"] is False
    assert "Vault" in result["error"]


def test_open_path_rejects_outside_vault(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("secret")

    api = Api()
    api._current_vault = vault
    result = api.open_path_in_explorer(str(outside))
    assert result["ok"] is False
    assert "вне vault" in result["error"]


def test_open_path_rejects_executable(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    evil = vault / "malware.exe"
    evil.write_bytes(b"MZ")  # имитация PE-заголовка

    api = Api()
    api._current_vault = vault
    result = api.open_path_in_explorer(str(evil))
    assert result["ok"] is False
    assert "Открытие исполняемых файлов" in result["error"]


def test_open_path_rejects_nonexistent(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()

    api = Api()
    api._current_vault = vault
    result = api.open_path_in_explorer(str(vault / "doesnt-exist.md"))
    assert result["ok"] is False

def test_build_vault_passes_use_osv(tmp_path, monkeypatch):
    """use_osv параметр от JS пробрасывается в VaultBuilder."""
    captured_kwargs = {}

    class FakeVaultBuilder:
        def __init__(self, *args, **kwargs):
            captured_kwargs.update(kwargs)

        def build(self, inventory):
            return {
                "vault_name": "test",
                "built_at": "2024-01-01",
                "products_count": 0,
                "cves_count": 0,
                "cwes_count": 0,
            }

    monkeypatch.setattr("nvd_vault.api.bridge.VaultBuilder", FakeVaultBuilder)

    api = Api()
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        '{"vault_name": "test", "products": [{"name": "x", "version": "1.0"}]}'
    )

    result = api.build_vault(
        str(inventory_path),
        str(tmp_path / "vault"),
        api_key=None,
        input_format="inventory",
        use_osv=True,
    )

    assert result.get("ok") is True

    # Сборка идёт в треде, дадим ей завершиться
    import time
    for _ in range(50):
        if not api._build_running:
            break
        time.sleep(0.05)

    assert captured_kwargs.get("use_osv") is True
