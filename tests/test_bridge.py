import sys
from unittest.mock import MagicMock

sys.modules.setdefault('webview', MagicMock())

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
