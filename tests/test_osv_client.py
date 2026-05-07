from unittest.mock import MagicMock

import pytest
import requests

from nvd_vault.core.osv_client import OsvClient


@pytest.fixture
def client(monkeypatch):
    """Клиент с замоканной HTTP-сессией."""
    osv = OsvClient()
    osv.session = MagicMock(spec=requests.Session)
    return osv


def _make_response(status_code: int, json_data: dict | list | None = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data or {}
    response.text = ""
    return response


def test_query_package_no_vulns(client):
    """Чистый пакет — пустой список."""
    client.session.post.return_value = _make_response(200, {"vulns": []})

    result = client.query_package("django", "5.0.0", "PyPI")

    assert result == []
    client.session.post.assert_called_once()
    call_args = client.session.post.call_args
    assert call_args[1]["json"] == {
        "package": {"name": "django", "ecosystem": "PyPI"},
        "version": "5.0.0",
    }


def test_query_package_with_vulns(client):
    osv_response = {
        "vulns": [
            {
                "id": "GHSA-test-1234-abcd",
                "summary": "Test vulnerability",
                "details": "Detailed description here",
                "aliases": ["CVE-2024-99999"],
                "severity": [{"type": "CVSS_V3", "score": "9.8/CVSS:3.1/AV:N/AC:L"}],
                "database_specific": {
                    "severity": "CRITICAL",
                    "cwe_ids": ["CWE-89"],
                },
                "references": [{"type": "ADVISORY", "url": "https://example.com"}],
                "published": "2024-01-15T10:00:00Z",
                "modified": "2024-01-20T10:00:00Z",
            }
        ]
    }
    client.session.post.return_value = _make_response(200, osv_response)

    result = client.query_package("django", "3.2.0", "PyPI")

    assert len(result) == 1
    vuln = result[0]
    # Каноничный id предпочитает CVE из aliases
    assert vuln.cve_id == "CVE-2024-99999"
    assert vuln.description_en == "Detailed description here"
    assert vuln.cvss_score == 9.8
    assert vuln.cvss_severity == "CRITICAL"
    assert vuln.weaknesses == ["CWE-89"]
    assert len(vuln.references) == 1


def test_query_package_uses_osv_id_when_no_cve_alias(client):
    """Если в aliases нет CVE — используем оригинальный OSV-id."""
    osv_response = {
        "vulns": [
            {
                "id": "PYSEC-2024-001",
                "summary": "PySec-only entry",
                "aliases": ["GHSA-other-id"],
            }
        ]
    }
    client.session.post.return_value = _make_response(200, osv_response)

    result = client.query_package("foo", "1.0", "PyPI")
    assert result[0].cve_id == "PYSEC-2024-001"


def test_query_package_handles_malformed_response(client):
    """Если OSV вернул мусор — не падаем, возвращаем пустой список."""
    client.session.post.return_value = _make_response(200, {"vulns": "not a list"})
    assert client.query_package("foo", "1.0", "PyPI") == []


def test_query_package_handles_non_dict_vuln(client):
    """Невалидная запись внутри vulns — пропускаем, остальные обрабатываем."""
    client.session.post.return_value = _make_response(
        200,
        {
            "vulns": [
                "not a dict",
                {"id": "GHSA-valid-1234", "summary": "Valid"},
                None,
            ]
        },
    )

    result = client.query_package("foo", "1.0", "PyPI")
    assert len(result) == 1
    assert result[0].cve_id == "GHSA-valid-1234"


def test_query_package_retries_on_5xx(client, monkeypatch):
    """5xx должны ретраиться."""
    # Замокаем sleep чтобы тест был быстрый
    monkeypatch.setattr("nvd_vault.core.osv_client.time.sleep", lambda _: None)

    client.session.post.side_effect = [
        _make_response(500),
        _make_response(503),
        _make_response(200, {"vulns": []}),
    ]

    result = client.query_package("foo", "1.0", "PyPI")
    assert result == []
    assert client.session.post.call_count == 3


def test_query_package_gives_up_after_max_retries(client, monkeypatch):
    monkeypatch.setattr("nvd_vault.core.osv_client.time.sleep", lambda _: None)

    client.session.post.return_value = _make_response(500)

    result = client.query_package("foo", "1.0", "PyPI")
    assert result == []
    assert client.session.post.call_count == 3


def test_query_package_no_retry_on_4xx(client):
    """400 — это наша ошибка в запросе, ретраить смысла нет."""
    client.session.post.return_value = _make_response(400)

    result = client.query_package("foo", "1.0", "PyPI")
    assert result == []
    assert client.session.post.call_count == 1


def test_severity_inferred_from_score(client):
    """Если в response есть только score без явной severity — выводим её."""
    osv_response = {
        "vulns": [
            {
                "id": "GHSA-no-severity",
                "summary": "Test",
                "severity": [{"type": "CVSS_V3", "score": "5.5/CVSS:3.1/AV:N"}],
                # database_specific.severity отсутствует
            }
        ]
    }
    client.session.post.return_value = _make_response(200, osv_response)

    result = client.query_package("foo", "1.0", "PyPI")
    assert result[0].cvss_score == 5.5
    assert result[0].cvss_severity == "MEDIUM"  # 4.0 <= 5.5 < 7.0


def test_no_cvss_no_severity(client):
    """Если CVSS вообще нет — score и severity остаются None."""
    osv_response = {
        "vulns": [
            {
                "id": "GHSA-no-cvss",
                "summary": "Some advisory without CVSS",
            }
        ]
    }
    client.session.post.return_value = _make_response(200, osv_response)

    result = client.query_package("foo", "1.0", "PyPI")
    assert result[0].cvss_score is None
    assert result[0].cvss_severity is None
