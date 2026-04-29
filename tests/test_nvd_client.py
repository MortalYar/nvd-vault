import pytest
import requests

from nvd_vault.core.nvd_client import NVD_CPE_URL, NvdClient
from nvd_vault.core.models import Vulnerability


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text="{}"):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.text = text

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


def test_discover_vendors_returns_matching_application_vendors(monkeypatch):
    client = NvdClient()

    def fake_request(url, params):
        assert url == NVD_CPE_URL
        assert params["keywordSearch"] == "nginx"

        return {
            "products": [
                {
                    "cpe": {
                        "cpeName": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
                    }
                },
                {
                    "cpe": {
                        "cpeName": "cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*"
                    }
                },
                {
                    "cpe": {
                        "cpeName": "cpe:2.3:o:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
                    }
                },
                {
                    "cpe": {
                        "cpeName": "cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*:*"
                    }
                },
            ]
        }

    monkeypatch.setattr(client, "_request", fake_request)

    assert client.discover_vendors("nginx") == ["nginx", "f5"]


def test_request_returns_empty_result_for_nvd_404_with_body(monkeypatch):
    client = NvdClient()

    def fake_get(url, params, timeout):
        return FakeResponse(
            status_code=404,
            json_data={"ignored": True},
            text='{"message": "not found"}',
        )

    monkeypatch.setattr(client.session, "get", fake_get)

    assert client._request("https://example.test", {}) == {
        "vulnerabilities": [],
        "totalResults": 0,
        "products": [],
    }


def test_request_raises_helpful_error_for_empty_404(monkeypatch):
    client = NvdClient()

    def fake_get(url, params, timeout):
        return FakeResponse(status_code=404, text="")

    monkeypatch.setattr(client.session, "get", fake_get)

    with pytest.raises(RuntimeError, match="NVD вернул 404 с пустым телом"):
        client._request("https://example.test", {})


def test_request_raises_helpful_error_for_403(monkeypatch):
    client = NvdClient()

    def fake_get(url, params, timeout):
        return FakeResponse(status_code=403, text="Forbidden")

    monkeypatch.setattr(client.session, "get", fake_get)

    with pytest.raises(RuntimeError, match="NVD: 403"):
        client._request("https://example.test", {})


def test_request_wraps_network_errors(monkeypatch):
    client = NvdClient()

    def fake_get(url, params, timeout):
        raise requests.ConnectionError("network down")

    monkeypatch.setattr(client.session, "get", fake_get)

    with pytest.raises(RuntimeError, match="Ошибка сети"):
        client._request("https://example.test", {})


def test_parse_cve_full_payload():
    payload = {
        "id": "CVE-2024-TEST",
        "descriptions": [
            {
                "lang": "es",
                "value": "Descripcion",
            },
            {
                "lang": "en",
                "value": "English description",
            },
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }
            ]
        },
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-01-02T00:00:00.000",
        "vulnStatus": "Analyzed",
        "weaknesses": [
            {
                "description": [
                    {
                        "lang": "en",
                        "value": "CWE-79",
                    }
                ]
            },
            {
                "description": [
                    {
                        "lang": "en",
                        "value": "CWE-79",
                    }
                ]
            },
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.20.0",
                                "versionEndExcluding": "1.25.0",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:a:nginx:nginx:1.26.0:*:*:*:*:*:*:*",
                            },
                        ]
                    }
                ]
            }
        ],
        "references": [
            {
                "url": "https://example.com/advisory",
                "tags": ["Exploit"],
            },
            {
                "url": "https://example.com/advisory",
                "tags": ["Duplicate"],
            },
        ],
        "cisaExploitAdd": "2024-01-10",
        "cisaRequiredAction": "Apply updates",
        "cisaActionDue": "2024-02-01",
    }

    vuln = NvdClient._parse_cve(payload)

    assert isinstance(vuln, Vulnerability)
    assert vuln.cve_id == "CVE-2024-TEST"
    assert vuln.description_en == "English description"
    assert vuln.cvss_score == 9.8
    assert vuln.cvss_severity == "CRITICAL"
    assert vuln.cvss_version == "3.1"
    assert vuln.published == "2024-01-01T00:00:00.000"
    assert vuln.last_modified == "2024-01-02T00:00:00.000"
    assert vuln.vuln_status == "Analyzed"

    assert vuln.weaknesses == ["CWE-79"]
    assert len(vuln.references) == 1
    assert vuln.references[0]["url"] == "https://example.com/advisory"

    assert len(vuln.cpe_ranges) == 1
    assert vuln.cpe_ranges[0].criteria == "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    assert vuln.cpe_ranges[0].version_start_including == "1.20.0"
    assert vuln.cpe_ranges[0].version_end_excluding == "1.25.0"

    assert vuln.cisa_kev is True
    assert vuln.cisa_action == "Apply updates"
    assert vuln.cisa_due == "2024-02-01"


def test_parse_cve_without_id_returns_none():
    assert NvdClient._parse_cve({"descriptions": []}) is None