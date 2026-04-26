"""HTTP-клиент NVD API 2.0."""

import time
from typing import Optional

import requests

from .models import CpeRange, Vulnerability


NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
RESULTS_PER_PAGE = 2000
REQUEST_TIMEOUT = 30
RATE_LIMIT_SLEEP = 6.5  # без API-ключа: 5 запросов / 30 секунд


class NvdClient:
    def __init__(self, api_key: Optional[str] = None):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (compatible; nvd-vault/1.0)"
        )
        self.api_key = api_key
        if api_key:
            self.session.headers["apiKey"] = api_key

    def _sleep(self) -> None:
        time.sleep(0.7 if self.api_key else RATE_LIMIT_SLEEP)

    def _request(self, url: str, params: dict) -> dict:
        try:
            r = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            raise RuntimeError(f"Ошибка сети: {e}") from e

        if r.status_code == 404 and not r.text.strip():
            raise RuntimeError(
                "NVD вернул 404 с пустым телом. "
                "Возможные причины: API-ключ не активирован, либо запрос некорректен."
            )
        if r.status_code == 403:
            raise RuntimeError(
                "NVD: 403 (rate limit). "
                "Получи API-ключ: https://nvd.nist.gov/developers/request-an-api-key"
            )
        if r.status_code == 404:
            return {"vulnerabilities": [], "totalResults": 0, "products": []}
        r.raise_for_status()
        return r.json()

    def discover_vendors(self, product: str) -> list[str]:
        """Список vendor'ов для продукта из CPE Dictionary."""
        data = self._request(
            NVD_CPE_URL,
            {"keywordSearch": product, "resultsPerPage": 500},
        )
        vendors: dict[str, int] = {}
        product_lc = product.lower()
        for prod in data.get("products", []):
            cpe_name = prod.get("cpe", {}).get("cpeName", "")
            parts = cpe_name.split(":")
            if len(parts) >= 6 and parts[2] == "a" and parts[4].lower() == product_lc:
                vendors[parts[3].lower()] = vendors.get(parts[3].lower(), 0) + 1
        return sorted(vendors.keys(), key=lambda v: -vendors[v])

    def fetch_cves(self, vendor: str, product: str) -> list[Vulnerability]:
        cpe_match = f"cpe:2.3:a:{vendor}:{product.lower()}:*:*:*:*:*:*:*:*"
        results: list[Vulnerability] = []
        start_index = 0

        while True:
            params = {
                "virtualMatchString": cpe_match,
                "resultsPerPage": RESULTS_PER_PAGE,
                "startIndex": start_index,
            }
            data = self._request(NVD_CVE_URL, params)
            for item in data.get("vulnerabilities", []):
                v = self._parse_cve(item.get("cve", {}))
                if v:
                    results.append(v)

            total = data.get("totalResults", 0)
            start_index += RESULTS_PER_PAGE
            if start_index >= total:
                break
            self._sleep()

        return results

    @staticmethod
    def _parse_cve(cve: dict) -> Optional[Vulnerability]:
        cve_id = cve.get("id")
        if not cve_id:
            return None

        description_en = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description_en = d.get("value", "")
                break

        score = severity = vector = cvss_ver = None
        metrics = cve.get("metrics", {})
        for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                         ("cvssMetricV2", "2.0")):
            if metrics.get(key):
                m = metrics[key][0]
                cvss = m.get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity") or m.get("baseSeverity")
                vector = cvss.get("vectorString")
                cvss_ver = ver
                break

        weaknesses = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-") and val not in weaknesses:
                    weaknesses.append(val)

        cpe_ranges = []
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if cpe.get("vulnerable") and cpe.get("criteria"):
                        cpe_ranges.append(CpeRange(
                            criteria=cpe["criteria"],
                            version_start_including=cpe.get("versionStartIncluding"),
                            version_start_excluding=cpe.get("versionStartExcluding"),
                            version_end_including=cpe.get("versionEndIncluding"),
                            version_end_excluding=cpe.get("versionEndExcluding"),
                        ))

        references = []
        seen = set()
        for ref in cve.get("references", []):
            url = ref.get("url")
            if url and url not in seen:
                seen.add(url)
                references.append({"url": url, "tags": ref.get("tags", [])})

        return Vulnerability(
            cve_id=cve_id,
            description_en=description_en,
            cvss_score=score,
            cvss_severity=severity,
            cvss_vector=vector,
            cvss_version=cvss_ver,
            published=cve.get("published"),
            last_modified=cve.get("lastModified"),
            vuln_status=cve.get("vulnStatus"),
            weaknesses=weaknesses,
            references=references,
            cpe_ranges=cpe_ranges,
            cisa_kev=bool(cve.get("cisaExploitAdd")),
            cisa_action=cve.get("cisaRequiredAction"),
            cisa_due=cve.get("cisaActionDue"),
        )