"""HTTP-клиент NVD API 2.0."""

import time
import logging
from typing import Optional
import requests

from .models import CpeRange, Vulnerability
from .nvd_cache import NvdCache

logger = logging.getLogger(__name__)


NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
RESULTS_PER_PAGE = 2000
REQUEST_TIMEOUT = 30
REQUEST_RETRIES = 3
RETRY_SLEEP = 3
# Минимальный интервал между запросами к NVD.
# Без ключа: лимит 5 запросов / 30 сек -> минимум 6 сек/запрос (берём 6.5 для запаса).
# С ключом: лимит 50 запросов / 30 сек -> минимум 0.6 сек/запрос (берём 0.7).
MIN_INTERVAL_NO_KEY = 6.5
MIN_INTERVAL_WITH_KEY = 0.7


class NvdClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        cache: Optional[NvdCache] = None,
    ):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (compatible; nvd-vault/1.0)"
        )
        self.api_key = api_key
        if api_key:
            self.session.headers["apiKey"] = api_key
        self._min_interval = MIN_INTERVAL_WITH_KEY if api_key else MIN_INTERVAL_NO_KEY
        self._last_request_at: float = 0.0
        self.cache = cache

    def _throttle(self) -> None:
            """Гарантирует минимальный интервал между запросами к NVD."""
            if self._last_request_at == 0.0:
                return
            elapsed = time.monotonic() - self._last_request_at
            wait = self._min_interval - elapsed
            if wait > 0:
                time.sleep(wait)

    def _request(self, url: str, params: dict) -> dict:
        last_error: requests.RequestException | None = None

        for attempt in range(1, REQUEST_RETRIES + 1):
            self._throttle()
            try:
                r = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
                self._last_request_at = time.monotonic()
            except requests.RequestException as e:
                self._last_request_at = time.monotonic()
                last_error = e

                if attempt < REQUEST_RETRIES:
                    logger.warning(
                        "NVD request failed, retrying %s/%s: %s",
                        attempt,
                        REQUEST_RETRIES,
                        e,
                    )
                    time.sleep(RETRY_SLEEP * attempt)
                    continue

                raise RuntimeError(
                    f"Ошибка сети после {REQUEST_RETRIES} попыток: {last_error}"
                ) from e

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

            # 429 Too Many Requests
            if r.status_code == 429:
                last_error = requests.HTTPError(f"HTTP 429 Too Many Requests")
                if attempt < REQUEST_RETRIES:
                    logger.warning(
                        "NVD: 429 Too Many Requests, retrying %s/%s",
                        attempt, REQUEST_RETRIES,
                    )
                    time.sleep(RETRY_SLEEP * attempt * 2)
                    continue
                raise RuntimeError(
                    f"NVD: 429 после {REQUEST_RETRIES} попыток. "
                    "Превышен rate limit, попробуй позже или используй API-ключ."
                ) from last_error

            # Другие 4xx
            if 400 <= r.status_code < 500:
                raise RuntimeError(
                    f"NVD API error: HTTP {r.status_code}. "
                    f"Тело ответа: {r.text[:200]}"
                )

            # 5xx: серверная ошибка
            if r.status_code >= 500:
                last_error = requests.HTTPError(f"HTTP {r.status_code}")
                if attempt < REQUEST_RETRIES:
                    logger.warning(
                        "NVD %s, retrying %s/%s",
                        r.status_code, attempt, REQUEST_RETRIES,
                    )
                    time.sleep(RETRY_SLEEP * attempt)
                    continue
                raise RuntimeError(
                    f"NVD API error: HTTP {r.status_code} после {REQUEST_RETRIES} попыток"
                ) from last_error

            # 2xx
            try:
                return r.json()
            except ValueError as e:
                raise RuntimeError(
                    f"NVD вернул невалидный JSON: {e}"
                ) from e

        raise RuntimeError("NVD API error: неизвестная ошибка")

    def discover_vendors(self, product: str) -> list[str]:
        """Список vendor'ов для продукта из CPE Dictionary."""
        cache_key = f"vendors__{product}"
        if self.cache is not None:
            cached = self.cache.get(cache_key)
            if cached is not None:
                logger.debug("NVD cache hit (vendors): %s", product)
                data = cached
            else:
                data = self._request(
                    NVD_CPE_URL,
                    {"keywordSearch": product, "resultsPerPage": 500},
                )
                self.cache.set(cache_key, data)
        else:
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
        cache_key = f"cves__{vendor}__{product}"

        # Кэш-попадание: возвращаем сохранённые сырые vulnerabilities,
        # парсим заново (Vulnerability dataclass'ы не сериализуются в JSON).
        if self.cache is not None:
            cached = self.cache.get(cache_key)
            if cached is not None:
                logger.debug(
                    "NVD cache hit (cves): %s/%s, %d items",
                    vendor, product, len(cached.get("vulnerabilities", [])),
                )
                return self._parse_raw_vulnerabilities(cached)

        # Кэш-промах: собираем все страницы с пагинацией.
        cpe_match = f"cpe:2.3:a:{vendor}:{product.lower()}:*:*:*:*:*:*:*:*"
        all_raw: list[dict] = []
        start_index = 0

        while True:
            params = {
                "virtualMatchString": cpe_match,
                "resultsPerPage": RESULTS_PER_PAGE,
                "startIndex": start_index,
            }
            data = self._request(NVD_CVE_URL, params)
            all_raw.extend(data.get("vulnerabilities", []))

            total = data.get("totalResults", 0) or 0
            start_index += RESULTS_PER_PAGE
            if start_index >= total:
                break

        # В кэш — сырой агрегированный ответ
        if self.cache is not None:
            self.cache.set(cache_key, {"vulnerabilities": all_raw})

        return self._parse_raw_vulnerabilities({"vulnerabilities": all_raw})

    def _parse_raw_vulnerabilities(self, data: dict) -> list[Vulnerability]:
        """Парсит {"vulnerabilities": [...]} в list[Vulnerability]."""
        results: list[Vulnerability] = []
        for item in data.get("vulnerabilities", []):
            v = self._parse_cve(item.get("cve", {}))
            if v:
                results.append(v)
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