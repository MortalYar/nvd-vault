"""HTTP-клиент OSV.dev API для запроса уязвимостей по пакетам.

OSV.dev (https://osv.dev) — открытый агрегатор уязвимостей от Google,
охватывающий пакетные экосистемы (PyPI, npm, RubyGems, Cargo, Go, Maven и др.),
Linux-дистрибутивы (Debian, Alpine, Ubuntu) и GitHub Security Advisories.

Дополняет NVD в случаях, когда уязвимости известны экосистеме, но не получили
CVE-id или CPE-маркеров.

API не требует ключа. Документация: https://osv.dev/docs/
"""

import logging
import time

import requests

from .models import Vulnerability

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"

REQUEST_TIMEOUT = 30
REQUEST_RETRIES = 3
RETRY_SLEEP = 2

# Ограничение OSV API на batch-запрос
QUERYBATCH_MAX_SIZE = 1000


class OsvClient:
    """Клиент OSV.dev API.

    Использование:
        client = OsvClient()
        vulns = client.query_package("django", "3.2.0", "PyPI")
    """

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "nvd-vault/0.1.0"})

    def query_package(
        self,
        name: str,
        version: str,
        ecosystem: str,
    ) -> list[Vulnerability]:
        """Запросить уязвимости для одного пакета.

        Возвращает список Vulnerability. Пустой список — пакет чистый.
        """
        payload = {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version,
        }

        data = self._post(OSV_QUERY_URL, payload)
        if not data:
            return []

        vulns_data = data.get("vulns", [])
        if not isinstance(vulns_data, list):
            logger.warning("OSV вернул неожиданный формат vulns: %s", type(vulns_data).__name__)
            return []

        result = []
        for v in vulns_data:
            parsed = self._parse_osv_vuln(v)
            if parsed is not None:
                result.append(parsed)
        return result

    def _post(self, url: str, payload: dict) -> dict | None:
        """POST-запрос с retry. Возвращает dict или None при окончательной ошибке."""
        for attempt in range(1, REQUEST_RETRIES + 1):
            try:
                response = self.session.post(url, json=payload, timeout=REQUEST_TIMEOUT)
            except requests.RequestException as e:
                if attempt < REQUEST_RETRIES:
                    logger.warning(
                        "OSV request failed, retrying %s/%s: %s",
                        attempt, REQUEST_RETRIES, e,
                    )
                    time.sleep(RETRY_SLEEP * attempt)
                    continue
                logger.error("OSV: ошибка сети после %s попыток: %s", REQUEST_RETRIES, e)
                return None

            if response.status_code == 429:
                if attempt < REQUEST_RETRIES:
                    logger.warning("OSV: 429, retrying %s/%s", attempt, REQUEST_RETRIES)
                    time.sleep(RETRY_SLEEP * attempt * 2)
                    continue
                logger.error("OSV: 429 после %s попыток", REQUEST_RETRIES)
                return None

            if response.status_code >= 500:
                if attempt < REQUEST_RETRIES:
                    logger.warning(
                        "OSV: %s, retrying %s/%s",
                        response.status_code, attempt, REQUEST_RETRIES,
                    )
                    time.sleep(RETRY_SLEEP * attempt)
                    continue
                logger.error("OSV: %s после %s попыток", response.status_code, REQUEST_RETRIES)
                return None

            if 400 <= response.status_code < 500:
                logger.warning("OSV: HTTP %s — %s", response.status_code, response.text[:200])
                return None

            try:
                data = response.json()
            except ValueError as e:
                logger.error("OSV: невалидный JSON: %s", e)
                return None

            if not isinstance(data, dict):
                logger.error("OSV: ожидался объект, получен %s", type(data).__name__)
                return None

            return data

        # Этой строки не должно быть достижимо, но mypy без неё ругается
        return None

    @staticmethod
    def _parse_osv_vuln(v: object) -> Vulnerability | None:
        """Парсит запись OSV в нашу модель Vulnerability.

        OSV-формат отличается от NVD: id может быть GHSA-xxxx, CVE-xxxx,
        PYSEC-xxxx и др. CVSS опционален. Для совместимости с уже существующей
        моделью используем canonical CVE-id если он есть в aliases, иначе OSV-id.
        """
        if not isinstance(v, dict):
            return None

        osv_id = v.get("id")
        if not isinstance(osv_id, str) or not osv_id:
            return None

        # Каноничный id: предпочитаем CVE если он есть в aliases
        aliases = v.get("aliases", [])
        canonical_id = osv_id
        if isinstance(aliases, list):
            for alias in aliases:
                if isinstance(alias, str) and alias.startswith("CVE-"):
                    canonical_id = alias
                    break

        # Description: details приоритетнее summary
        description = v.get("details") or v.get("summary") or ""
        if not isinstance(description, str):
            description = ""

        # CVSS из severity (если есть)
        cvss_score: float | None = None
        cvss_vector: str | None = None
        cvss_version: str | None = None
        cvss_severity: str | None = None

        severity_list = v.get("severity", [])
        if isinstance(severity_list, list):
            for sev in severity_list:
                if not isinstance(sev, dict):
                    continue
                sev_type = sev.get("type", "")
                score_str = sev.get("score", "")
                if not isinstance(score_str, str):
                    continue
                # Формат: "9.8/CVSS:3.1/AV:N/AC:L/..."
                if "/" in score_str:
                    score_part, vector_part = score_str.split("/", 1)
                    try:
                        cvss_score = float(score_part)
                    except ValueError:
                        continue
                    cvss_vector = vector_part
                    if "CVSS:3" in sev_type or "CVSS:3" in vector_part:
                        cvss_version = "3.1"
                    elif "CVSS:4" in sev_type or "CVSS:4" in vector_part:
                        cvss_version = "4.0"
                    break

        # Severity из database_specific (если есть)
        db_specific = v.get("database_specific", {})
        if isinstance(db_specific, dict):
            sev = db_specific.get("severity")
            if isinstance(sev, str):
                cvss_severity = sev.upper()

        # Если CVSS-vector есть, но severity нет — выводим из score
        if cvss_severity is None and cvss_score is not None:
            if cvss_score >= 9.0:
                cvss_severity = "CRITICAL"
            elif cvss_score >= 7.0:
                cvss_severity = "HIGH"
            elif cvss_score >= 4.0:
                cvss_severity = "MEDIUM"
            else:
                cvss_severity = "LOW"

        # CWE
        weaknesses: list[str] = []
        if isinstance(db_specific, dict):
            cwe_ids = db_specific.get("cwe_ids", [])
            if isinstance(cwe_ids, list):
                weaknesses = [c for c in cwe_ids if isinstance(c, str)]

        # References
        references: list[dict] = []
        refs = v.get("references", [])
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, dict):
                    url = ref.get("url")
                    if isinstance(url, str):
                        references.append({"url": url, "source": "OSV"})

        # Даты
        published = v.get("published") if isinstance(v.get("published"), str) else None
        modified = v.get("modified") if isinstance(v.get("modified"), str) else None

        return Vulnerability(
            cve_id=canonical_id,
            description_en=description,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            cvss_vector=cvss_vector,
            cvss_version=cvss_version,
            published=published,
            last_modified=modified,
            vuln_status=None,
            weaknesses=weaknesses,
            references=references,
        )
