"""Обогащение CVE данными из EPSS и CISA KEV."""

import time
from typing import Optional

import requests


EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_BATCH_SIZE = 100  # API принимает до ~100 CVE за раз через csv


class EnrichmentClient:
    """Клиент для запросов к EPSS API и CISA KEV feed."""

    def __init__(self, timeout: int = 30):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (compatible; nvd-vault/1.0)"
        )
        self.timeout = timeout

    def fetch_epss_batch(self, cve_ids: list[str]) -> dict[str, dict]:
        """
        Запрашивает EPSS-данные для списка CVE.
        Возвращает {cve_id: {epss_score, epss_percentile, epss_date}}.
        """
        if not cve_ids:
            return {}

        result: dict[str, dict] = {}

        # Бьём на батчи -- API ограничивает длину query string
        for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
            batch = cve_ids[i:i + EPSS_BATCH_SIZE]
            params = {"cve": ",".join(batch)}

            try:
                resp = self.session.get(EPSS_API_URL, params=params,
                                        timeout=self.timeout)
            except requests.RequestException:
                # Сетевая ошибка -- не фейлим, просто эти CVE будут без EPSS
                continue

            if resp.status_code != 200:
                continue

            try:
                data = resp.json()
            except ValueError:
                continue

            for item in data.get("data", []):
                cve_id = item.get("cve")
                if not cve_id:
                    continue
                try:
                    score = float(item.get("epss", 0))
                    percentile = float(item.get("percentile", 0))
                except (ValueError, TypeError):
                    continue
                result[cve_id] = {
                    "epss_score": score,
                    "epss_percentile": percentile,
                    "epss_date": item.get("date"),
                }

            # Вежливая пауза между батчами
            if i + EPSS_BATCH_SIZE < len(cve_ids):
                time.sleep(0.5)

        return result

    def fetch_kev_catalog(self) -> dict[str, dict]:
        """
        Скачивает полный каталог CISA KEV.
        Возвращает {cve_id: {kev_added, kev_due, kev_action, kev_name}}.
        """
        try:
            resp = self.session.get(KEV_FEED_URL, timeout=self.timeout)
        except requests.RequestException:
            return {}

        if resp.status_code != 200:
            return {}

        try:
            data = resp.json()
        except ValueError:
            return {}

        result: dict[str, dict] = {}
        for item in data.get("vulnerabilities", []):
            cve_id = item.get("cveID")
            if not cve_id:
                continue
            result[cve_id] = {
                "kev_added": item.get("dateAdded"),
                "kev_due": item.get("dueDate"),
                "kev_action": item.get("requiredAction"),
                "kev_name": item.get("vulnerabilityName"),
                "kev_known_ransomware": (
                    item.get("knownRansomwareCampaignUse") == "Known"
                ),
            }
        return result


# ---------- Risk scoring ----------

def compute_risk_score(
    cvss_score: Optional[float],
    epss_score: Optional[float],
    is_kev: bool,
    kev_known_ransomware: bool = False,
) -> dict:
    """
    Вычисляет приоритетный risk score из CVSS + EPSS + KEV.

    Возвращает {"score": float, "tier": str, "reasoning": list[str]}.

    Tier:
        critical_now    -- KEV-листед, патчить срочно
        critical_likely -- EPSS >= 0.7 или ransomware-related
        high            -- CVSS >= 8 или EPSS >= 0.3
        medium          -- CVSS >= 5
        low             -- остальное
    """
    cvss = cvss_score or 0.0
    epss = epss_score or 0.0
    reasoning = []

    # Tier 1: уже эксплуатируется
    if is_kev:
        reasoning.append("CISA KEV — активная эксплуатация в реальных атаках")
        if kev_known_ransomware:
            reasoning.append("Используется в ransomware-кампаниях")
        return {
            "score": min(10.0, cvss + 2.0),
            "tier": "critical_now",
            "reasoning": reasoning,
        }

    # Tier 2: высокая вероятность эксплуатации
    if epss >= 0.7:
        reasoning.append(f"EPSS {epss:.2f} — высокая вероятность эксплуатации")
        return {
            "score": min(10.0, cvss + 1.5),
            "tier": "critical_likely",
            "reasoning": reasoning,
        }

    # Tier 3: high
    if cvss >= 8.0:
        reasoning.append(f"CVSS {cvss:.1f} — высокая базовая опасность")
        if epss >= 0.1:
            reasoning.append(f"EPSS {epss:.2f}")
        return {"score": cvss, "tier": "high", "reasoning": reasoning}

    if epss >= 0.3:
        reasoning.append(f"EPSS {epss:.2f} — заметная вероятность эксплуатации")
        return {
            "score": min(10.0, cvss + 1.0),
            "tier": "high",
            "reasoning": reasoning,
        }

    # Tier 4: medium
    if cvss >= 5.0:
        return {
            "score": cvss,
            "tier": "medium",
            "reasoning": [f"CVSS {cvss:.1f}"],
        }

    # Tier 5: low
    return {
        "score": cvss,
        "tier": "low",
        "reasoning": [f"CVSS {cvss:.1f}, EPSS {epss:.2f}" if epss else "Низкий риск"],
    }