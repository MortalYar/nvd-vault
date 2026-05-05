"""Модели данных: уязвимости, CPE-диапазоны."""

from dataclasses import dataclass, field


@dataclass
class CpeRange:
    """CPE-конфигурация с диапазоном версий."""

    criteria: str
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None


@dataclass
class Vulnerability:
    """Одна уязвимость CVE со всеми метаданными."""

    cve_id: str
    description_en: str
    cvss_score: float | None
    cvss_severity: str | None
    cvss_vector: str | None
    cvss_version: str | None
    published: str | None
    last_modified: str | None
    vuln_status: str | None
    weaknesses: list[str] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)
    cpe_ranges: list[CpeRange] = field(default_factory=list)

    # CISA KEV (от NVD, может быть пустым)
    cisa_kev: bool = False
    cisa_action: str | None = None
    cisa_due: str | None = None

    # Обогащение из EPSS
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None

    # Обогащение из CISA KEV (приоритетнее данных от NVD)
    kev_added: str | None = None
    kev_due: str | None = None
    kev_action: str | None = None
    kev_name: str | None = None
    kev_known_ransomware: bool = False

    # Computed risk score
    risk_score: float | None = None
    risk_tier: str | None = None
    risk_reasoning: list[str] = field(default_factory=list)
