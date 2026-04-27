"""Модели данных: уязвимости, CPE-диапазоны."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CpeRange:
    """CPE-конфигурация с диапазоном версий."""
    criteria: str
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None


@dataclass
class Vulnerability:
    """Одна уязвимость CVE со всеми метаданными."""
    cve_id: str
    description_en: str
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    cvss_vector: Optional[str]
    cvss_version: Optional[str]
    published: Optional[str]
    last_modified: Optional[str]
    vuln_status: Optional[str]
    weaknesses: list[str] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)
    cpe_ranges: list[CpeRange] = field(default_factory=list)

    # CISA KEV (от NVD, может быть пустым)
    cisa_kev: bool = False
    cisa_action: Optional[str] = None
    cisa_due: Optional[str] = None

    # Обогащение из EPSS
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_date: Optional[str] = None

    # Обогащение из CISA KEV (приоритетнее данных от NVD)
    kev_added: Optional[str] = None
    kev_due: Optional[str] = None
    kev_action: Optional[str] = None
    kev_name: Optional[str] = None
    kev_known_ransomware: bool = False

    # Computed risk score
    risk_score: Optional[float] = None
    risk_tier: Optional[str] = None
    risk_reasoning: list[str] = field(default_factory=list)