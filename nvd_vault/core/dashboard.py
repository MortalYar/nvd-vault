"""Агрегаты для дашборда: KPI, топы, распределения."""

import re
from datetime import date, datetime
from pathlib import Path
from typing import Optional


_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


def build_dashboard(vault_path: Path) -> dict:
    """
    Собирает аналитику по vault.
    Возвращает словарь с KPI и топами для UI.
    """
    cves = _collect_cves(vault_path)
    products = _collect_products(vault_path)
    cwes = _collect_cwes(vault_path)

    if not cves:
        return _empty_dashboard()

    return {
        "kpi": _build_kpi(cves),
        "tier_distribution": _tier_distribution(cves),
        "top_cves": _top_cves(cves, limit=10),
        "top_products": _top_products(cves, products, limit=5),
        "top_cwes": _top_cwes(cves, cwes, limit=5),
        "kev_deadlines": _kev_deadlines(cves, days_ahead=30),
        "ransomware_cves": _ransomware_cves(cves),
    }


# ---------- KPI ----------

def _build_kpi(cves: list[dict]) -> dict:
    total = len(cves)
    by_tier = _count_by(cves, "risk_tier")
    kev = sum(1 for c in cves if c.get("kev"))
    ransomware = sum(1 for c in cves if c.get("ransomware"))

    overdue, due_soon = _count_kev_deadlines(cves)

    return {
        "total_cves": total,
        "critical_now": by_tier.get("critical_now", 0),
        "critical_likely": by_tier.get("critical_likely", 0),
        "high": by_tier.get("high", 0),
        "medium": by_tier.get("medium", 0),
        "low": by_tier.get("low", 0),
        "kev_total": kev,
        "ransomware_total": ransomware,
        "kev_overdue": overdue,
        "kev_due_soon": due_soon,
    }


def _count_kev_deadlines(cves: list[dict]) -> tuple[int, int]:
    """Считает просроченные и near-due CISA-дедлайны (30 дней)."""
    today = date.today()
    overdue = 0
    due_soon = 0
    for c in cves:
        kev_due = c.get("kev_due")
        if not kev_due:
            continue
        try:
            due = datetime.strptime(kev_due, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            continue
        days = (due - today).days
        if days < 0:
            overdue += 1
        elif days <= 30:
            due_soon += 1
    return overdue, due_soon


# ---------- Распределения ----------

def _tier_distribution(cves: list[dict]) -> list[dict]:
    """Распределение по risk tier для bar chart."""
    counts = _count_by(cves, "risk_tier")
    order = ["critical_now", "critical_likely", "high", "medium", "low", "unknown"]
    labels = {
        "critical_now": "Критично (эксплуатируется)",
        "critical_likely": "Критично (вероятно)",
        "high": "Высокий",
        "medium": "Средний",
        "low": "Низкий",
        "unknown": "Не определён",
    }
    total = max(1, sum(counts.values()))
    return [
        {
            "tier": tier,
            "label": labels[tier],
            "count": counts.get(tier, 0),
            "percent": round(counts.get(tier, 0) / total * 100, 1),
        }
        for tier in order
        if counts.get(tier, 0) > 0
    ]


# ---------- Топы ----------

def _top_cves(cves: list[dict], limit: int) -> list[dict]:
    """Топ CVE по risk score."""
    tier_order = {
        "critical_now": 0, "critical_likely": 1,
        "high": 2, "medium": 3, "low": 4, "unknown": 5,
    }
    sorted_cves = sorted(
        cves,
        key=lambda c: (
            tier_order.get(c.get("risk_tier") or "unknown", 99),
            -float(c.get("risk_score") or 0),
        ),
    )
    return [
        {
            "cve_id": c["cve_id"],
            "risk_tier": c.get("risk_tier"),
            "risk_score": c.get("risk_score"),
            "cvss_score": c.get("cvss_score"),
            "epss_score": c.get("epss_score"),
            "kev": c.get("kev", False),
            "ransomware": c.get("ransomware", False),
            "products": c.get("products", []),
            "relative_path": f"cves/{c['cve_id']}.md",
        }
        for c in sorted_cves[:limit]
    ]


def _top_products(cves: list[dict], products: list[dict], limit: int) -> list[dict]:
    """Топ продуктов по числу critical/high CVE."""
    risk_by_product: dict[str, dict] = {}

    for c in cves:
        tier = c.get("risk_tier")
        for prod_name in c.get("products", []):
            entry = risk_by_product.setdefault(prod_name, {
                "name": prod_name,
                "critical_now": 0,
                "critical_likely": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0,
                "kev": 0,
            })
            entry["total"] += 1
            if tier in ("critical_now", "critical_likely", "high", "medium", "low"):
                entry[tier] += 1
            if c.get("kev"):
                entry["kev"] += 1

    # Сортировка: больше critical_now → critical_likely → high → kev
    sorted_products = sorted(
        risk_by_product.values(),
        key=lambda p: (
            -p["critical_now"], -p["critical_likely"],
            -p["high"], -p["kev"], -p["total"],
        ),
    )
    return sorted_products[:limit]


def _top_cwes(cves: list[dict], cwes: list[dict], limit: int) -> list[dict]:
    """Топ CWE по числу CVE этого типа."""
    cwe_counts: dict[str, int] = {}
    cwe_critical: dict[str, int] = {}

    for c in cves:
        is_critical = c.get("risk_tier") in ("critical_now", "critical_likely")
        for cwe in c.get("cwes", []):
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
            if is_critical:
                cwe_critical[cwe] = cwe_critical.get(cwe, 0) + 1

    sorted_cwes = sorted(
        cwe_counts.items(),
        key=lambda x: (-cwe_critical.get(x[0], 0), -x[1]),
    )
    return [
        {
            "cwe_id": cwe_id,
            "count": count,
            "critical_count": cwe_critical.get(cwe_id, 0),
            "relative_path": f"cwes/{cwe_id}.md",
        }
        for cwe_id, count in sorted_cwes[:limit]
    ]


def _kev_deadlines(cves: list[dict], days_ahead: int) -> list[dict]:
    """CVE с CISA-дедлайнами в ближайшие N дней (включая просроченные)."""
    today = date.today()
    result = []
    for c in cves:
        kev_due = c.get("kev_due")
        if not kev_due:
            continue
        try:
            due = datetime.strptime(kev_due, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            continue
        days = (due - today).days
        if days > days_ahead:
            continue
        result.append({
            "cve_id": c["cve_id"],
            "kev_due": kev_due,
            "days_remaining": days,
            "overdue": days < 0,
            "products": c.get("products", []),
            "relative_path": f"cves/{c['cve_id']}.md",
        })
    result.sort(key=lambda x: x["days_remaining"])
    return result


def _ransomware_cves(cves: list[dict]) -> list[dict]:
    """CVE, помеченные как ransomware-related."""
    result = []
    for c in cves:
        if c.get("ransomware"):
            result.append({
                "cve_id": c["cve_id"],
                "risk_tier": c.get("risk_tier"),
                "products": c.get("products", []),
                "relative_path": f"cves/{c['cve_id']}.md",
            })
    return result


# ---------- Чтение vault'а ----------

def _collect_cves(vault_path: Path) -> list[dict]:
    """Прочитать все CVE-заметки и вернуть список словарей с метаданными."""
    cves_dir = vault_path / "cves"
    if not cves_dir.exists():
        return []

    result = []
    for md_file in cves_dir.glob("*.md"):
        fm = _read_frontmatter(md_file)
        if not fm:
            continue
        result.append({
            "cve_id": md_file.stem,
            "risk_tier": fm.get("risk_tier"),
            "risk_score": _to_float(fm.get("risk_score")),
            "cvss_score": _to_float(fm.get("cvss")),
            "epss_score": _to_float(fm.get("epss")),
            "kev": _to_bool(fm.get("kev")),
            "kev_due": fm.get("kev_due"),
            "ransomware": _to_bool(fm.get("ransomware")),
            "products": fm.get("products") or [],
            "cwes": fm.get("cwes") or [],
        })
    return result


def _collect_products(vault_path: Path) -> list[dict]:
    products_dir = vault_path / "products"
    if not products_dir.exists():
        return []
    result = []
    for f in products_dir.glob("*.md"):
        fm = _read_frontmatter(f)
        result.append({
            "name": f.stem,
            "version": fm.get("version", ""),
            "vendor": fm.get("vendor", ""),
        })
    return result


def _collect_cwes(vault_path: Path) -> list[dict]:
    cwes_dir = vault_path / "cwes"
    if not cwes_dir.exists():
        return []
    return [{"cwe_id": f.stem} for f in cwes_dir.glob("*.md")]


# ---------- Утилиты ----------

def _read_frontmatter(path: Path) -> dict:
    try:
        content = path.read_text(encoding="utf-8")
    except Exception:
        return {}
    match = _FRONTMATTER_RE.match(content)
    if not match:
        return {}

    yaml_text = match.group(1)
    fm: dict = {}
    for line in yaml_text.split("\n"):
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            fm[key] = [x.strip() for x in inner.split(",")] if inner else []
        else:
            fm[key] = value
    return fm


def _count_by(cves: list[dict], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for c in cves:
        val = c.get(field) or "unknown"
        counts[val] = counts.get(val, 0) + 1
    return counts


def _to_float(value) -> Optional[float]:
    if value is None or value == "null":
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() == "true"


def _empty_dashboard() -> dict:
    return {
        "kpi": {
            "total_cves": 0, "critical_now": 0, "critical_likely": 0,
            "high": 0, "medium": 0, "low": 0,
            "kev_total": 0, "ransomware_total": 0,
            "kev_overdue": 0, "kev_due_soon": 0,
        },
        "tier_distribution": [],
        "top_cves": [],
        "top_products": [],
        "top_cwes": [],
        "kev_deadlines": [],
        "ransomware_cves": [],
    }