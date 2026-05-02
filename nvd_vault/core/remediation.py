from pathlib import Path

from nvd_vault.core.frontmatter import read_frontmatter


TIER_WEIGHT = {
    "critical_now": 100,
    "critical_likely": 80,
    "high": 50,
    "medium": 20,
    "low": 5,
    "unknown": 1,
}


def build_remediation_plan(vault_path: Path) -> dict:
    cves_dir = vault_path / "cves"

    if not cves_dir.exists():
        return {
            "summary": {
                "products": 0,
                "cves": 0,
            },
            "items": [],
        }

    products: dict[str, dict] = {}

    for cve_file in cves_dir.glob("*.md"):
        fm = read_frontmatter(cve_file)

        product_names = _extract_products(fm)
        if not product_names:
            continue

        cve_id = cve_file.stem
        tier = fm.get("risk_tier") or "unknown"
        risk_score = _to_float(fm.get("risk_score"), 0.0)
        cvss = _to_float(fm.get("cvss"), 0.0)
        epss = _to_float(fm.get("epss"), 0.0)
        kev = _to_bool(fm.get("kev"))
        ransomware = _to_bool(fm.get("ransomware"))

        for product_name in product_names:
            item = products.setdefault(
                product_name,
                {
                    "product": product_name,
                    "cves_count": 0,
                    "critical_now": 0,
                    "critical_likely": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unknown": 0,
                    "kev_count": 0,
                    "ransomware_count": 0,
                    "max_risk_score": 0.0,
                    "max_cvss": 0.0,
                    "max_epss": 0.0,
                    "remediation_score": 0.0,
                    "top_cves": [],
                },
            )

            item["cves_count"] += 1
            item[tier] = item.get(tier, 0) + 1
            item["kev_count"] += 1 if kev else 0
            item["ransomware_count"] += 1 if ransomware else 0
            item["max_risk_score"] = max(item["max_risk_score"], risk_score)
            item["max_cvss"] = max(item["max_cvss"], cvss)
            item["max_epss"] = max(item["max_epss"], epss)

            item["remediation_score"] += (
                TIER_WEIGHT.get(tier, 1)
                + risk_score * 5
                + cvss * 2
                + epss * 20
                + (75 if kev else 0)
                + (40 if ransomware else 0)
            )

            item["top_cves"].append(
                {
                    "cve_id": cve_id,
                    "risk_tier": tier,
                    "risk_score": risk_score,
                    "cvss": cvss,
                    "epss": epss,
                    "kev": kev,
                    "ransomware": ransomware,
                    "relative_path": f"cves/{cve_file.name}",
                }
            )

    items = list(products.values())

    for item in items:
        item["top_cves"] = sorted(
            item["top_cves"],
            key=lambda c: (
                TIER_WEIGHT.get(c["risk_tier"], 1),
                c["risk_score"],
                c["cvss"],
                c["epss"],
            ),
            reverse=True,
        )[:5]

        item["recommendation"] = _recommend(item)

    items.sort(
        key=lambda p: (
            p["remediation_score"],
            p["kev_count"],
            p["critical_now"],
            p["max_risk_score"],
        ),
        reverse=True,
    )

    total_remediation_score = sum(item["remediation_score"] for item in items)

    for item in items:
        if total_remediation_score > 0:
            item["risk_reduction_percent"] = round(
                item["remediation_score"] / total_remediation_score * 100,
                1,
            )
        else:
            item["risk_reduction_percent"] = 0.0

    return {
        "summary": {
            "products": len(items),
            "cves": sum(item["cves_count"] for item in items),
        },
        "items": items,
    }


def _extract_products(frontmatter: dict) -> list[str]:
    products = frontmatter.get("products")

    if isinstance(products, list):
        return [str(p).strip() for p in products if str(p).strip()]

    if isinstance(products, str):
        return [
            p.strip()
            for p in products.replace("[", "").replace("]", "").split(",")
            if p.strip()
        ]

    product = frontmatter.get("product")
    if product:
        return [str(product).strip()]

    return []


def _recommend(item: dict) -> str:
    if item["kev_count"] > 0 or item["critical_now"] > 0:
        return "Patch immediately"

    if item["critical_likely"] > 0:
        return "Patch within days"

    if item["high"] > 0:
        return "Prioritize in next patch window"

    if item["medium"] > 0:
        return "Plan standard remediation"

    return "Monitor"


def _to_float(value, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"true", "yes", "1"}