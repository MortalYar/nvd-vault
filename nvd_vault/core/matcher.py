"""Сравнение версий и матчинг CPE-диапазонов."""

from .models import Vulnerability


def parse_version(v: str) -> tuple:
    """'8.19.9' -> (8, 19, 9). Семантическое сравнение."""
    if not v or v in ("*", "-"):
        return ()
    parts = []
    for chunk in v.replace("-", ".").split("."):
        num, rest = "", ""
        for ch in chunk:
            if ch.isdigit() and not rest:
                num += ch
            else:
                rest += ch
        parts.append((int(num) if num else 0, rest))
    return tuple(parts)


def vcmp(a: str, b: str) -> int:
    """Возвращает -1, 0, 1 как cmp(a, b)."""
    pa, pb = parse_version(a), parse_version(b)
    return (pa > pb) - (pa < pb)


def extract_product_from_cpe(cpe: str) -> str:
    """cpe:2.3:a:elastic:elasticsearch:8.19.9:... -> 'elasticsearch'"""
    parts = cpe.split(":")
    return parts[4].lower() if len(parts) >= 5 else ""


def cpe_matches_version(vuln: Vulnerability, product: str, version: str) -> bool:
    """True если хоть один CPE-диапазон CVE покрывает (product, version)."""
    product = product.lower()
    for r in vuln.cpe_ranges:
        if extract_product_from_cpe(r.criteria) != product:
            continue

        cpe_parts = r.criteria.split(":")
        cpe_version = cpe_parts[5] if len(cpe_parts) >= 6 else "*"
        no_range = not any([
            r.version_start_including, r.version_start_excluding,
            r.version_end_including, r.version_end_excluding,
        ])

        if no_range:
            if cpe_version in ("*", "-"):
                return True
            if cpe_version == version:
                return True
            continue

        ok = True
        if r.version_start_including and vcmp(version, r.version_start_including) < 0:
            ok = False
        if ok and r.version_start_excluding and vcmp(version, r.version_start_excluding) <= 0:
            ok = False
        if ok and r.version_end_including and vcmp(version, r.version_end_including) > 0:
            ok = False
        if ok and r.version_end_excluding and vcmp(version, r.version_end_excluding) >= 0:
            ok = False
        if ok:
            return True
    return False