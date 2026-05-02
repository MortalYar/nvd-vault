"""Сравнение версий и матчинг CPE-диапазонов.

Стратегия сравнения версий:
1. packaging.version.Version (PEP 440) — корректно для большинства
   open-source-пакетов, включая pre-release ('1.0.0-rc2' vs '1.0.0-rc10'),
   post-release, dev-теги, метаданные сборки.
2. Если PEP 440 не справился (InvalidVersion) — fallback на самописный парсер,
   который разбивает строку на чередующиеся блоки (число, строка), что покрывает
   большинство SemVer-подобных версий.
3. Самый последний fallback — лексикографическое сравнение по строкам.
"""

import re

from packaging.version import InvalidVersion, Version

from .models import Vulnerability


_TOKEN_RE = re.compile(r"(\d+)|([^\d.]+)")


def parse_version(v: str):
    """Парсит строку версии в значение, поддерживающее операторы сравнения.

    Возвращает либо `Version` (PEP 440), либо tuple of (int, str) blocks
    (fallback). Пустые / wildcard-значения возвращают пустой tuple.

    Note: возвращаемые объекты сравнимы между собой только в пределах одного
    типа. Используй `vcmp` для двух произвольных строк — он сам обеспечивает
    однородность через fallback-цепочку.
    """
    if not v or v in ("*", "-"):
        return ()

    try:
        return Version(v)
    except InvalidVersion:
        return _parse_fallback(v)


def _parse_fallback(v: str) -> tuple:
    """Самописный парсер: 'rc10' -> ((0, 'rc'), (10, '')).

    Разбивает строку на чередующиеся блоки цифр и не-цифр, что обеспечивает
    численное сравнение чисел внутри pre-release-суффиксов.
    """
    parts = []
    for chunk in v.replace("-", ".").replace("+", ".").split("."):
        if not chunk:
            continue
        # Каждый chunk -> цепочка (num, str)-токенов
        for match in _TOKEN_RE.finditer(chunk):
            num_part, str_part = match.groups()
            if num_part is not None:
                parts.append((int(num_part), ""))
            else:
                parts.append((0, str_part))
    return tuple(parts)


def vcmp(a: str, b: str) -> int:
    """Возвращает -1, 0, 1 как cmp(a, b).

    Пытается сравнивать через packaging.version. Если хоть одна из строк не
    парсится как PEP 440 — обе сравниваются через fallback-парсер,
    чтобы гарантировать однотипность.
    """
    # Wildcard / пустые
    if not a or a in ("*", "-"):
        a_empty = True
    else:
        a_empty = False
    if not b or b in ("*", "-"):
        b_empty = True
    else:
        b_empty = False

    if a_empty and b_empty:
        return 0
    if a_empty:
        return -1
    if b_empty:
        return 1

    # Пробуем PEP 440 для обеих
    try:
        va, vb = Version(a), Version(b)
        return (va > vb) - (va < vb)
    except InvalidVersion:
        pass

    # Fallback — обе через самописный парсер
    pa, pb = _parse_fallback(a), _parse_fallback(b)
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