"""Генерация Markdown-заметок для vault'а."""

from .models import Vulnerability


def severity_tag(severity: str | None) -> str:
    """CRITICAL -> 'critical' для тегов."""
    return (severity or "unknown").lower()


def render_cve_note(vuln: Vulnerability, products_for_cve: list[str]) -> str:
    """Генерирует .md заметку для одной CVE."""
    score = f"{vuln.cvss_score:.1f}" if vuln.cvss_score is not None else "null"
    severity = (vuln.cvss_severity or "unknown").lower()
    published = vuln.published[:10] if vuln.published else "unknown"

    # YAML frontmatter
    lines = ["---"]
    lines.append("type: cve")
    lines.append(f"id: {vuln.cve_id}")
    lines.append(f"severity: {severity}")
    lines.append(f"cvss: {score}")
    lines.append(f"cvss_version: {vuln.cvss_version or 'null'}")
    lines.append(f"published: {published}")
    lines.append(f"products: [{', '.join(products_for_cve)}]")
    lines.append(f"cwes: [{', '.join(vuln.weaknesses)}]")
    lines.append(f"kev: {str(vuln.cisa_kev).lower()}")

    # Теги для фильтрации
    tags = [severity]
    if vuln.cisa_kev:
        tags.append("kev")
    lines.append(f"tags: [{', '.join(tags)}]")
    lines.append("---")
    lines.append("")

    # Заголовок и сводка
    lines.append(f"# {vuln.cve_id}")
    lines.append("")
    lines.append(f"**Severity:** {vuln.cvss_severity or '—'} · "
                 f"**CVSS:** {score}")
    if vuln.cisa_kev:
        lines.append("")
        lines.append("> ⚠ Активно эксплуатируется (CISA KEV)")
    lines.append("")

    # Затронутые продукты — wiki-links
    if products_for_cve:
        product_links = ", ".join(f"[[{p}]]" for p in products_for_cve)
        lines.append(f"**Затрагивает:** {product_links}")
        lines.append("")

    # CWE — wiki-links
    if vuln.weaknesses:
        cwe_links = ", ".join(f"[[{c}]]" for c in vuln.weaknesses)
        lines.append(f"**Тип слабости:** {cwe_links}")
        lines.append("")

    # Описание
    if vuln.description_en:
        lines.append("## Описание")
        lines.append("")
        lines.append(vuln.description_en.strip())
        lines.append("")

    # CVSS вектор
    if vuln.cvss_vector:
        lines.append("## CVSS")
        lines.append("")
        lines.append(f"`{vuln.cvss_vector}`")
        lines.append("")

    # Метаданные
    lines.append("## Метаданные")
    lines.append("")
    if vuln.published:
        lines.append(f"- Опубликовано: {vuln.published[:10]}")
    if vuln.last_modified:
        lines.append(f"- Изменено: {vuln.last_modified[:10]}")
    if vuln.vuln_status:
        lines.append(f"- Статус NVD: {vuln.vuln_status}")
    lines.append(f"- Запись в NVD: https://nvd.nist.gov/vuln/detail/{vuln.cve_id}")
    lines.append("")

    # References
    if vuln.references:
        lines.append("## Источники")
        lines.append("")
        for ref in vuln.references[:15]:
            tags_str = f" _({', '.join(ref['tags'])})_" if ref["tags"] else ""
            lines.append(f"- {ref['url']}{tags_str}")
        lines.append("")

    return "\n".join(lines)


def render_product_note(product_name: str, vendor: str, version: str,
                        cves: list[Vulnerability]) -> str:
    """Карточка продукта со списком его CVE."""
    lines = ["---"]
    lines.append("type: product")
    lines.append(f"name: {product_name}")
    lines.append(f"vendor: {vendor}")
    lines.append(f"version: {version}")
    lines.append(f"cve_count: {len(cves)}")
    lines.append("---")
    lines.append("")

    lines.append(f"# {product_name} {version}")
    lines.append("")
    lines.append(f"**Vendor:** {vendor}")
    lines.append(f"**CVE найдено:** {len(cves)}")
    lines.append("")

    if not cves:
        lines.append("Уязвимости не найдены.")
        return "\n".join(lines)

    # Группировка по severity
    by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "OTHER": []}
    for v in cves:
        sev = (v.cvss_severity or "OTHER").upper()
        if sev not in by_severity:
            sev = "OTHER"
        by_severity[sev].append(v)

    lines.append("## Уязвимости")
    lines.append("")
    for sev_name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "OTHER"):
        bucket = by_severity[sev_name]
        if not bucket:
            continue
        lines.append(f"### {sev_name} ({len(bucket)})")
        lines.append("")
        for v in bucket:
            score = f"{v.cvss_score:.1f}" if v.cvss_score is not None else "—"
            kev_marker = " ⚠" if v.cisa_kev else ""
            lines.append(f"- [[{v.cve_id}]] · CVSS {score}{kev_marker}")
        lines.append("")

    return "\n".join(lines)


def render_cwe_note(cwe_id: str, cves_with_cwe: list[Vulnerability]) -> str:
    """Карточка типа слабости (CWE)."""
    lines = ["---"]
    lines.append("type: cwe")
    lines.append(f"id: {cwe_id}")
    lines.append(f"cve_count: {len(cves_with_cwe)}")
    lines.append("---")
    lines.append("")

    cwe_num = cwe_id.replace("CWE-", "")
    lines.append(f"# {cwe_id}")
    lines.append("")
    lines.append(f"Описание типа слабости: "
                 f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")
    lines.append("")
    lines.append(f"**Количество CVE этого типа в vault:** {len(cves_with_cwe)}")
    lines.append("")

    if cves_with_cwe:
        lines.append("## Связанные CVE")
        lines.append("")
        sorted_cves = sorted(
            cves_with_cwe,
            key=lambda v: -(v.cvss_score or 0),
        )
        for v in sorted_cves:
            score = f"{v.cvss_score:.1f}" if v.cvss_score is not None else "—"
            lines.append(f"- [[{v.cve_id}]] · {v.cvss_severity or '—'} · CVSS {score}")
        lines.append("")

    return "\n".join(lines)