"""Построение узлов и рёбер графа из vault'а."""

from pathlib import Path
from typing import Optional

from .frontmatter import read_frontmatter

def build_graph(vault_path: Path) -> dict:
    """
    Сканирует vault и собирает структуру для cytoscape.js.
    Возвращает {nodes: [...], edges: [...], stats: {...}}.
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    seen_nodes: set[str] = set()

    # ---- Продукты ----
    products_dir = vault_path / "products"
    if products_dir.exists():
        for f in products_dir.glob("*.md"):
            fm = read_frontmatter(f)
            node_id = f"product:{f.stem}"
            seen_nodes.add(node_id)
            nodes.append({
                "data": {
                    "id": node_id,
                    "label": f.stem,
                    "type": "product",
                    "vendor": fm.get("vendor", ""),
                    "version": fm.get("version", ""),
                    "cve_count": _safe_int(fm.get("cve_count")),
                    "relative_path": f"products/{f.name}",
                }
            })

    # ---- CWE ----
    cwes_dir = vault_path / "cwes"
    if cwes_dir.exists():
        for f in cwes_dir.glob("*.md"):
            fm = read_frontmatter(f)
            node_id = f"cwe:{f.stem}"
            seen_nodes.add(node_id)
            nodes.append({
                "data": {
                    "id": node_id,
                    "label": f.stem,
                    "type": "cwe",
                    "cve_count": _safe_int(fm.get("cve_count")),
                    "relative_path": f"cwes/{f.name}",
                }
            })

    # ---- CVE + рёбра ----
    cves_dir = vault_path / "cves"
    if cves_dir.exists():
        for f in cves_dir.glob("*.md"):
            fm = read_frontmatter(f)
            node_id = f"cve:{f.stem}"
            seen_nodes.add(node_id)

            severity = _normalize_severity(fm.get("severity"))
            cvss = _safe_float(fm.get("cvss"))

            nodes.append({
                "data": {
                    "id": node_id,
                    "label": f.stem,
                    "type": "cve",
                    "severity": severity,
                    "cvss": cvss,
                    "kev": _to_bool(fm.get("kev")),
                    "relative_path": f"cves/{f.name}",
                }
            })

            # Рёбра: CVE → продукты
            for prod_name in fm.get("products", []) or []:
                prod_id = f"product:{prod_name}"
                if prod_id in seen_nodes:
                    edges.append({
                        "data": {
                            "id": f"e:{node_id}-{prod_id}",
                            "source": node_id,
                            "target": prod_id,
                            "type": "affects",
                        }
                    })

            # Рёбра: CVE → CWE
            for cwe_name in fm.get("cwes", []) or []:
                cwe_id = f"cwe:{cwe_name}"
                if cwe_id in seen_nodes:
                    edges.append({
                        "data": {
                            "id": f"e:{node_id}-{cwe_id}",
                            "source": node_id,
                            "target": cwe_id,
                            "type": "instance-of",
                        }
                    })

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "products": sum(1 for n in nodes if n["data"]["type"] == "product"),
            "cves": sum(1 for n in nodes if n["data"]["type"] == "cve"),
            "cwes": sum(1 for n in nodes if n["data"]["type"] == "cwe"),
            "edges": len(edges),
        },
    }


# ---------- Утилиты ----------

def _normalize_severity(value) -> str:
    if not value:
        return "unknown"
    return str(value).lower()


def _safe_float(value) -> Optional[float]:
    if value is None or value == "null":
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _safe_int(value) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() == "true"