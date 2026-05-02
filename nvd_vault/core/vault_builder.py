"""Создание структуры vault на диске."""

import json
from datetime import datetime, UTC
from pathlib import Path
from typing import Callable, Optional

from .enrichment import EnrichmentClient, compute_risk_score
from .inventory import Inventory
from .markdown_writer import render_cve_note, render_cwe_note, render_product_note
from .matcher import cpe_matches_version
from .models import Vulnerability
from .nvd_client import NvdClient
from .nvd_cache import NvdCache


class VaultBuilder:
    def __init__(self, vault_path: Path, api_key: Optional[str] = None,
                 progress_callback: Optional[Callable[[str], None]] = None):
        self.vault_path = vault_path
        self.client = NvdClient(api_key=api_key, cache=NvdCache())
        self.progress = progress_callback or (lambda msg: None)

    def build(self, inventory: Inventory) -> dict:
        """
        Создаёт vault с заметками для всех продуктов из inventory.
        Возвращает статистику.
        """
        self._ensure_dirs()

        # cve_id -> Vulnerability (одна CVE может затрагивать несколько продуктов)
        all_cves: dict[str, Vulnerability] = {}
        # cve_id -> [имена продуктов]
        cve_to_products: dict[str, list[str]] = {}
        # имя_продукта -> [Vulnerability]
        product_to_cves: dict[str, list[Vulnerability]] = {}

        # Шаг 1 — собрать данные через NVD
        for item in inventory.products:
            self.progress(f"Сканирую {item.name} {item.version}...")

            vendor = item.vendor
            if not vendor:
                vendors = self.client.discover_vendors(item.name)
                if not vendors:
                    self.progress(f"  ! Vendor для '{item.name}' не найден, пропускаю")
                    continue
                vendor = vendors[0]

            all_for_product = self.client.fetch_cves(vendor, item.name)
            matched = [v for v in all_for_product
                       if cpe_matches_version(v, item.name, item.version)]

            self.progress(f"  Найдено {len(matched)} из {len(all_for_product)} CVE")

            product_to_cves[item.name] = matched
            for v in matched:
                all_cves[v.cve_id] = v
                cve_to_products.setdefault(v.cve_id, []).append(item.name)

        # Шаг 1.5 — обогащение через EPSS и CISA KEV
        if all_cves:
            self.progress(f"Обогащаю {len(all_cves)} CVE данными EPSS и CISA KEV...")
            enricher = EnrichmentClient()

            kev_data = enricher.fetch_kev_catalog()
            self.progress(f"  CISA KEV: загружено {len(kev_data)} записей")

            cve_ids = list(all_cves.keys())
            epss_data = enricher.fetch_epss_batch(cve_ids)
            self.progress(f"  EPSS: получены данные для {len(epss_data)} из "
                          f"{len(cve_ids)} CVE")

            for cve_id, vuln in all_cves.items():
                if cve_id in epss_data:
                    e = epss_data[cve_id]
                    vuln.epss_score = e["epss_score"]
                    vuln.epss_percentile = e["epss_percentile"]
                    vuln.epss_date = e["epss_date"]

                if cve_id in kev_data:
                    k = kev_data[cve_id]
                    vuln.cisa_kev = True
                    vuln.kev_added = k["kev_added"]
                    vuln.kev_due = k["kev_due"]
                    vuln.kev_action = k["kev_action"]
                    vuln.kev_name = k["kev_name"]
                    vuln.kev_known_ransomware = k["kev_known_ransomware"]

                risk = compute_risk_score(
                    cvss_score=vuln.cvss_score,
                    epss_score=vuln.epss_score,
                    is_kev=vuln.cisa_kev,
                    kev_known_ransomware=vuln.kev_known_ransomware,
                )
                vuln.risk_score = risk["score"]
                vuln.risk_tier = risk["tier"]
                vuln.risk_reasoning = risk["reasoning"]

        # Шаг 2 — записать заметки на диск
        self.progress("Генерирую vault...")

        for cve_id, vuln in all_cves.items():
            content = render_cve_note(vuln, cve_to_products.get(cve_id, []))
            (self.vault_path / "cves" / f"{cve_id}.md").write_text(
                content, encoding="utf-8"
            )

        for item in inventory.products:
            if item.name not in product_to_cves:
                continue
            vendor = item.vendor or "unknown"
            content = render_product_note(
                item.name, vendor, item.version, product_to_cves[item.name]
            )
            (self.vault_path / "products" / f"{item.name}.md").write_text(
                content, encoding="utf-8"
            )

        cwe_to_cves: dict[str, list[Vulnerability]] = {}
        for vuln in all_cves.values():
            for cwe in vuln.weaknesses:
                cwe_to_cves.setdefault(cwe, []).append(vuln)
        for cwe_id, cves in cwe_to_cves.items():
            content = render_cwe_note(cwe_id, cves)
            (self.vault_path / "cwes" / f"{cwe_id}.md").write_text(
                content, encoding="utf-8"
            )

        meta = {
            "vault_name": inventory.vault_name,
            "built_at": datetime.now(UTC).isoformat(),
            "products_count": len(product_to_cves),
            "cves_count": len(all_cves),
            "cwes_count": len(cwe_to_cves),
        }
        (self.vault_path / "meta.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        self.progress("Готово.")
        return meta

    def _ensure_dirs(self) -> None:
        for sub in ("cves", "products", "cwes"):
            (self.vault_path / sub).mkdir(parents=True, exist_ok=True)