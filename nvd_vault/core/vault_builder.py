"""Создание структуры vault на диске."""

import json
import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from .enrichment import EnrichmentClient, compute_risk_score
from .inventory import Inventory
from .markdown_writer import render_cve_note, render_cwe_note, render_product_note
from .matcher import cpe_matches_version
from .models import Vulnerability
from .nvd_cache import NvdCache
from .nvd_client import NvdClient
from .osv_client import OsvClient
from .path_safety import safe_filename_stem

logger = logging.getLogger(__name__)

# Канонические форматы идентификаторов уязвимостей и слабостей.
# CVE: 'CVE-YYYY-N+' (4-значный год, 4+ цифр номера — на самом деле может быть >7)
# CWE: 'CWE-N+'
# Принимаем CVE-id из NVD, GHSA из GitHub, PYSEC/MAL из OSV-database, RUSTSEC и др.
_VULN_ID_RE = re.compile(
    r"^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|"
    r"PYSEC-\d{4}-\d+|MAL-\d{4}-\d+|RUSTSEC-\d{4}-\d{4}|GO-\d{4}-\d+)$",
    re.IGNORECASE,
)
_CWE_ID_RE = re.compile(r"^CWE-\d+$")


class VaultBuilder:
    def __init__(
        self,
        vault_path: Path,
        api_key: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
        use_cache: bool = True,
        use_osv: bool = False,
    ):
        self.vault_path = vault_path
        cache = NvdCache() if use_cache else None
        self.client = NvdClient(api_key=api_key, cache=cache)
        self.osv_client = OsvClient() if use_osv else None
        self.progress = progress_callback or (lambda msg: None)
        # Источники для каждой CVE: cve_id -> {"NVD", "OSV"}
        self._sources: dict[str, set[str]] = {}

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

        # собрать данные через NVD
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
            matched = [
                v for v in all_for_product if cpe_matches_version(v, item.name, item.version)
            ]

            self.progress(f"  Найдено {len(matched)} из {len(all_for_product)} CVE")

            product_to_cves[item.name] = matched
            for v in matched:
                all_cves[v.cve_id] = v
                cve_to_products.setdefault(v.cve_id, []).append(item.name)
                self._sources.setdefault(v.cve_id, set()).add("NVD")

        # дополнительные источники (OSV)
        if self.osv_client is not None:
            self._scan_via_osv(inventory, all_cves, cve_to_products, product_to_cves)

        # обогащение через EPSS и CISA KEV
        if all_cves:
            self.progress(f"Обогащаю {len(all_cves)} CVE данными EPSS и CISA KEV...")
            enricher = EnrichmentClient()

            kev_data = enricher.fetch_kev_catalog()
            self.progress(f"  CISA KEV: загружено {len(kev_data)} записей")

            cve_ids = list(all_cves.keys())
            epss_data = enricher.fetch_epss_batch(cve_ids)
            self.progress(f"  EPSS: получены данные для {len(epss_data)} из {len(cve_ids)} CVE")

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
            if not _VULN_ID_RE.match(cve_id):
                logger.warning("Пропущена запись с некорректным id: %r", cve_id)
                continue
            sources = sorted(self._sources.get(cve_id, {"NVD"}))
            content = render_cve_note(vuln, cve_to_products.get(cve_id, []), sources=sources)
            stem = safe_filename_stem(cve_id, fallback="cve")
            (self.vault_path / "cves" / f"{stem}.md").write_text(content, encoding="utf-8")

        for item in inventory.products:
            if item.name not in product_to_cves:
                continue
            vendor = item.vendor or "unknown"
            content = render_product_note(
                item.name, vendor, item.version, product_to_cves[item.name]
            )
            stem = safe_filename_stem(item.name, fallback="product")
            (self.vault_path / "products" / f"{stem}.md").write_text(content, encoding="utf-8")

        cwe_to_cves: dict[str, list[Vulnerability]] = {}
        for vuln in all_cves.values():
            for cwe in vuln.weaknesses:
                cwe_to_cves.setdefault(cwe, []).append(vuln)
        for cwe_id, cves in cwe_to_cves.items():
            if not _CWE_ID_RE.match(cwe_id):
                logger.warning("Пропущен CWE с некорректным id: %r", cwe_id)
                continue
            content = render_cwe_note(cwe_id, cves)
            stem = safe_filename_stem(cwe_id, fallback="cwe")
            (self.vault_path / "cwes" / f"{stem}.md").write_text(content, encoding="utf-8")

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

    def _scan_via_osv(
        self,
        inventory: Inventory,
        all_cves: dict[str, Vulnerability],
        cve_to_products: dict[str, list[str]],
        product_to_cves: dict[str, list[Vulnerability]],
    ) -> None:
        """Дополнительное сканирование через OSV.dev для пакетов с указанной ecosystem.

        Дедупликация: если CVE уже найдена через NVD, OSV-результат пропускается
        (NVD данные приоритетнее — они структурированнее, есть CPE и CWE).
        Если CVE найдена только в OSV, добавляется как новая запись.
        """
        assert self.osv_client is not None  # гарант от конструктора

        items_with_eco = [item for item in inventory.products if item.ecosystem]
        if not items_with_eco:
            self.progress("OSV: пропущено, ни у одного продукта не указан ecosystem")
            return

        self.progress(f"OSV: сканирую {len(items_with_eco)} продуктов с указанным ecosystem...")

        for item in items_with_eco:
            ecosystem = item.ecosystem
            if ecosystem is None:
                continue  # на всякий случай, хотя items_with_eco уже отфильтрован

            try:
                osv_vulns = self.osv_client.query_package(item.name, item.version, ecosystem)
            except Exception as e:
                self.progress(f"  ! OSV ошибка для {item.name}: {e}")
                continue

            new_count = 0
            for vuln in osv_vulns:
                # Помечаем источник в любом случае
                self._sources.setdefault(vuln.cve_id, set()).add("OSV")

                # Дедупликация: если уже есть в NVD — пропускаем
                if vuln.cve_id in all_cves:
                    continue

                # Новая CVE только из OSV
                all_cves[vuln.cve_id] = vuln
                cve_to_products.setdefault(vuln.cve_id, []).append(item.name)
                product_to_cves.setdefault(item.name, []).append(vuln)
                new_count += 1

            if new_count:
                self.progress(f"  {item.name}: +{new_count} CVE из OSV")
