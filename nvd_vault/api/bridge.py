"""API, доступное из JavaScript через window.pywebview.api."""

from nvd_vault.core.matcher import cpe_matches_version
from nvd_vault.core.nvd_client import NvdClient


class Api:
    """
    Каждый публичный метод этого класса автоматически становится доступен
    из JS как window.pywebview.api.<имя_метода>().
    """

    def ping(self) -> str:
        """Проверка связи фронт <-> бэк."""
        return "pong: связь с Python работает"

    def scan_product(self, product: str, version: str,
                     vendor: str = None, api_key: str = None) -> dict:
        """
        Сканирует продукт через NVD.
        Возвращает список CVE, затрагивающих указанную версию.
        """
        try:
            client = NvdClient(api_key=api_key or None)

            # Если vendor не задан — определяем сами
            if not vendor:
                vendors = client.discover_vendors(product)
                if not vendors:
                    return {"ok": False, "error": f"Vendor для '{product}' не найден"}
                vendor = vendors[0]

            all_vulns = client.fetch_cves(vendor, product)
            matched = [v for v in all_vulns if cpe_matches_version(v, product, version)]

            return {
                "ok": True,
                "product": product,
                "version": version,
                "vendor": vendor,
                "total_in_db": len(all_vulns),
                "matched_count": len(matched),
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "severity": v.cvss_severity,
                        "score": v.cvss_score,
                        "description": v.description_en[:300],
                        "published": v.published,
                        "cisa_kev": v.cisa_kev,
                    }
                    for v in matched
                ],
            }
        except RuntimeError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            return {"ok": False, "error": f"Неожиданная ошибка: {e}"}