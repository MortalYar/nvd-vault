from nvd_vault.core.matcher import (
    cpe_matches_version,
    extract_product_from_cpe,
    parse_version,
    vcmp,
)
from nvd_vault.core.models import CpeRange, Vulnerability


def make_vuln(cpe_ranges):
    return Vulnerability(
        cve_id="CVE-TEST-0001",
        description_en="Test vulnerability",
        cvss_score=7.5,
        cvss_severity="HIGH",
        cvss_vector=None,
        cvss_version="3.1",
        published=None,
        last_modified=None,
        vuln_status=None,
        cpe_ranges=cpe_ranges,
    )


def test_parse_version_returns_comparable():
    """parse_version возвращает значение, которое сравнимо с другими через vcmp.

    Внутренний тип реализации (Version или tuple) — деталь реализации,
    тест проверяет только контракт сравнения через публичный API vcmp.
    """
    assert vcmp("1.24.0", "1.24.0") == 0
    assert vcmp("1.24.0", "1.23.0") == 1
    assert vcmp("1.24.0", "1.25.0") == -1


def test_vcmp_compares_versions():
    assert vcmp("1.24.0", "1.23.9") == 1
    assert vcmp("1.24.0", "1.24.0") == 0
    assert vcmp("1.24.0", "1.25.0") == -1


def test_extract_product_from_valid_cpe():
    cpe = "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"

    assert extract_product_from_cpe(cpe) == "nginx"


def test_extract_product_from_malformed_cpe_returns_empty_string():
    assert extract_product_from_cpe("broken-cpe") == ""


def test_cpe_matches_exact_product_and_version():
    vuln = make_vuln(
        [
            CpeRange(
                criteria="cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
            )
        ]
    )

    assert cpe_matches_version(vuln, "nginx", "1.24.0") is True


def test_cpe_does_not_match_different_product():
    vuln = make_vuln(
        [
            CpeRange(
                criteria="cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
            )
        ]
    )

    assert cpe_matches_version(vuln, "postgresql", "1.24.0") is False


def test_cpe_does_not_match_different_exact_version():
    vuln = make_vuln(
        [
            CpeRange(
                criteria="cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
            )
        ]
    )

    assert cpe_matches_version(vuln, "nginx", "1.25.0") is False


def test_cpe_matches_any_version_when_cpe_version_is_wildcard():
    vuln = make_vuln(
        [
            CpeRange(
                criteria="cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
            )
        ]
    )

    assert cpe_matches_version(vuln, "nginx", "1.24.0") is True


def test_cpe_matches_inclusive_version_range():
    vuln = make_vuln(
        [
            CpeRange(
                criteria="cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                version_start_including="1.20.0",
                version_end_including="1.24.0",
            )
        ]
    )

    assert cpe_matches_version(vuln, "nginx", "1.24.0") is True


def test_cpe_does_not_match_outside_exclusive_upper_bound():
    vuln = make_vuln(
        [
            CpeRange(
                criteria="cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                version_start_including="1.20.0",
                version_end_excluding="1.24.0",
            )
        ]
    )

    assert cpe_matches_version(vuln, "nginx", "1.24.0") is False


# ---------- Pre-release и сложные суффиксы ----------


def test_vcmp_handles_release_candidates_numerically():
    """rc10 должен быть БОЛЬШЕ чем rc2 (численное, не лексикографическое)."""
    assert vcmp("1.0.0-rc10", "1.0.0-rc2") == 1
    assert vcmp("1.0.0-rc2", "1.0.0-rc10") == -1


def test_vcmp_release_greater_than_prerelease():
    """1.0.0 (релиз) больше чем 1.0.0-rc1 (пре-релиз) — semver/PEP440."""
    assert vcmp("1.0.0", "1.0.0-rc1") == 1
    assert vcmp("1.0.0-rc1", "1.0.0") == -1


def test_vcmp_alpha_beta_rc_ordering():
    """alpha < beta < rc < release."""
    assert vcmp("1.0.0a1", "1.0.0b1") == -1
    assert vcmp("1.0.0b1", "1.0.0rc1") == -1
    assert vcmp("1.0.0rc1", "1.0.0") == -1


def test_vcmp_handles_wildcards():
    """Пустые / wildcard versions сравнимы без падений."""
    assert vcmp("", "") == 0
    assert vcmp("*", "*") == 0
    assert vcmp("", "1.0.0") == -1
    assert vcmp("1.0.0", "") == 1


def test_vcmp_fallback_for_non_pep440():
    assert vcmp("5.7.32-0ubuntu0.18.04.1", "5.7.32-0ubuntu0.18.04.1") == 0
    result = vcmp("5.7.32-0ubuntu0.18.04.10", "5.7.32-0ubuntu0.18.04.2")
    assert result == 1