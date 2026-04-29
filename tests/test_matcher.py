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


def test_parse_version_splits_numeric_parts():
    assert parse_version("1.24.0") == ((1, ""), (24, ""), (0, ""))


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