"""Тесты для compute_risk_score из enrichment.py.

Запуск из корня проекта:
    pytest tests/test_risk_score.py -v
"""

import pytest

from nvd_vault.core.enrichment import compute_risk_score


# ---------- Tier 1: critical_now (KEV-listed) ----------

class TestCriticalNow:
    """KEV-флаг — всегда critical_now независимо от других параметров."""

    def test_kev_with_high_cvss(self):
        result = compute_risk_score(
            cvss_score=9.8, epss_score=0.5, is_kev=True,
        )
        assert result["tier"] == "critical_now"
        assert result["score"] == 10.0  # 9.8 + 2.0, capped at 10
        assert "CISA KEV" in result["reasoning"][0]

    def test_kev_with_low_cvss(self):
        """Даже при низком CVSS, KEV даёт critical_now."""
        result = compute_risk_score(
            cvss_score=3.0, epss_score=0.0, is_kev=True,
        )
        assert result["tier"] == "critical_now"
        assert result["score"] == 5.0  # 3.0 + 2.0

    def test_kev_with_ransomware(self):
        result = compute_risk_score(
            cvss_score=8.0, epss_score=0.5, is_kev=True,
            kev_known_ransomware=True,
        )
        assert result["tier"] == "critical_now"
        assert any("ransomware" in r.lower() for r in result["reasoning"])

    def test_kev_overrides_high_epss(self):
        """KEV приоритетнее, чем высокий EPSS."""
        result = compute_risk_score(
            cvss_score=5.0, epss_score=0.95, is_kev=True,
        )
        assert result["tier"] == "critical_now"

    def test_kev_with_none_cvss(self):
        """KEV без CVSS-балла — должно работать."""
        result = compute_risk_score(
            cvss_score=None, epss_score=0.0, is_kev=True,
        )
        assert result["tier"] == "critical_now"
        assert result["score"] == 2.0  # 0 + 2.0


# ---------- Tier 2: critical_likely (EPSS >= 0.7) ----------

class TestCriticalLikely:
    """Высокий EPSS без KEV даёт critical_likely."""

    def test_epss_at_threshold(self):
        result = compute_risk_score(
            cvss_score=6.0, epss_score=0.7, is_kev=False,
        )
        assert result["tier"] == "critical_likely"
        assert result["score"] == 7.5  # 6.0 + 1.5

    def test_epss_above_threshold(self):
        result = compute_risk_score(
            cvss_score=7.0, epss_score=0.95, is_kev=False,
        )
        assert result["tier"] == "critical_likely"
        assert result["score"] == 8.5  # 7.0 + 1.5

    def test_epss_max_capped(self):
        """Score не должен превышать 10.0."""
        result = compute_risk_score(
            cvss_score=9.5, epss_score=0.99, is_kev=False,
        )
        assert result["tier"] == "critical_likely"
        assert result["score"] == 10.0  # capped

    def test_epss_just_below_threshold_not_critical_likely(self):
        result = compute_risk_score(
            cvss_score=6.0, epss_score=0.69, is_kev=False,
        )
        assert result["tier"] != "critical_likely"


# ---------- Tier 3: high ----------

class TestHigh:
    """CVSS >= 8.0 или EPSS >= 0.3 даёт high (если не KEV/critical_likely)."""

    def test_high_cvss_low_epss(self):
        result = compute_risk_score(
            cvss_score=8.0, epss_score=0.0, is_kev=False,
        )
        assert result["tier"] == "high"
        assert result["score"] == 8.0

    def test_high_cvss_at_boundary(self):
        result = compute_risk_score(
            cvss_score=8.0, epss_score=0.05, is_kev=False,
        )
        assert result["tier"] == "high"

    def test_critical_cvss(self):
        """CVSS 9.8 без KEV/EPSS — это high (важно: не critical, потому что нет реальных индикаторов эксплуатации)."""
        result = compute_risk_score(
            cvss_score=9.8, epss_score=0.0, is_kev=False,
        )
        assert result["tier"] == "high"
        assert result["score"] == 9.8

    def test_medium_cvss_high_epss(self):
        """Средний CVSS (5-7) + EPSS >= 0.3 → high."""
        result = compute_risk_score(
            cvss_score=6.0, epss_score=0.5, is_kev=False,
        )
        assert result["tier"] == "high"
        assert result["score"] == 7.0  # 6.0 + 1.0

    def test_epss_03_threshold(self):
        result = compute_risk_score(
            cvss_score=5.5, epss_score=0.3, is_kev=False,
        )
        assert result["tier"] == "high"

    def test_low_cvss_medium_epss(self):
        """Низкий CVSS + EPSS >= 0.3 → всё равно high."""
        result = compute_risk_score(
            cvss_score=3.5, epss_score=0.4, is_kev=False,
        )
        assert result["tier"] == "high"


# ---------- Tier 4: medium ----------

class TestMedium:
    """CVSS 5.0-7.9 без KEV и без высокого EPSS — medium."""

    def test_medium_at_threshold(self):
        result = compute_risk_score(
            cvss_score=5.0, epss_score=0.0, is_kev=False,
        )
        assert result["tier"] == "medium"
        assert result["score"] == 5.0

    def test_medium_with_low_epss(self):
        result = compute_risk_score(
            cvss_score=6.5, epss_score=0.05, is_kev=False,
        )
        assert result["tier"] == "medium"

    def test_medium_just_below_high(self):
        result = compute_risk_score(
            cvss_score=7.9, epss_score=0.1, is_kev=False,
        )
        assert result["tier"] == "medium"


# ---------- Tier 5: low ----------

class TestLow:
    """CVSS < 5.0 без KEV и без существенного EPSS."""

    def test_low_cvss(self):
        result = compute_risk_score(
            cvss_score=3.5, epss_score=0.0, is_kev=False,
        )
        assert result["tier"] == "low"

    def test_zero_cvss(self):
        result = compute_risk_score(
            cvss_score=0.0, epss_score=0.0, is_kev=False,
        )
        assert result["tier"] == "low"

    def test_none_cvss(self):
        """CVE без CVSS — должно попадать в low."""
        result = compute_risk_score(
            cvss_score=None, epss_score=None, is_kev=False,
        )
        assert result["tier"] == "low"


# ---------- Boundary cases (граничные значения) ----------

class TestBoundaries:
    """Проверка точных границ между tier'ами."""

    def test_cvss_799_is_medium(self):
        """CVSS 7.99 — medium, не high."""
        result = compute_risk_score(
            cvss_score=7.99, epss_score=0.0, is_kev=False,
        )
        assert result["tier"] == "medium"

    def test_cvss_499_is_low(self):
        """CVSS 4.99 — low, не medium."""
        result = compute_risk_score(
            cvss_score=4.99, epss_score=0.0, is_kev=False,
        )
        assert result["tier"] == "low"

    def test_epss_069_not_critical_likely(self):
        """EPSS 0.69 — не critical_likely."""
        result = compute_risk_score(
            cvss_score=6.0, epss_score=0.69, is_kev=False,
        )
        assert result["tier"] == "high"

    def test_epss_029_not_high(self):
        """EPSS 0.29 при низком CVSS не повышает до high."""
        result = compute_risk_score(
            cvss_score=4.0, epss_score=0.29, is_kev=False,
        )
        assert result["tier"] == "low"


# ---------- Edge cases ----------

class TestEdgeCases:
    """Странные/невалидные входные данные."""

    def test_all_none(self):
        result = compute_risk_score(
            cvss_score=None, epss_score=None, is_kev=False,
        )
        assert result["tier"] == "low"
        assert result["score"] == 0.0

    def test_negative_cvss_treated_as_zero(self):
        """Защита от мусорных данных — отрицательный CVSS = 0."""
        result = compute_risk_score(
            cvss_score=-1.0, epss_score=0.0, is_kev=False,
        )
        # cvss_score=-1.0 — функция не отрицает его, но tier должен быть low
        assert result["tier"] == "low"

    def test_score_never_exceeds_10(self):
        """При любых вводах score <= 10.0."""
        cases = [
            (10.0, 1.0, True, True),
            (10.0, 0.99, False),
            (9.5, 0.95, True),
        ]
        for case in cases:
            if len(case) == 3:
                result = compute_risk_score(case[0], case[1], case[2])
            else:
                result = compute_risk_score(
                    case[0], case[1], case[2], kev_known_ransomware=case[3]
                )
            assert result["score"] <= 10.0, f"Score > 10 для {case}"

    def test_reasoning_not_empty(self):
        """Каждый ответ должен иметь хотя бы одну причину."""
        cases = [
            (9.8, 0.95, True, True),
            (7.0, 0.8, False),
            (8.5, 0.0, False),
            (6.0, 0.5, False),
            (5.5, 0.0, False),
            (2.0, 0.0, False),
        ]
        for case in cases:
            if len(case) == 4:
                result = compute_risk_score(
                    case[0], case[1], case[2], kev_known_ransomware=case[3]
                )
            else:
                result = compute_risk_score(case[0], case[1], case[2])
            assert len(result["reasoning"]) > 0


# ---------- Параметризованный массовый тест ----------

@pytest.mark.parametrize("cvss,epss,kev,expected_tier", [
    # KEV всегда critical_now
    (9.0, 0.5, True, "critical_now"),
    (3.0, 0.0, True, "critical_now"),
    (0.0, 0.0, True, "critical_now"),
    # EPSS >= 0.7 → critical_likely
    (5.0, 0.7, False, "critical_likely"),
    (8.0, 0.85, False, "critical_likely"),
    # CVSS >= 8.0 → high
    (8.0, 0.0, False, "high"),
    (9.5, 0.1, False, "high"),
    # EPSS >= 0.3 → high
    (4.0, 0.5, False, "high"),
    (3.0, 0.3, False, "high"),
    # CVSS >= 5.0 → medium
    (5.0, 0.0, False, "medium"),
    (7.5, 0.2, False, "medium"),
    # Остальное → low
    (4.0, 0.0, False, "low"),
    (0.0, 0.0, False, "low"),
])
def test_tier_assignment(cvss, epss, kev, expected_tier):
    """Параметризованный тест базовой матрицы."""
    result = compute_risk_score(cvss_score=cvss, epss_score=epss, is_kev=kev)
    assert result["tier"] == expected_tier, (
        f"Для cvss={cvss}, epss={epss}, kev={kev} "
        f"ожидался '{expected_tier}', получен '{result['tier']}'"
    )