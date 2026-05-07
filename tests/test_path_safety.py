from nvd_vault.core.path_safety import safe_filename_stem


def test_normal_name_unchanged():
    assert safe_filename_stem("nginx") == "nginx"
    assert safe_filename_stem("CVE-2024-1234") == "CVE-2024-1234"
    assert safe_filename_stem("CWE-79") == "CWE-79"


def test_path_traversal_neutralized():
    result = safe_filename_stem("../../etc/passwd")
    assert "/" not in result
    assert "\\" not in result
    assert result not in ("", ".", "..")

    assert safe_filename_stem("..") == "untitled"
    assert safe_filename_stem(".") == "untitled"


def test_pure_traversal_inputs_are_safe():
    """Любой ввод из одних точек/слэшей не должен возвращать
    traversal-сегмент или пустоту. Конкретное значение — деталь реализации."""
    for evil in ["..", ".", "../..", "....", "./.", "../"]:
        result = safe_filename_stem(evil)
        assert result not in ("", ".", "..")
        assert "/" not in result
        assert "\\" not in result


def test_path_separators_replaced():
    assert "/" not in safe_filename_stem("foo/bar")
    assert "\\" not in safe_filename_stem("foo\\bar")


def test_windows_reserved_names_prefixed():
    assert safe_filename_stem("con") == "_con"
    assert safe_filename_stem("CON") == "_CON"
    assert safe_filename_stem("com1") == "_com1"
    assert safe_filename_stem("nul") == "_nul"


def test_windows_forbidden_chars_replaced():
    assert safe_filename_stem('a<b>c:d"e') == "a_b_c_d_e"
    assert safe_filename_stem("name|with?wildcard*") == "name_with_wildcard_"


def test_control_characters_replaced():
    assert safe_filename_stem("a\x00b\x01c") == "a_b_c"


def test_empty_returns_fallback():
    assert safe_filename_stem("") == "untitled"
    assert safe_filename_stem("   ") == "untitled"
    assert safe_filename_stem(None) == "untitled"


def test_custom_fallback():
    assert safe_filename_stem("", fallback="cve") == "cve"


def test_long_name_truncated():
    long_name = "a" * 500
    result = safe_filename_stem(long_name)
    assert len(result) == 200


def test_leading_trailing_dots_stripped():
    assert safe_filename_stem(".hidden") == "hidden"
    assert safe_filename_stem("file.") == "file"
    assert safe_filename_stem("...") == "untitled"


def test_windows_reserved_with_extension():
    """CON.md тоже зарезервировано — Windows блокирует имя по части до точки."""
    result = safe_filename_stem("CON.md")
    assert result.startswith("_"), f"Expected reserved prefix, got {result!r}"
    assert result.lower() != "con.md"


def test_com0_lpt0_reserved():
    """COM0 и LPT0 тоже Windows-reserved, не только COM1-9/LPT1-9."""
    assert safe_filename_stem("COM0") == "_COM0"
    assert safe_filename_stem("lpt0") == "_lpt0"


def test_truncation_strips_trailing_dot():
    """После обрезания на max_length не должно оставаться trailing-точки."""
    result = safe_filename_stem("hello.world", max_length=6)
    assert not result.endswith("."), f"Trailing dot in {result!r}"


def test_truncation_to_only_dots_returns_fallback():
    """Если после обрезания и rstrip имя стало пустым — fallback."""
    # 'a..........' max=2 → 'a.' → rstrip → 'a' (нормально)
    assert safe_filename_stem("a..........", max_length=2) == "a"
    # 'x.x.x.x...' max=1 → 'x' → норм; вариант где обрезание даёт только точки
    assert safe_filename_stem("x." * 100, max_length=1) in ("x", "untitled")
