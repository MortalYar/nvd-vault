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