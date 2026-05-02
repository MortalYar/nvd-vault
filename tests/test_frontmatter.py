"""Round-trip тесты для frontmatter parser/writer."""

from nvd_vault.core.frontmatter import parse_frontmatter
from nvd_vault.core.markdown_writer import _yaml_list, _yaml_str


def test_yaml_str_simple_value_no_quoting():
    assert _yaml_str("nginx") == "nginx"
    assert _yaml_str("CVE-2024-1234") == "CVE-2024-1234"


def test_yaml_str_quotes_value_with_comma():
    assert _yaml_str("foo, bar") == '"foo, bar"'


def test_yaml_str_quotes_value_with_brackets():
    assert _yaml_str("foo[bar]") == '"foo[bar]"'


def test_yaml_str_escapes_inner_quotes():
    assert _yaml_str('foo "bar"') == '"foo \\"bar\\""'


def test_yaml_str_empty_string():
    assert _yaml_str("") == '""'


def test_yaml_list_simple():
    assert _yaml_list(["a", "b", "c"]) == "[a, b, c]"


def test_yaml_list_with_special_chars():
    assert _yaml_list(["foo", "bar, baz"]) == '[foo, "bar, baz"]'


def test_yaml_list_empty():
    assert _yaml_list([]) == "[]"


def test_roundtrip_simple_list():
    """Записали и прочитали — список из простых имён."""
    serialized = f"---\nproducts: {_yaml_list(['nginx', 'openssl'])}\n---\n"
    fm, _ = parse_frontmatter(serialized)
    assert fm["products"] == ["nginx", "openssl"]


def test_roundtrip_list_with_comma_in_name():
    """Имя с запятой выживает round-trip без потерь."""
    original = ["foo, bar", "baz"]
    serialized = f"---\nproducts: {_yaml_list(original)}\n---\n"
    fm, _ = parse_frontmatter(serialized)
    assert fm["products"] == ["foo, bar", "baz"]


def test_roundtrip_list_with_quotes_in_name():
    """Кавычка внутри имени тоже переживает round-trip."""
    original = ['foo "x" bar']
    serialized = f"---\nproducts: {_yaml_list(original)}\n---\n"
    fm, _ = parse_frontmatter(serialized)
    assert fm["products"] == ['foo "x" bar']


def test_backward_compat_unquoted_lists():
    """Старые vault-файлы без кавычек парсятся как раньше."""
    content = "---\nproducts: [nginx, openssl, kibana]\ntags: [critical, kev]\n---\n"
    fm, _ = parse_frontmatter(content)
    assert fm["products"] == ["nginx", "openssl", "kibana"]
    assert fm["tags"] == ["critical", "kev"]


def test_empty_list():
    fm, _ = parse_frontmatter("---\nproducts: []\n---\n")
    assert fm["products"] == []