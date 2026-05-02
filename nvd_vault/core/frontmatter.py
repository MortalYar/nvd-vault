"""Парсер YAML-frontmatter для markdown-заметок vault.

Поддерживает:
- строки (raw): `name: nginx` -> {"name": "nginx"}
- списки: `tags: [a, b, c]` -> {"tags": ["a", "b", "c"]}
- числа: `cvss: 9.8` -> {"cvss": 9.8}, `cve_count: 42` -> {"cve_count": 42}
- булевы: `kev: true` -> {"kev": True}
- null: `published: null` -> {"published": None}
"""

import re
from pathlib import Path

_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


def parse_frontmatter(content: str) -> tuple[dict, str]:
    """Разбирает YAML frontmatter в начале строки content.

    Возвращает (frontmatter_dict, body). Если frontmatter отсутствует —
    ({}, content).
    """
    match = _FRONTMATTER_RE.match(content)
    if not match:
        return {}, content

    yaml_text = match.group(1)
    body = content[match.end():]

    fm: dict = {}
    for line in yaml_text.split("\n"):
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        fm[key.strip()] = _parse_value(value.strip())
    return fm, body


def read_frontmatter(path: Path) -> dict:
    """Читает только frontmatter из файла, без тела.

    На любой ошибке (файл не существует, нечитаем) возвращает пустой dict.
    """
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    fm, _ = parse_frontmatter(content)
    return fm


def _parse_value(value: str):
    """Преобразует raw-строку YAML-значения в Python-тип."""
    if not value:
        return None

    # Список: [a, b, c] или [a, "b, with comma", c]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_unquote(item.strip()) for item in _split_list(inner)]

    # Quoted строка: "..."
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return _unquote(value)

    # Bool
    if value == "true":
        return True
    if value == "false":
        return False

    # Null
    if value == "null":
        return None

    # Число
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        pass

    # Строка
    return value


def _split_list(inner: str) -> list[str]:
    """Разбивает содержимое [...] на элементы, учитывая кавычки.

    Запятые внутри "..." не считаются разделителями.
    """
    items: list[str] = []
    buf: list[str] = []
    in_quotes = False
    escape = False

    for ch in inner:
        if escape:
            buf.append(ch)
            escape = False
            continue

        if ch == "\\" and in_quotes:
            buf.append(ch)
            escape = True
            continue

        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
            continue

        if ch == "," and not in_quotes:
            items.append("".join(buf))
            buf = []
            continue

        buf.append(ch)

    if buf:
        items.append("".join(buf))

    return items


def _unquote(value: str) -> str:
    """Снимает обрамляющие кавычки и разэкранирует \\\" -> \"."""
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        inner = value[1:-1]
        return inner.replace('\\"', '"').replace("\\\\", "\\")
    return value