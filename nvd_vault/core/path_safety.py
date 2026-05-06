"""Санитизация пользовательских строк перед использованием в путях файловой системы.

Имена продуктов из SBOM и inventory.json приходят от внешнего источника
и могут содержать что угодно: '..', '/', '\\', управляющие символы,
зарезервированные имена Windows (CON, PRN, AUX, NUL, COM1-9, LPT1-9).

Эта функция приводит произвольную строку к безопасному имени файла,
не теряя читаемости там, где это возможно.
"""

import re

# Зарезервированные имена устройств в Windows.
# Файл с любым из них (даже с расширением, e.g. CON.txt) недоступен.
_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

# Запрещённые символы: разделители путей, спецсимволы Windows, управляющие.
_FORBIDDEN = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def safe_filename_stem(value: str, fallback: str = "untitled", max_length: int = 200) -> str:
    """Превращает произвольную строку в безопасный stem (без расширения).

    Гарантии:
    - Не содержит разделителей пути ('/', '\\') — нельзя выйти за пределы директории.
    - Не равен '.' или '..' — не попадёт в parent directory.
    - Не совпадает с Windows-reserved именами.
    - Длина <= max_length.
    - Если результат пустой — возвращается fallback.
    """
    name = (value or "").strip()
    if not name:
        return fallback

    # Заменяем всё запрещённое на '_'
    name = _FORBIDDEN.sub("_", name)

    # Точки в начале/конце Windows плохо переваривает
    name = name.strip(". ")

    # Защита от '..', '.' и пустой строки после очистки
    if name in ("", ".", ".."):
        return fallback

    # Windows-reserved (case-insensitive)
    if name.lower() in _WINDOWS_RESERVED:
        name = f"_{name}"

    # Длина
    if len(name) > max_length:
        name = name[:max_length]

    return name