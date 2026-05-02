"""Дисковый кэш для ответов NVD API.

Хранит JSON-файлы в стандартной user cache directory (платформо-зависимая).
Каждый файл = один ответ NVD (или discover_vendors), с timestamp создания.

При чтении проверяется TTL: если запись старше — считается отсутствующей.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24 часа


def default_cache_dir() -> Path:
    """Стандартный путь для кэша на текущей платформе."""
    if os.name == "nt":  # Windows
        base = Path(
            os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
        )
        return base / "nvd-vault" / "cache"
    # Linux/macOS — XDG-style ~/.cache/nvd-vault
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "nvd-vault"
    return Path.home() / ".cache" / "nvd-vault"


def _sanitize_key(key: str) -> str:
    """Превращает произвольный ключ в безопасное имя файла.

    Заменяет всё, что не [a-zA-Z0-9._-] на '_'. Регистр приводит к lowercase
    для согласованности (cache hit не зависит от регистра ввода).
    """
    return re.sub(r"[^a-zA-Z0-9._-]", "_", key.lower())


class NvdCache:
    """Простой key-value JSON-кэш с TTL."""

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self.cache_dir = cache_dir or default_cache_dir()
        self.ttl_seconds = ttl_seconds
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.cache_dir / f"{_sanitize_key(key)}.json"

    def get(self, key: str) -> Optional[dict]:
        """Возвращает данные если кэш свежий, иначе None."""
        path = self._path(key)
        if not path.exists():
            return None

        try:
            with path.open(encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Битый файл кэша %s: %s", path, e)
            return None

        timestamp = payload.get("timestamp", 0)
        age = time.time() - timestamp
        if age > self.ttl_seconds:
            logger.debug("Кэш-промах (TTL): %s, возраст %.0f сек", key, age)
            return None

        logger.debug("Кэш-попадание: %s (возраст %.0f сек)", key, age)
        return payload.get("data")

    def set(self, key: str, data: dict) -> None:
        """Сохраняет данные с текущим timestamp."""
        path = self._path(key)
        payload = {
            "timestamp": time.time(),
            "key": key,
            "data": data,
        }
        try:
            # Атомарная запись через временный файл, чтобы не получить
            # битый JSON если процесс упадёт посередине записи.
            tmp = path.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
            tmp.replace(path)
        except OSError as e:
            logger.warning("Не удалось записать кэш %s: %s", path, e)

    def clear(self) -> int:
        """Удаляет весь кэш. Возвращает количество удалённых файлов."""
        count = 0
        for f in self.cache_dir.glob("*.json"):
            try:
                f.unlink()
                count += 1
            except OSError as e:
                logger.warning("Не удалось удалить %s: %s", f, e)
        return count

    def stats(self) -> dict:
        """Возвращает {files: N, bytes: M} по содержимому кэша."""
        files = list(self.cache_dir.glob("*.json"))
        total = sum(f.stat().st_size for f in files)
        return {
            "files": len(files),
            "bytes": total,
            "path": str(self.cache_dir),
        }