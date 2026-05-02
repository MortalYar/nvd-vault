"""Тесты для NvdCache."""

import json
import time
from pathlib import Path

import pytest

from nvd_vault.core.nvd_cache import NvdCache, _sanitize_key


@pytest.fixture
def tmp_cache(tmp_path: Path) -> NvdCache:
    return NvdCache(cache_dir=tmp_path / "cache", ttl_seconds=3600)


def test_set_and_get_round_trip(tmp_cache: NvdCache):
    tmp_cache.set("nginx", {"foo": "bar", "items": [1, 2, 3]})
    assert tmp_cache.get("nginx") == {"foo": "bar", "items": [1, 2, 3]}


def test_get_missing_returns_none(tmp_cache: NvdCache):
    assert tmp_cache.get("never_set") is None


def test_ttl_expiry(tmp_path: Path):
    cache = NvdCache(cache_dir=tmp_path / "cache", ttl_seconds=1)
    cache.set("key", {"data": "value"})
    assert cache.get("key") == {"data": "value"}

    time.sleep(1.1)
    assert cache.get("key") is None


def test_zero_ttl_means_always_expired(tmp_path: Path):
    """TTL=0 фактически отключает кэш."""
    cache = NvdCache(cache_dir=tmp_path / "cache", ttl_seconds=0)
    cache.set("key", {"x": 1})
    # Сразу после записи уже считается устаревшим
    assert cache.get("key") is None


def test_sanitize_key_handles_special_chars():
    assert _sanitize_key("Foo Bar") == "foo_bar"
    assert _sanitize_key("vendor:product/v2") == "vendor_product_v2"
    assert _sanitize_key("UPPER") == "upper"
    assert _sanitize_key("dot.preserved-and_dash") == "dot.preserved-and_dash"


def test_keys_with_same_sanitized_name_collide(tmp_cache: NvdCache):
    """Это не баг, а контракт: 'a/b' и 'a:b' дают тот же файл."""
    tmp_cache.set("a/b", {"version": 1})
    tmp_cache.set("a:b", {"version": 2})
    # Последняя запись побеждает
    assert tmp_cache.get("a/b") == {"version": 2}


def test_corrupted_file_returns_none(tmp_path: Path):
    """Битый JSON не должен ронять кэш."""
    cache = NvdCache(cache_dir=tmp_path / "cache", ttl_seconds=3600)
    # Имитируем битый файл
    cache_file = cache._path("broken")
    cache_file.write_text("not valid json {", encoding="utf-8")

    assert cache.get("broken") is None


def test_two_instances_share_disk(tmp_path: Path):
    """Кэш реально на диске, а не in-memory — два инстанса видят одно."""
    a = NvdCache(cache_dir=tmp_path / "cache", ttl_seconds=3600)
    a.set("key", {"v": 42})

    b = NvdCache(cache_dir=tmp_path / "cache", ttl_seconds=3600)
    assert b.get("key") == {"v": 42}


def test_clear_removes_all_entries(tmp_cache: NvdCache):
    tmp_cache.set("a", {})
    tmp_cache.set("b", {})
    tmp_cache.set("c", {})

    deleted = tmp_cache.clear()
    assert deleted == 3
    assert tmp_cache.get("a") is None
    assert tmp_cache.get("b") is None


def test_stats(tmp_cache: NvdCache):
    s = tmp_cache.stats()
    assert s["files"] == 0
    assert s["bytes"] == 0
    assert "path" in s

    tmp_cache.set("x", {"data": "a" * 1000})
    s = tmp_cache.stats()
    assert s["files"] == 1
    assert s["bytes"] > 1000


def test_set_persists_on_disk_correctly(tmp_path: Path):
    """JSON на диске можно прочитать обычным способом."""
    cache = NvdCache(cache_dir=tmp_path / "cache", ttl_seconds=3600)
    cache.set("key", {"hello": "мир"})  # юникод проверяем тоже

    raw = cache._path("key").read_text(encoding="utf-8")
    payload = json.loads(raw)
    assert payload["data"]["hello"] == "мир"
    assert payload["key"] == "key"
    assert "timestamp" in payload


def test_atomic_write_no_tmp_files_left(tmp_cache: NvdCache):
    """После set() не должно оставаться .tmp файлов."""
    tmp_cache.set("key", {"x": 1})
    tmp_files = list(tmp_cache.cache_dir.glob("*.tmp"))
    assert tmp_files == []