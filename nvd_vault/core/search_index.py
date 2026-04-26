"""SQLite FTS5 индекс для полнотекстового поиска по vault."""

import threading
import re
import sqlite3
from pathlib import Path
from typing import Optional


class SearchIndex:
    """Хранит FTS5-индекс по содержимому заметок vault."""

    def __init__(self) -> None:
        self.conn: Optional[sqlite3.Connection] = None
        self._vault_path: Optional[Path] = None
        self._lock = threading.Lock()

    def build(self, vault_path: Path) -> dict:
        """Построить индекс заново для указанного vault."""
        self._vault_path = vault_path

        # In-memory БД -- быстро, не оставляет мусора на диске
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

        cur = self.conn.cursor()
        cur.executescript("""
            CREATE VIRTUAL TABLE notes USING fts5(
                relative_path UNINDEXED,
                folder UNINDEXED,
                name,
                title,
                tags,
                body,
                tokenize = 'unicode61 remove_diacritics 1'
            );
        """)

        indexed = 0
        with self._lock:
            for subfolder in ("products", "cves", "cwes"):
                folder = vault_path / subfolder
                if not folder.exists():
                    continue
                for md_file in folder.glob("*.md"):
                    self._index_file(md_file, subfolder)
                    indexed += 1
            self.conn.commit()

        return {"indexed": indexed}

    def search(self, query: str, limit: int = 50) -> list[dict]:
        """
        Поиск по индексу. Возвращает релевантные заметки.
        Использует FTS5 ranking + snippet для подсветки.
        """
        if not self.conn:
            return []

        clean_query = self._sanitize_query(query)
        if not clean_query:
            return []

        try:
            with self._lock:
                cur = self.conn.cursor()
                cur.execute("""
                    SELECT
                        relative_path,
                        folder,
                        name,
                        title,
                        snippet(notes, 5, '<mark>', '</mark>', '...', 32) as excerpt,
                        rank
                    FROM notes
                    WHERE notes MATCH ?
                    ORDER BY rank
                    LIMIT ?
                """, (clean_query, limit))

                results = []
                for row in cur.fetchall():
                    results.append({
                        "relative_path": row["relative_path"],
                        "folder": row["folder"],
                        "name": row["name"],
                        "title": row["title"] or row["name"],
                        "excerpt": row["excerpt"],
                    })
                return results
        except sqlite3.OperationalError as e:
            return [{"error": f"Некорректный запрос: {e}"}]

    def close(self) -> None:
        with self._lock:
            if self.conn:
                self.conn.close()
                self.conn = None

    # ---------- Внутренние ----------

    def _index_file(self, path: Path, folder: str) -> None:
        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            return

        # Извлекаем frontmatter
        fm, body = self._split_frontmatter(content)

        # Заголовок: первый '# ...' в теле или имя файла
        title = path.stem
        title_match = re.search(r"^#\s+(.+)$", body, re.MULTILINE)
        if title_match:
            title = title_match.group(1).strip()

        # Теги в одну строку для индексации
        tags_list = fm.get("tags", []) or []
        if not isinstance(tags_list, list):
            tags_list = []
        # Также добавим severity и type как теги
        for key in ("severity", "type", "vendor"):
            val = fm.get(key)
            if val and isinstance(val, str):
                tags_list.append(val)
        tags_text = " ".join(tags_list)

        # Тело без frontmatter и markdown-разметки (упрощённо)
        clean_body = self._strip_markdown(body)

        relative = f"{folder}/{path.name}"

        self.conn.execute(
            "INSERT INTO notes (relative_path, folder, name, title, tags, body) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (relative, folder, path.stem, title, tags_text, clean_body),
        )

    @staticmethod
    def _split_frontmatter(content: str) -> tuple[dict, str]:
        """Разделить frontmatter и тело. Простой парсер ключ:значение."""
        match = re.match(r"^---\n(.*?)\n---\n", content, re.DOTALL)
        if not match:
            return {}, content

        yaml_text = match.group(1)
        body = content[match.end():]

        fm: dict = {}
        for line in yaml_text.split("\n"):
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()

            if value.startswith("[") and value.endswith("]"):
                inner = value[1:-1].strip()
                fm[key] = [x.strip() for x in inner.split(",")] if inner else []
            else:
                fm[key] = value

        return fm, body

    @staticmethod
    def _strip_markdown(text: str) -> str:
        """Очистить markdown-разметку для индексации (грубо, но для FTS достаточно)."""
        # Убираем заголовки (### → пусто)
        text = re.sub(r"^#+\s+", "", text, flags=re.MULTILINE)
        # Убираем wiki-links: [[name]] → name
        text = re.sub(r"\[\[([^\]]+)\]\]", r"\1", text)
        # Markdown-ссылки [text](url) → text
        text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
        # Bold/italic markers
        text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
        text = re.sub(r"\*([^*]+)\*", r"\1", text)
        # Inline code
        text = re.sub(r"`([^`]+)`", r"\1", text)
        return text.strip()

    @staticmethod
    def _sanitize_query(query: str) -> str:
        """
        FTS5 имеет специальный синтаксис (AND, OR, NOT, "...", *).
        Разрешаем простой поиск: разбиваем по словам, берём только алфанум+дефис+звёздочка.
        Каждое слово оборачиваем в кавычки чтобы избежать конфликта со словами FTS5.
        """
        words = re.findall(r"[\w\-]+\*?", query, flags=re.UNICODE)
        if not words:
            return ""
        # Все слова должны быть в результате (AND-семантика по умолчанию в FTS5)
        return " ".join(f'"{w}"' for w in words)