"""In-memory FTS5 search (SQLite :memory:).

Spec 5.2: tokenize='unicode61 remove_diacritics 2' — prefix search, diacritics, multi-token AND.
Standard search: names, field keys, tags. Not values (unless deep search).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Optional


@dataclass
class SearchResult:
    """A search result pointing to a vault entry."""

    entry_id: str
    node_id: str
    name: str
    node_path: str  # e.g. "servers/hetzner"
    rank: float


class SearchIndex:
    """In-memory FTS5 search index built from decrypted metadata."""

    def __init__(self):
        self._conn: Optional[sqlite3.Connection] = None

    def build(self) -> None:
        """Create the in-memory FTS5 index."""
        self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS fts_entries USING fts5(
                entry_id UNINDEXED,
                node_id UNINDEXED,
                node_path UNINDEXED,
                name,
                field_keys,
                tags,
                tokenize='unicode61 remove_diacritics 2'
            )
            """
        )

    def add_entry(
        self,
        entry_id: str,
        node_id: str,
        node_path: str,
        name: str,
        field_keys: list[str],
        tags: list[str],
    ) -> None:
        """Add an entry to the search index."""
        if self._conn is None:
            return
        self._conn.execute(
            "INSERT INTO fts_entries (entry_id, node_id, node_path, name, field_keys, tags) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                entry_id,
                node_id,
                node_path,
                name,
                " ".join(field_keys),
                " ".join(tags),
            ),
        )

    def remove_entry(self, entry_id: str) -> None:
        """Remove an entry from the search index."""
        if self._conn is None:
            return
        self._conn.execute(
            "DELETE FROM fts_entries WHERE entry_id = ?", (entry_id,)
        )

    def search(self, query: str, limit: int = 50) -> list[SearchResult]:
        """Search the FTS index. Multi-token AND with prefix matching."""
        if self._conn is None:
            return []
        if not query.strip():
            return []

        # Build FTS5 query: each token gets a prefix match
        tokens = query.strip().split()
        fts_query = " AND ".join(f'"{t}"*' for t in tokens)

        try:
            rows = self._conn.execute(
                "SELECT entry_id, node_id, node_path, name, rank "
                "FROM fts_entries WHERE fts_entries MATCH ? "
                "ORDER BY rank LIMIT ?",
                (fts_query, limit),
            ).fetchall()
        except Exception:
            return []

        return [
            SearchResult(
                entry_id=row[0],
                node_id=row[1],
                node_path=row[2],
                name=row[3],
                rank=row[4],
            )
            for row in rows
        ]

    def clear(self) -> None:
        """Drop the FTS index (lock — zeroize search data)."""
        if self._conn:
            self._conn.close()
            self._conn = None
