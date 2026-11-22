"""docs/ROOT_CAUSE_PLAN.md S4 (INV-3): UserInfo.key_fingerprint is unsigned.

The team dialog's user table showed the server's fingerprint. An admin who
compared it with the member's own saw the real one, while the key pinned and
sealed for was the server's: the fingerprint shown is the pinned key's, or
none.
"""

from __future__ import annotations

import sqlite3
import sys
from types import SimpleNamespace

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication, QTableWidget, QTableWidgetItem  # noqa: E402

from sezam.gui import team_dialog  # noqa: E402

PINNED = "aa" * 32
REAL = "bb" * 32
OWN = "cc" * 32


class _Db:
    def __init__(self):
        self._conn = sqlite3.connect(":memory:")
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            "CREATE TABLE known_keys (user_id TEXT PRIMARY KEY, signing_pk BLOB, encryption_pk BLOB, "
            "fingerprint TEXT, first_seen INTEGER, last_verified INTEGER)"
        )
        self._conn.execute("INSERT INTO known_keys VALUES ('bob', x'00', x'00', ?, 0, 0)", (PINNED,))

    def fetchone(self, sql, params=()):
        return self._conn.execute(sql, params).fetchone()

    def get_meta(self, key):
        return {"user_id": "ann"}.get(key)


def test_user_table_shows_the_pinned_fingerprint_not_the_servers():
    _app = QApplication.instance() or QApplication(sys.argv)
    table = QTableWidget(0, 5)
    dialog = SimpleNamespace(
        _users_table=table,
        _vault=SimpleNamespace(db=_Db(), keypair=SimpleNamespace(fingerprint=OWN)),
        _status_item=lambda status: QTableWidgetItem(status),
    )
    rows = [
        {"id": "bob", "username": "bob", "status": "active", "key_fingerprint": REAL},
        {"id": "eve", "username": "eve", "status": "pending", "key_fingerprint": REAL},
        {"id": "ann", "username": "ann", "status": "active", "key_fingerprint": REAL},
    ]
    team_dialog.TeamDialog._show_users(dialog, rows)
    assert table.item(0, 2).text() == PINNED
    assert REAL not in table.item(1, 2).text()
    assert table.item(2, 2).text() == OWN
