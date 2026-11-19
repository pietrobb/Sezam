"""Review 688edcb N3: duplicate-looking names and NBSP.

Lockout review N3 trimmed the name with each language's own trim. Those
differ: Python's str.strip keeps a BOM and a zero-width space that JS/Dart
trim (or keep), MariaDB's [[:space:]] misses NBSP, and nobody normalized the
Unicode form. So "\\ufeffalice" from one client reached no account while the
web reached "alice"; an NFD "Šimon" registered next to the NFC one as a
second, identical-looking account; the migration left "alice\\u00a0" under a
name no request can reach; and an untrimmed account whose trimmed name was
taken stayed unreachable for good. Now one function (server, desktop, web,
phone) gives the same name, and the migration renames such accounts.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_regular_user,
    app_client,
    mock_db,
)
from tests.test_username_trim_review_n3 import _Cursor, _register
from tests.node_support import node_cmd, requires_node

ROOT = Path(__file__).resolve().parents[1]
NFD_SIMON = "S\u030cimon"
NFC_SIMON = "\u0160imon"
VECTORS = {
    " alice\u00a0": "alice",
    "\ufeffalice": "alice",
    "alice\u200b": "alice",
    "alice\x1c": "alice",
    "\x85alice": "alice",
    "\u3000alice\u202f": "alice",
    NFD_SIMON: NFC_SIMON,
    "a\u00a0b": "a\u00a0b",
    " \u00a0\ufeff ": "",
}


def test_desktop_and_server_normalize_alike():
    from sezam.usernames import normalize_username as desktop
    from server.app.models.schemas import normalize_username as server

    for raw, expected in VECTORS.items():
        assert server(raw) == expected, repr(raw)
        assert desktop(raw) == expected, repr(raw)


@requires_node
def test_web_normalizes_like_the_server():
    src = (ROOT / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    start = src.index("function normalizeUsername(")
    fn = src[start:src.index("\n}\n", start) + 3]
    script = fn + f"\nconsole.log(JSON.stringify({json.dumps(list(VECTORS))}.map(normalizeUsername)));"
    out = subprocess.run(
        [node_cmd(), "-e", script], check=True, capture_output=True, text=True, encoding="utf-8"
    ).stdout
    assert json.loads(out) == list(VECTORS.values())


def test_every_web_entry_point_normalizes():
    src = (ROOT / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    for field in ("username", "onboard-username", "bootstrap-username"):
        assert f"normalizeUsername(document.getElementById('{field}').value)" in src


def test_phone_normalizes_like_the_server():
    dart = (ROOT / "mobile" / "lib" / "services" / "auth_service.dart").read_text(encoding="utf-8")
    assert "unorm.nfc(username).replaceAll(_usernameEdge, '')" in dart
    assert r"r'^[\s\ufeff\u200b\x1c-\x1f\x85]+|[\s\ufeff\u200b\x1c-\x1f\x85]+$'" in dart


@pytest.mark.asyncio
async def test_nfd_name_is_the_nfc_account(app_client, mock_db):
    from tests.test_username_trim_review_n3 import _create_admin_user

    _create_admin_user(mock_db._storage)
    first = await _register(app_client, NFC_SIMON)
    assert first.status_code == 200, first.text
    second = await _register(app_client, NFD_SIMON + "\u00a0")
    assert second.status_code == 409, second.text
    assert [u["username"] for u in mock_db._storage["users"]] == ["admin", NFC_SIMON]


@pytest.mark.asyncio
async def test_bom_padded_name_gets_the_real_salt(app_client, mock_db):
    _create_regular_user(mock_db._storage, username="alice")
    mock_db._storage["users"][0]["argon2_salt"] = b"\x11" * 16
    meta = (await app_client.get("/api/meta", params={"username": "\ufeffalice\u200b"})).json()
    assert meta["argon2_salt"] == "11" * 16


class _MariaCursor(_Cursor):
    """MariaDB's REGEXP [[:space:]] is ASCII only."""

    async def execute(self, query: str, args: tuple = ()) -> None:
        if query.startswith("SELECT id, username") and "REGEXP" in query:
            self._rows = [
                (uid, name) for uid, name in self.users.items()
                if re.search(r"^\s|\s$", name, re.ASCII)
            ]
        elif query.startswith("SELECT id, username"):
            self._rows = list(self.users.items())
        else:
            await super().execute(query, args)


def test_migration_reaches_unicode_padding_and_renames_taken_names(caplog):
    from server.app.database import trim_stored_usernames

    cur = _MariaCursor({
        "A": "alice\u00a0", "B": NFD_SIMON, "C": "carol", "D": " carol ",
        "E": "carol\u00a0", "F": "dave",
    })
    with caplog.at_level("WARNING"):
        asyncio.run(trim_stored_usernames(cur))
    assert cur.users == {
        "A": "alice", "B": NFC_SIMON, "C": "carol", "D": "carol-2",
        "E": "carol-3", "F": "dave",
    }
    assert "now logs in as 'carol-2'" in caplog.text
