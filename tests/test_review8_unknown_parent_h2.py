"""Review main@a159e97 H2, desktop: the forged-folder filter let an unknown parent through.

The check of 7c10379 H4 judges a pulled folder or item by the folder it is
written into. A parent the desktop did not know passed unjudged ("handled
where items are reattached"), and the reattach then hung the folder straight
below the admin's root, where it stayed through every honest pull after.
A lying server only had to hold the real parent back once (or for good: to
the desktop that is a parent id that does not exist). Such a write is now
held back until its parent is known and judged then; written by this
account or an admin it is applied as before.
"""

from __future__ import annotations

import contextlib

import pytest

import server.app.routers.sync as server_sync
from sezam import cli
from sezam.models import new_ulid
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)
from tests.test_review6_web_member_personal_folder import sealed
from tests.test_review7_forged_root_folder_desktop_h4 import (
    _always,
    _forged_payloads,
    _login,
    _names,
    _push,
)
from tests.test_server_spec import _create_regular_user


@pytest.fixture
def member(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    root = laptop.db.get_meta("root_node_id")
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    payloads = _forged_payloads(phone, root)
    phone.lock()
    alice = new_ulid()
    sk, _ = _create_regular_user(db._storage, alice, "alice")
    token = _login(url, sk, "alice")
    # A server before b8c3cb8, or a lying one, takes whatever she writes.
    monkeypatch.setattr(server_sync, "_has_write_authority", _always)
    yield url, laptop, root, payloads, (token, sk), db
    laptop.lock()


@contextlib.contextmanager
def _withheld(db, obj_id):
    """The server leaves one object out of what it serves."""
    rows = db._storage["vault_objects"]
    held = [row for row in rows if row["id"] == obj_id]
    rows[:] = [row for row in rows if row["id"] != obj_id]
    try:
        yield
    finally:
        rows.extend(held)


def _visible_anywhere(laptop, obj_id):
    return (
        laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (obj_id,)) is not None
        or laptop.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (obj_id,)) is not None
    )


def test_a_folder_below_a_parent_held_back_is_not_shown_below_the_root(member):
    url, laptop, root, (folder, folder_payload, entry, entry_payload), (token, sk), db = member
    _push(url, token, sk, folder, "node", root, folder_payload)
    sub = new_ulid()
    _push(url, token, sk, sub, "node", folder, folder_payload)
    _push(url, token, sk, entry, "entry", sub, entry_payload)

    # To this desktop the folder does not exist: its sub-folder names a
    # parent it does not know.
    with _withheld(db, folder):
        result = _client(laptop, url).pull()
        assert result["skipped"] == 2
        assert not _visible_anywhere(laptop, sub)
        assert not _visible_anywhere(laptop, entry)
        assert laptop.list_nodes(root) == []
        _client(laptop, url).full_resync(confirmed=True)
        assert not _visible_anywhere(laptop, sub)
        assert laptop.list_nodes(root) == []

    # The honest pull brings the folder: it and all below it are left out.
    _client(laptop, url).pull()
    for obj_id in (folder, sub, entry):
        assert not _visible_anywhere(laptop, obj_id)
    assert "IT - nove VPN prihlasenie" not in _names(laptop, root)


def _signs_a_top_level_node(url, db, token, sk, payload):
    """Capability run 196: the server takes one admin-only object from her (it
    sets the admin flag; there is nothing signed about it), so her signature
    is on a top-level node in the same pull."""
    user = next(u for u in db._storage["users"] if u.get("username") == "alice")
    user["is_admin"] = 1
    try:
        _push(url, token, sk, new_ulid(), "node", None, payload)
    finally:
        user["is_admin"] = 0
    return user["id"]


def test_an_account_the_server_calls_admin_is_still_held_back(member):
    url, laptop, root, (folder, folder_payload, entry, entry_payload), (token, sk), db = member
    _push(url, token, sk, folder, "node", root, folder_payload)
    sub = new_ulid()
    _push(url, token, sk, sub, "node", folder, folder_payload)
    _push(url, token, sk, entry, "entry", sub, entry_payload)
    _signs_a_top_level_node(url, db, token, sk, folder_payload)
    with _withheld(db, folder):
        assert _client(laptop, url).pull()["skipped"] == 2
        assert not _visible_anywhere(laptop, sub)
        assert not _visible_anywhere(laptop, entry)
        assert laptop.list_nodes(root) == []


def test_an_account_the_server_calls_admin_may_not_write_below_the_root(member):
    url, laptop, root, (folder, folder_payload, entry, entry_payload), (token, sk), db = member
    _signs_a_top_level_node(url, db, token, sk, folder_payload)
    _push(url, token, sk, folder, "node", root, folder_payload)
    _push(url, token, sk, entry, "entry", folder, entry_payload)
    assert _client(laptop, url).pull()["skipped"] == 2
    assert not _visible_anywhere(laptop, folder)
    assert "IT - nove VPN prihlasenie" not in _names(laptop, root)


def test_an_item_held_back_for_its_parent_is_applied_when_the_parent_may_hold_it(member):
    url, laptop, root, _payloads, (token, sk), db = member
    personal_dek, personal, item = new_ulid(), new_ulid(), new_ulid()
    _push(url, token, sk, personal_dek, "dek", None, b"k" * 72)
    _push(url, token, sk, personal, "node", root, sealed(personal_dek))
    meta = sealed(personal_dek)
    _push(url, token, sk, item, "entry", personal, len(meta).to_bytes(4, "big") + meta + b"d")
    with _withheld(db, personal):
        assert _client(laptop, url).pull()["skipped"] == 1
        assert not _visible_anywhere(laptop, item)

    # Her personal folder (sealed with her own key) arrives with a later
    # change of it: the item in it, sealed with her key as well, is applied now.
    _push(url, token, sk, personal, "node", root, sealed(personal_dek), version=2)
    _client(laptop, url).pull()
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (personal,)) is not None
    assert laptop.db.fetchone(
        "SELECT node_id FROM entries WHERE id = ?", (item,)
    )["node_id"] == personal
