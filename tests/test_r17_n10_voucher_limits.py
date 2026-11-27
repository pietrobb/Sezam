"""Review c02cc47 R17-N10/N11: the voucher endpoints and the folder-move check
had no bounds.

N10: a JWT alone posted the same voucher list again and again (hundreds of MiB
stored), and one GET read and decoded all of them on the event loop. A list is
kept once (UNIQUE user, key, signature), a key holds at most
MAX_LISTS_PER_KEY lists and MAX_BYTES_PER_KEY bytes (413 key_vouchers_full),
the signatures are checked off the event loop (a rotation's before the push's
global lock), and the GET is paged; every client follows the pages.

N11: ``_is_below`` ran one SELECT per level under the global lock for every new
or moved folder. A new folder skips it, the rows come from the push's
authority cache, and the walk is bounded.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os

import pytest
from nacl.signing import SigningKey

from sezam import key_vouchers as kv
from server.app import key_vouchers as server_kv
from server.app.routers import sync as sync_router
from tests.test_archived_key_bound_v4 import _bob_desktop, _rotated_team
from tests.test_cross_client_password_change import _web_login
from tests.test_grant_folder_access import _readable_passwords, team  # noqa: F401
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401
from tests.test_key_vouchers_server import _entry, _identity_rotation, _old_object, _vouchers
from tests.test_review2_rotation_server import USER_ID, _auth, _dek, _seeded
from tests.test_review_web import pytestmark  # noqa: F401
from tests.test_server_spec import MockCursor, _sign_sync_object, app_client, mock_db  # noqa: F401


async def _post(app_client, token, voucher_list):  # noqa: F811
    return await app_client.post("/api/users/me/key-vouchers", json=voucher_list, headers=_auth(token))


@pytest.mark.asyncio
async def test_a_list_sent_again_is_kept_once(app_client, mock_db):  # noqa: F811
    sk, token = await _seeded(app_client, mock_db)
    good = kv.sign_vouchers(USER_ID, sk, [_entry(mock_db)])

    for _ in range(3):
        resp = await _post(app_client, token, good)
        assert resp.status_code == 200, resp.text

    assert len(mock_db._storage["key_vouchers"]) == 1
    assert (await _vouchers(app_client, token))["lists"] == [good]


@pytest.mark.asyncio
async def test_a_key_holds_a_bounded_number_of_lists_and_bytes(app_client, mock_db, monkeypatch):  # noqa: F811
    sk, token = await _seeded(app_client, mock_db)
    lists = [kv.sign_vouchers(USER_ID, sk, entries) for entries in ([], [_entry(mock_db)], [_old_object(mock_db, sk)])]

    monkeypatch.setattr(server_kv, "MAX_LISTS_PER_KEY", 2, raising=False)
    assert [(await _post(app_client, token, vl)).status_code for vl in lists[:2]] == [200, 200]
    resp = await _post(app_client, token, lists[2])
    assert resp.status_code == 413, resp.text
    assert resp.json()["code"] == "key_vouchers_full"
    # A list already kept is not one more.
    assert (await _post(app_client, token, lists[0])).status_code == 200

    mock_db._storage["key_vouchers"] = []
    monkeypatch.setattr(server_kv, "MAX_LISTS_PER_KEY", 64, raising=False)
    sizes = [len(json.dumps(kv.canonical_entries(vl["entries"]), separators=(",", ":"))) for vl in lists[1:]]
    monkeypatch.setattr(server_kv, "MAX_BYTES_PER_KEY", sum(sizes) - 1, raising=False)
    assert (await _post(app_client, token, lists[1])).status_code == 200
    resp = await _post(app_client, token, lists[2])
    assert resp.status_code == 413 and resp.json()["code"] == "key_vouchers_full", resp.text
    assert len(mock_db._storage["key_vouchers"]) == 1


@pytest.mark.asyncio
async def test_the_lists_are_served_in_pages(app_client, mock_db, monkeypatch):  # noqa: F811
    sk, token = await _seeded(app_client, mock_db)
    lists = [kv.sign_vouchers(USER_ID, sk, entries) for entries in ([], [_entry(mock_db)], [_old_object(mock_db, sk)])]
    for vl in lists:
        assert (await _post(app_client, token, vl)).status_code == 200
    monkeypatch.setattr(server_kv, "PAGE_BYTES", 1, raising=False)

    served, after = [], ""
    for _ in range(4):
        query = f"?after={after}" if after else ""
        resp = await app_client.get(f"/api/users/{USER_ID}/key-vouchers{query}", headers=_auth(token))
        assert resp.status_code == 200, resp.text
        page = resp.json()
        assert len(page["lists"]) == 1  # a page holds at least one list
        served += page["lists"]
        after = page["next"]
        if not after:
            break

    assert sorted(map(str, served)) == sorted(map(str, lists)) and after == ""


def _event_loop_probe(monkeypatch) -> list[str]:
    """Where core.list_valid runs ('loop' or 'thread'), and when the push takes its lock."""
    events: list[str] = []
    real = kv.list_valid

    def probe(*args):
        try:
            asyncio.get_running_loop()
            events.append("loop")
        except RuntimeError:
            events.append("thread")
        return real(*args)

    real_execute = MockCursor.execute

    async def execute(self, query, args=()):
        if "FROM commit_counter WHERE id = 1 FOR UPDATE" in query:
            events.append("lock")
        return await real_execute(self, query, args)

    monkeypatch.setattr(server_kv.core, "list_valid", probe)
    monkeypatch.setattr(MockCursor, "execute", execute)
    return events


@pytest.mark.asyncio
async def test_signatures_are_checked_off_the_event_loop_and_before_the_push_lock(
    app_client, mock_db, monkeypatch  # noqa: F811
):
    sk, token = await _seeded(app_client, mock_db)
    events = _event_loop_probe(monkeypatch)

    assert (await _post(app_client, token, kv.sign_vouchers(USER_ID, sk, [_entry(mock_db)]))).status_code == 200
    assert events == ["thread"]

    events.clear()
    new_sk = SigningKey.generate()
    after = kv.sign_vouchers(USER_ID, new_sk, [_old_object(mock_db, sk)])
    rotation = await _identity_rotation(app_client, mock_db, sk, new_sk, [after])
    resp = await app_client.post("/api/sync", json={
        "objects": [_dek(new_sk, 2, b"dek under new KEK")], "atomic_batch": True, "key_epoch": 1,
        "key_rotation": rotation,
    }, headers=_auth(token))
    assert resp.status_code == 200, resp.text
    assert "loop" not in events and events.index("thread") < events.index("lock"), events


# ── N11: the folder-move check ─────────────────────────────────────────────


def test_the_move_check_reads_the_push_cache_and_is_bounded():
    chain = {f"N{i:025d}": f"N{i + 1:025d}" for i in range(2000)}
    cache = {("node", node): ("OWNER", parent) for node, parent in chain.items()}
    cache[("node", "N" + "0" * 24 + "5")] = ("OWNER", None)  # a short chain ends at the root

    async def run():
        # cur=None: every row comes from the cache.
        short = await sync_router._is_below(None, "N" + "0" * 25, "X" * 26, cache)
        deep = await sync_router._is_below(None, f"N{10:025d}", "X" * 26, cache)
        return short, deep

    assert asyncio.run(run()) == (False, True)


@pytest.mark.asyncio
async def test_a_new_folder_is_not_walked(app_client, mock_db, monkeypatch):  # noqa: F811
    sk, token = await _seeded(app_client, mock_db)
    calls = []

    async def is_below(*args):
        calls.append(args[1:3])
        return False

    monkeypatch.setattr(sync_router, "_is_below", is_below)
    top, child = "01JTOP0000000000000000000A", "01JCHILD000000000000000000"
    for obj_id, parent in ((top, None), (child, top)):
        resp = await app_client.post("/api/sync", json={"objects": [_node(sk, obj_id, parent, 1)]}, headers=_auth(token))
        assert resp.status_code == 200 and resp.json()["accepted"], resp.text
    assert calls == []

    # Moving a stored folder is still checked.
    other = "01JOTHER000000000000000000"
    resp = await app_client.post("/api/sync", json={"objects": [_node(sk, other, None, 1)]}, headers=_auth(token))
    assert resp.status_code == 200, resp.text
    stored = next(o for o in mock_db._storage["vault_objects"] if o["id"] == child)
    moved = {**_node(sk, child, other, 2), "base_version": 1, "base_payload_hash": stored["payload_hash"]}
    resp = await app_client.post("/api/sync", json={"objects": [moved]}, headers=_auth(token))
    assert resp.status_code == 200 and resp.json()["accepted"], resp.text
    assert calls == [(other, child)]


def _node(sk, obj_id: str, parent: str | None, version: int) -> dict:
    payload = os.urandom(16)
    payload_hash = hashlib.sha256(payload).hexdigest()
    return {
        "id": obj_id, "object_type": "node", "parent_ref": parent, "version": version, "is_deleted": 0,
        "payload": base64.b64encode(payload).decode(), "payload_hash": payload_hash,
        "signature": _sign_sync_object(sk, obj_id, "node", parent, None, 0, version, payload_hash),
    }


# ── every client follows the pages ─────────────────────────────────────────


def _paged_with_a_decoy_first(db, monkeypatch):
    """One list per page, and a list that vouches for nothing (a bad
    signature) before each real one: a client reading only the first page
    misses what the rotation vouched for."""
    monkeypatch.setattr(server_kv, "PAGE_BYTES", 1, raising=False)
    rows = db._storage["key_vouchers"]
    assert rows
    for index, row in enumerate(list(rows)):
        rows.append({**row, "id": f"{index:026d}", "signature": bytes(64)})


def test_a_member_desktop_reads_every_page(team, monkeypatch, tmp_path):  # noqa: F811
    url, db, *_ = _rotated_team(team, monkeypatch)
    _paged_with_a_decoy_first(db, monkeypatch)
    old_key_signed = [
        o["id"] for o in db._storage["vault_objects"]
        if o["object_type"] == "entry" and o["parent_ref"] == team[5]["Ops"]
    ]
    bob, client = _bob_desktop(tmp_path, url)
    try:
        client.pull()
        assert old_key_signed and all(
            bob.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (entry_id,)) for entry_id in old_key_signed
        )
    finally:
        bob.lock()


def test_a_member_web_session_reads_every_page(team, monkeypatch):  # noqa: F811
    url, db, *_ = _rotated_team(team, monkeypatch)
    _paged_with_a_decoy_first(db, monkeypatch)
    member = _web_login(url, "bob", PASSWORD, {})
    assert member["error"] is None, member
    assert _readable_passwords(member) == {"vpn": "ops-pw"}
