"""Review 4acfdde R11 #4 and #5.

#4: a readmit (member.remove + member.add in one append) reached the server
half: with the member.add refused, only it was set aside and the removal went
out on its own. The member was removed, lost write_acl and share links, and a
second readmit said they were 'not another active member'. Even a readmit that
landed deleted the member's share links for good.

#5: 'sezam team-log hand-over' gave the admin role to an account the server
has no users row for, or to one waiting for a readmit (it signs in with keys
the log does not name); no device of it could sign and the team froze.
"""

from __future__ import annotations

import time

import pytest

from server.app import team_log as server_team_log
from server.app.errors import TEAM_LOG_REFUSED, ApiError
from sezam.vault import team_migration
from tests.test_integration_client_server import _client
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review10_readmit import _confirming, _fingerprint, _lost_rotated_device
from tests.test_review9_team_identity import _rotate
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401


def _share_of(db, user_id: str) -> str:
    now = int(time.time() * 1000)
    share_id = f"share-{user_id[-6:]}"
    db._storage["shared_links"].append({
        "id": share_id, "encrypted_blob": b"blob", "created_by": user_id, "created_at": now,
        "expires_at": now + 3_600_000, "max_views": 1, "view_count": 0, "pin_hash": None,
        "pin_attempts": 0, "is_locked": 0, "notify_on_view": 0,
    })
    return share_id


def _status(db, user_id: str):
    return next(u["status"] for u in db._storage["users"] if u["id"] == user_id)


def _awaiting_readmit(team, url, tmp_path):  # noqa: F811
    """Bob's account rotated to fresh keys K3 the log never saw (R10-F)."""
    _db, _admin, _, bob, _ = team
    bob_id = bob.db.get_meta("user_id")
    admin_client, laptop, ops, item, own = _lost_rotated_device(team, url, tmp_path)
    admin_client.allow_key_reset(bob_id)
    laptop_client = _client(laptop, url)
    laptop_client.pull()
    _rotate(laptop, laptop_client, url).push()
    _confirming(lambda: admin_client.full_resync(confirmed=True), admin_client)
    return admin_client, laptop, ops, bob_id


def test_a_refused_readmit_changes_nothing_and_can_run_again(team, server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    _, admin, _, _, _ = team
    admin_client, laptop, ops, bob_id = _awaiting_readmit(team, url, tmp_path)
    share = _share_of(db, bob_id)
    acl = [r for r in db._storage["write_acl"] if r["user_id"] == bob_id]
    assert acl

    check = server_team_log._check_against_users

    async def refuse_the_add(cur, body, pending_identity, step):
        if body["type"] == "member.add":
            raise ApiError(400, TEAM_LOG_REFUSED, {"message": "refused here", "seq": body["seq"]})
        await check(cur, body, pending_identity, step)

    monkeypatch.setattr(server_team_log, "_check_against_users", refuse_the_add)
    fresh = _fingerprint(laptop)
    with pytest.raises(RuntimeError, match="nothing changed") as refused:
        team_migration.readmit_member(admin, admin_client, bob_id, confirm_fingerprint=lambda fp: fp == fresh)
    assert f"sezam team-log readmit {bob_id}" in str(refused.value)

    assert admin_client.team_state().members[bob_id].active
    assert _status(db, bob_id) == "active"
    assert [r for r in db._storage["write_acl"] if r["user_id"] == bob_id] == acl
    assert share in [s["id"] for s in db._storage["shared_links"]]
    assert admin_client.pending_team_changes() == []
    assert admin_client.set_aside_team_changes() == []

    monkeypatch.setattr(server_team_log, "_check_against_users", check)
    team_migration.readmit_member(admin, admin_client, bob_id, confirm_fingerprint=lambda fp: fp == fresh)
    state = admin_client.team_state()
    assert state.members[bob_id].signing_pk == bytes(laptop.keypair.signing_pk).hex()
    assert state.access[ops][bob_id] == "write"
    # A readmit is no removal for the member's share links.
    assert share in [s["id"] for s in db._storage["shared_links"]]


def test_a_removal_still_deletes_the_share_links(team, server):  # noqa: F811
    url, db = server
    _, admin, client, bob, _ = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    share = _share_of(db, bob_id)
    client.append_team_log([("member.remove", {"user_id": bob_id})])
    assert share not in [s["id"] for s in db._storage["shared_links"]]


def test_no_hand_over_to_an_account_waiting_for_a_readmit(team, server, tmp_path):  # noqa: F811
    url, db = server
    _, admin, _, _, _ = team
    admin_id = admin.db.get_meta("user_id")
    admin_client, _laptop, _ops, bob_id = _awaiting_readmit(team, url, tmp_path)
    head = admin_client.team_state().head_seq

    with pytest.raises(RuntimeError, match="readmit it first"):
        team_migration.hand_over_admin(admin, admin_client, bob_id, confirm_fingerprint=lambda fp: True)

    state = admin_client.team_state()
    assert state.head_seq == head
    assert state.members[admin_id].role == "admin" and state.members[bob_id].role == "member"
    assert admin_client.pending_team_changes() == []
    # Both halves wait together: the admin's own demotion never goes alone.
    aside = [item["change"][1]["user_id"] for item in admin_client.set_aside_team_changes()]
    assert sorted(aside) == sorted([bob_id, admin_id])
    admin_client.retry_set_aside_team_changes()  # 'sezam team-log retry': refused together again
    admin_client.flush_team_log()
    assert len(admin_client.set_aside_team_changes()) == 2
    assert admin_client.team_state().members[admin_id].role == "admin"


def test_no_hand_over_to_an_account_without_a_users_row(team, server):  # noqa: F811
    url, db = server
    _, admin, client, bob, _ = team
    admin_id = admin.db.get_meta("user_id")
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    db._storage["users"] = [u for u in db._storage["users"] if u["id"] != bob_id]

    with pytest.raises(RuntimeError, match="readmit it first"):
        team_migration.hand_over_admin(admin, client, bob_id, confirm_fingerprint=lambda fp: True)
    assert client.team_state().members[admin_id].role == "admin"
    assert next(u for u in db._storage["users"] if u["id"] == admin_id)["is_admin"]
