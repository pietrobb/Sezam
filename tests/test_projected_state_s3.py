"""Sync S3, projected state (docs/SYNC_SINGLE_SOURCE.md 3.5).

Who gets a key, and under which key, is decided on the state after this
device's outbox lands, not on the server's copy alone. Before: the admin
removed Bob offline (member.remove queued) and then shared the folder with
Carol. The grant was sealed under the key that removal retires, reported as
"goes with the next push", and Carol never got the folder. A grant to Bob
himself was sealed too.
"""

from __future__ import annotations

import pytest

from sezam import teamlog
from sezam.vault import pending_states, revocation
from sezam.vault.team_log_local import projected_team_state
from tests.test_grant_under_rekeyed_key_sm62 import _invite_carol
from tests.test_integration_client_server import _client, server  # noqa: F401  (fixture)
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _carol, _member, _ops


def test_team_grant_waits_for_the_queued_removal_rekey(team, server, tmp_path, monkeypatch):  # noqa: F811
    url, _ = server
    db, admin, admin_client, bob, _ = team
    bob_id = bob.db.get_meta("user_id")
    carol = _carol(url, admin_client, tmp_path, monkeypatch)
    carol_id = carol.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    admin_client.append_team_log([("member.add", _member(carol))])
    ops = _ops(admin)
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    admin_client.push()
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    old_key = teamlog.current_key(admin_client.team_state(), ops)
    real = admin_client._request

    def offline(method, path, *a, **k):
        if path.startswith("/api/team-log") or path.startswith("/api/sync"):
            raise RuntimeError("Network error: connection refused")
        return real(method, path, *a, **k)

    monkeypatch.setattr(admin_client, "_request", offline)
    with pytest.raises(revocation.RekeyPending):
        revocation.revoke_member(admin, admin_client, bob_id)
    projected = projected_team_state(admin.db, admin.db.get_meta("user_id"))
    assert not projected.members[bob_id].active and teamlog.is_stale(projected, ops)
    assert admin_client.team_state().members[bob_id].active  # the server's log still has him

    with pytest.raises(RuntimeError, match="waits for the re-key"):
        revocation.grant_member(admin, admin_client, carol_id, ops, "read")
    with pytest.raises(ValueError, match="queued for removal"):
        revocation.grant_member(admin, admin_client, bob_id, ops, "write")
    assert not admin.db.fetchone(
        "SELECT 1 FROM access_envelopes WHERE user_id = ? AND dek_id = ?", (carol_id, old_key)
    )
    assert not admin_client.pending_team_grants()

    monkeypatch.setattr(admin_client, "_request", real)
    revocation.push_with_queued_revocations(admin, admin_client)
    revocation.grant_member(admin, admin_client, carol_id, ops, "read")
    new_key = teamlog.current_key(admin_client.team_state(), ops)
    assert new_key != old_key
    assert {o["parent_ref"] for o in _bob_envelopes_live(db, carol_id)} == {new_key}
    assert _bob_envelopes_live(db, bob_id) == []
    carol.lock()


def test_grant_to_a_member_queued_for_removal_seals_nothing(server, tmp_path, monkeypatch):  # noqa: F811
    """Without a team log: the removal's re-key waits; Bob gets no new key, Carol gets the new one."""
    url, db = server
    laptop, _phone = _two_devices(url, tmp_path)
    client = _client(laptop, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    client.push()
    bob_id = invite_bob(url, client, tmp_path, monkeypatch)
    carol_id = _invite_carol(url, client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, client, bob_id, folder, confirm_fingerprint=lambda _fp: True)

    undo = _fail_once(client, "POST", "/api/sync", "before")
    try:
        revocation.revoke_member(laptop, client, bob_id)
    except RuntimeError:
        pass
    finally:
        undo()
    assert pending_states.rekey_batch(laptop.db)
    # The server already refuses him here; the sealer does not rely on that.
    bob_pk = bytes(laptop.db.fetchone(
        "SELECT encryption_pk FROM known_keys WHERE user_id = ?", (bob_id,)
    )["encryption_pk"])
    with pytest.raises(ValueError, match="queued for removal"):
        laptop.grant_folder_access(folder, bob_id, bob_pk, "read")
    revocation.grant_member(laptop, client, carol_id, folder, confirm_fingerprint=lambda _fp: True)
    revocation.push_with_queued_revocations(laptop, client)

    current = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert current in {o["parent_ref"] for o in _bob_envelopes_live(db, carol_id)}
    assert _bob_envelopes_live(db, bob_id) == []
    laptop.lock()
    _phone.lock()


def test_rotated_member_gets_no_envelope_under_a_key_a_queued_removal_retires(team, server, tmp_path, monkeypatch):  # noqa: F811
    """A member rotated while the admin's removal of another member waits: the& echo     admin seals nothing under the key that removal retires; its re-key seals the& echo     new key to the rotated member's new key."""
    from sezam.vault.sync_rekey import ROTATION_SEALED_META
    from tests.test_review9_member_rotation_envelope import _bob_reads
    from tests.test_review9_team_identity import _rotate
    from tests.test_review9_team_log_restore import _pull_confirming
    from tests.test_team_log_desktop import _confirm_founder

    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    carol = _carol(url, admin_client, tmp_path, monkeypatch)
    carol_id = carol.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    admin_client.append_team_log([("member.add", _member(carol))])
    ops = _ops(admin)
    item = admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    revocation.grant_member(admin, admin_client, carol_id, ops, "read")
    _confirm_founder(admin, bob)
    bob_client.pull()
    _rotate(bob, bob_client, url).push()
    old_key = teamlog.current_key(admin_client.team_state(), ops)
    real = admin_client._request

    def offline(method, path, *a, **k):
        if method == "POST" and path.startswith("/api/team-log"):
            raise RuntimeError("Network error: connection refused")
        return real(method, path, *a, **k)

    monkeypatch.setattr(admin_client, "_request", offline)
    with pytest.raises(revocation.RekeyPending):
        revocation.revoke_member(admin, admin_client, carol_id)
    _pull_confirming(admin_client)
    sealed_here = admin.db.fetchall(
        "SELECT 1 FROM access_envelopes WHERE dek_id = ? AND user_id = ? AND created_by = ?",
        (old_key, bob_id, admin.db.get_meta("user_id")),
    )
    assert len(sealed_here) == 1  # only the grant from before the rotation
    assert int(admin.db.get_meta(ROTATION_SEALED_META) or -1) < admin_client.team_state().head_seq
    monkeypatch.setattr(admin_client, "_request", real)
    revocation.push_with_queued_revocations(admin, admin_client)
    _pull_confirming(admin_client)
    admin_client.push()
    assert teamlog.current_key(admin_client.team_state(), ops) != old_key
    _bob_reads(bob, url, item)
    assert all(o["parent_ref"] == old_key for o in _bob_envelopes_live(db, carol_id))
    carol.lock()
