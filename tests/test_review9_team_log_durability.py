"""Review 1141a20 H4 + durability of team changes (R9-D, goal #360).

Real desktop clients against the real server:
- a grant whose envelope the server refuses leaves no ``access.set`` in the
  log (it would make the member a recipient of every later key), and its
  lost reply or a restart neither loses nor doubles it;
- a removal re-key built before the log moved (another device of the admin
  changed a folder's access) seals the new key to the log's recipients at the
  head it lands on, not to those it was built for.
"""

from __future__ import annotations

import pytest

from sezam import teamlog
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401  (fixture)
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _carol, _member, _ops, _server_head


def _refuse_envelopes_to(client, monkeypatch, user_id):
    """The server refuses every envelope for ``user_id`` (it fails its signature)."""
    real = client._request

    def tamper(method, path, body=None, *args, **kwargs):
        if method == "POST" and path == "/api/sync" and body:
            for obj in body.get("objects") or []:
                if obj.get("object_type") == "envelope" and obj.get("target_user_id") == user_id:
                    obj["access_level"] = "write" if obj["access_level"] == "read" else "read"
                    obj["signature"] = "00" * 64
        return real(method, path, body, *args, **kwargs)

    monkeypatch.setattr(client, "_request", tamper)
    return real


def test_a_refused_grant_leaves_no_access_in_the_log(team, monkeypatch):  # noqa: F811
    db, admin, client, bob, _ = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    ops = _ops(admin)
    head = _server_head(db)
    real = _refuse_envelopes_to(client, monkeypatch, bob_id)

    with pytest.raises(RuntimeError, match="refused the access envelope"):
        revocation.grant_member(admin, client, bob_id, ops, "read")

    assert _server_head(db) == head  # neither folder.key nor access.set landed
    state = client.team_state()
    assert bob_id not in state.access.get(ops, {})
    assert not client.pending_team_changes()
    assert _bob_envelopes_live(db, bob_id) == []
    monkeypatch.setattr(client, "_request", real)
    client.push()
    assert _server_head(db) == head
    assert _bob_envelopes_live(db, bob_id) == []
    # Granted again, it lands whole.
    revocation.grant_member(admin, client, bob_id, ops, "read")
    assert client.team_state().access[ops] == {bob_id: "read"}
    assert len(_bob_envelopes_live(db, bob_id)) == 1


@pytest.mark.parametrize("restart", [False, True])
def test_a_grant_whose_reply_is_lost_lands_once(team, server, monkeypatch, restart):  # noqa: F811
    url, _ = server
    db, admin, client, bob, _ = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    ops = _ops(admin)
    head = _server_head(db)
    real = client._request

    def lose_reply(method, path, *args, **kwargs):
        result = real(method, path, *args, **kwargs)
        if method == "POST" and path in ("/api/sync", "/api/team-log"):
            raise RuntimeError("Network error: connection reset")
        return result

    monkeypatch.setattr(client, "_request", lose_reply)
    with pytest.raises(RuntimeError, match="not sent"):
        revocation.grant_member(admin, client, bob_id, ops, "read")
    monkeypatch.setattr(client, "_request", real)
    if restart:
        client = _client(admin, url)

    client.push()
    state = client.team_state()
    assert state.access[ops] == {bob_id: "read"}
    assert _server_head(db) == state.head_seq == head + 2  # folder.key + access.set, once
    assert not client.pending_team_changes()
    assert len(_bob_envelopes_live(db, bob_id)) == 1


def _post_elsewhere(client, real, changes) -> None:
    """Another device of the admin appends ``changes`` (this device does not see them)."""
    state = client.team_state()
    records = []
    signing_key = client._keypair.to_nacl_signing_key()
    for kind, data in changes:
        record = teamlog.sign_record(teamlog.next_body(state, kind, client._user_id, data), signing_key)
        state = teamlog.apply_record(state, record)
        records.append(record)
    real("POST", "/api/team-log", {"records": records}, auth=True)


@pytest.mark.parametrize("change", ["access_dropped", "access_added"])
def test_a_removal_rekey_seals_to_the_recipients_of_the_head_it_lands_on(
    team, server, tmp_path, monkeypatch, change  # noqa: F811
):
    url, _ = server
    db, admin, client, bob, _ = team
    bob_id = bob.db.get_meta("user_id")
    carol = _carol(url, client, tmp_path, monkeypatch)
    carol_id = carol.db.get_meta("user_id")
    _found_with_bob(client, bob)
    client.append_team_log([("member.add", _member(carol))])
    ops = _ops(admin)
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    assert client.push()["conflicts"] == []
    revocation.grant_member(admin, client, bob_id, ops, "write")
    if change == "access_dropped":
        revocation.grant_member(admin, client, carol_id, ops, "read")
    real = client._request

    def sync_offline(method, path, *args, **kwargs):
        if path.startswith("/api/sync"):
            raise RuntimeError("Network error: connection refused")
        return real(method, path, *args, **kwargs)

    monkeypatch.setattr(client, "_request", sync_offline)
    with pytest.raises(revocation.RekeyPending):
        revocation.revoke_member(admin, client, bob_id)
    monkeypatch.setattr(client, "_request", real)
    level = None if change == "access_dropped" else "read"
    _post_elsewhere(client, real, [("access.set", {"folder": ops, "user_id": carol_id, "level": level})])

    revocation.push_with_queued_revocations(admin, client)

    state = client.team_state()
    assert not revocation.queued_revocations(admin)
    new_key = teamlog.current_key(state, ops)
    assert len(state.folders[ops]) == 2 and not teamlog.is_stale(state, ops)
    assert new_key == admin.dek_mgr.get_dek_for_node(ops)[0]
    assert _bob_envelopes_live(db, bob_id) == []
    carol_new = [o for o in _bob_envelopes_live(db, carol_id) if o["parent_ref"] == new_key]
    if change == "access_dropped":
        assert carol_new == []
    else:
        assert [o["access_level"] for o in carol_new] == ["read"]
    carol.lock()


def test_a_refused_removal_survives_a_restart_and_blocks_the_member_meanwhile(
    team, server, monkeypatch  # noqa: F811
):
    from sezam.vault.sync_common import ServerError

    url, _ = server
    db, admin, client, bob, _ = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    ops = _ops(admin)
    revocation.grant_member(admin, client, bob_id, ops, "read")
    real = client._request

    def refuse(method, path, *args, **kwargs):
        if method == "POST" and path in ("/api/team-log", "/api/sync"):
            raise ServerError(400, '{"code":"team_log_refused","detail":"refused"}')
        return real(method, path, *args, **kwargs)

    monkeypatch.setattr(client, "_request", refuse)
    with pytest.raises(revocation.RekeyPending, match="NOT confirmed"):
        revocation.revoke_member(admin, client, bob_id)
    monkeypatch.setattr(client, "_request", real)
    client = _client(admin, url)  # restart
    assert client.pending_team_changes() == [["member.remove", {"user_id": bob_id}]]
    # Meanwhile nothing more is given to Bob from this device (S3 3.5: refused
    # on the projected state, before anything is sealed).
    with pytest.raises(ValueError, match="queued for removal"):
        revocation.grant_member(admin, client, bob_id, ops, "write")
    assert not client.pending_team_grants()
    assert len(_bob_envelopes_live(db, bob_id)) == 1  # the old grant, still to be withdrawn

    revocation.push_with_queued_revocations(admin, client)
    state = client.team_state()
    assert not state.members[bob_id].active and len(state.folders[ops]) == 2
    assert not client.pending_team_changes() and not revocation.queued_revocations(admin)
    assert _bob_envelopes_live(db, bob_id) == []


WEB_SETUP = """
const calls = [];
let journal = { revoked_user_id: 'BOB', phase: 'prepared', objects: [obj('NEW', 10)],
                team_log: [{ body: 'remove-bob', sig: 'S' }] };
globalThis.state.userId = 'ME';
globalThis.pendingWebRevocations = async () => (journal ? ['BOB'] : []);
globalThis.loadWebRekeyJournal = async () => (journal ? JSON.parse(JSON.stringify(journal)) : null);
globalThis.saveWebRekeyJournal = async (value) => { journal = JSON.parse(JSON.stringify(value)); };
globalThis.clearWebRekeyJournal = async () => { calls.push('clear'); journal = null; };
globalThis.pullAndBuildTree = async () => {};
globalThis.resealUnderFolderSuccessor = async (o) => o;
globalThis.buildWebRekeyBatch = async () => ({ objects: [obj('NEW', 10)], folders_rekeyed: 1,
                                              team_log: [{ body: 'remove-bob', sig: 'S' }] });
globalThis.apiFetch = async (path, opts) => {
    if (opts.method === 'DELETE') { calls.push('DELETE ' + path); return {}; }
    if (opts.body.team_log) {
        calls.push('refused');
        const err = new Error('team log refused'); err.status = 400; throw err;
    }
    calls.push('sync ' + opts.body.objects.map(o => o.id).join(','));
    return { accepted: opts.body.objects.map(o => ({ id: o.id })), conflicts: [] };
};
"""


def test_web_keeps_a_refused_removal_and_the_rest_of_a_retry_goes_on():
    from tests.test_web_push_limits import STUBS, _run
    from tests.test_web_rekey_journal_too_large_r5s3 import FUNCTIONS

    result = _run(FUNCTIONS, STUBS + WEB_SETUP + """
        const first = await attempt(() => finishWebRevocation('BOB', {}));
        state.outbox = { U1: { ...obj('U1', 10), version: 2 } };
        const retry = await attempt(() => retryAllWebDirtyObjects());
        return { first, retry, calls, journal: journal && journal.revoked_user_id,
                 left: Object.keys(state.outbox) };
    """)
    assert result["first"] == "team log refused"
    assert "clear" not in result["calls"] and not any(c.startswith("DELETE") for c in result["calls"])
    assert result["journal"] == "BOB"  # kept: no other revocation starts, Bob is not "removed"
    assert result["calls"][-1] == "sync U1"
    assert result["left"] == []
