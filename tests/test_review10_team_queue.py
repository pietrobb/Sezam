"""Review 8595ec1 #2: a queued team change the rules refuse blocked every push (R10-C, goal #373).

The outbox's queued ``team_change`` rows go out before each push. A change in it that the log
no longer takes (the log moved on: ``member_exists``) or that the server
refuses (``400 team_log_refused``) failed every push, had no way out and
'sezam status' did not show it. Now such a change is set aside with the
reason, pushes go on, status lists it, and 'sezam team-log retry' /
'sezam team-log discard' resolve it. A removal set aside still keeps the
member from every new key this device seals.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from sezam import cli
from sezam.vault import pending_states, revocation
from sezam.vault.sync_common import ServerError, queued_for_removal
from sezam.vault.team_log_local import _set_aside, _set_queued_changes
from tests.test_integration_client_server import PASSWORD, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_review9_team_log_durability import _post_elsewhere
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _carol, _member, _ops, _server_head


def _registered_not_approved(url, admin_client, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    invitation = admin_client.create_invitation()
    dave = _vault(tmp_path / "dave", "dave")
    cli._server_register_and_upload(
        url, dave, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    return dave


def _offline_team_log(client, monkeypatch):
    real = client._request

    def offline(method, path, *args, **kwargs):
        if method == "POST" and path == "/api/team-log":
            raise RuntimeError("Network error: connection refused")
        return real(method, path, *args, **kwargs)

    monkeypatch.setattr(client, "_request", offline)
    return real


def _entry_on_server(db, admin, entry_id) -> bool:
    return any(o["id"] == entry_id for o in db._storage["vault_objects"])


def _states(admin) -> dict:
    return {s.key: s for s in pending_states.pending_states(admin)}


def _plain(changes) -> list:
    """Queued changes without the local '_' annotations (never signed)."""
    return [[kind, {k: v for k, v in data.items() if not k.startswith("_")}] for kind, data in changes]


def _aside(client) -> list:
    return _plain(item["change"] for item in client.set_aside_team_changes())


def test_a_queued_change_the_log_moved_past_is_set_aside(team, server, tmp_path, monkeypatch):  # noqa: F811
    url, _ = server
    db, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    carol = _carol(url, client, tmp_path, monkeypatch)
    carol_id = carol.db.get_meta("user_id")
    # Queued offline with keys Carol has since replaced; meanwhile another
    # device of the admin added her with her current keys.
    stale = {**_member(carol), "signing_pk": bytes(SigningKey.generate().verify_key).hex(),
             "encryption_pk": bytes(PrivateKey.generate().public_key).hex()}
    real = _offline_team_log(client, monkeypatch)
    with pytest.raises(RuntimeError, match="Network error"):
        client.append_team_log([("member.add", stale)])
    monkeypatch.setattr(client, "_request", real)
    _post_elsewhere(client, real, [("member.add", _member(carol))])
    client.pull()
    head = _server_head(db)

    entry_id = admin.create_entry(_ops(admin), "vpn", [{"key": "password", "value": "pw"}])
    client.push()  # 8595ec1: TeamLogError member_exists, on every push

    assert _entry_on_server(db, admin, entry_id)
    assert client.pending_team_changes() == []
    assert _aside(client) == [["member.add", stale]]
    assert "member_exists" in client.set_aside_team_changes()[0]["reason"]
    assert _server_head(db) == head  # nothing of it reached the log
    assert client.team_state().members[carol_id].signing_pk == _member(carol)["signing_pk"]
    state = _states(admin)["team_changes_set_aside"]
    assert "member.add" in state.summary and carol_id in state.summary and "member_exists" in state.summary
    assert "team-log discard" in state.drop

    client.discard_set_aside_team_changes()
    assert client.set_aside_team_changes() == []
    assert "team_changes_set_aside" not in _states(admin)
    carol.lock()


def test_a_change_the_server_refuses_is_set_aside_and_lands_on_retry(
    team, server, tmp_path, monkeypatch  # noqa: F811
):
    url, _ = server
    db, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    dave = _registered_not_approved(url, client, tmp_path, monkeypatch)
    dave_id = dave.db.get_meta("user_id")
    real = _offline_team_log(client, monkeypatch)
    with pytest.raises(RuntimeError, match="Network error"):
        client.append_team_log([("member.add", _member(dave))])
    monkeypatch.setattr(client, "_request", real)
    assert "team_changes_queued" in _states(admin)  # 8595ec1: status showed nothing
    head = _server_head(db)

    entry_id = admin.create_entry(_ops(admin), "vpn", [{"key": "password", "value": "pw"}])
    client.push()  # 8595ec1: 400 team_log_refused (Dave is not approved), on every push

    assert _entry_on_server(db, admin, entry_id)
    assert _server_head(db) == head
    assert _aside(client) == [["member.add", _member(dave)]]
    assert "approved account" in client.set_aside_team_changes()[0]["reason"]
    assert "team_changes_queued" not in _states(admin)

    # Approved meanwhile: the retry puts it back in the queue and it lands.
    client.approve_user(dave_id)
    client.retry_set_aside_team_changes()
    assert client.set_aside_team_changes() == []
    client.push()
    assert client.team_state().members[dave_id].active
    assert client.pending_team_changes() == []
    dave.lock()


def test_a_refused_removal_set_aside_still_keeps_the_member_from_new_keys(team, monkeypatch):  # noqa: F811
    db, admin, client, bob, _ = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    ops = _ops(admin)
    revocation.grant_member(admin, client, bob_id, ops, "read")
    real = client._request

    def refuse_removal(method, path, body=None, *args, **kwargs):
        if method == "POST" and path == "/api/team-log":
            seq = json.loads(body["records"][0]["body"])["seq"]
            raise ServerError(400, json.dumps({"code": "team_log_refused", "detail": {
                "message": "refused here", "seq": seq}}))
        return real(method, path, body, *args, **kwargs)

    _set_queued_changes(client._db, [["member.remove", {"user_id": bob_id}]])
    monkeypatch.setattr(client, "_request", refuse_removal)
    entry_id = admin.create_entry(ops, "vpn", [{"key": "password", "value": "pw"}])
    client.push()  # the rest goes on

    monkeypatch.setattr(client, "_request", real)
    assert _entry_on_server(db, admin, entry_id)
    assert client.pending_team_changes() == []
    assert _aside(client) == [["member.remove", {"user_id": bob_id}]]
    assert bob_id in queued_for_removal(admin.db)  # no key this device seals goes to Bob
    state = _states(admin)["team_changes_set_aside"]
    assert "keeps" in state.summary and bob_id in state.summary
    assert len(_bob_envelopes_live(db, bob_id)) == 1  # the old grant, not withdrawn yet

    # The admin chooses: retried, the removal lands.
    client.retry_set_aside_team_changes()
    client.push()
    assert not client.team_state().members[bob_id].active
    assert client.set_aside_team_changes() == [] and client.pending_team_changes() == []


def test_cli_lists_retries_and_discards_set_aside_changes(team, monkeypatch):  # noqa: F811
    db, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    aside = [{"change": ["member.add", _member(bob)], "reason": "member_exists: team log record 2"}]
    _set_aside(client._db, aside)
    monkeypatch.setattr(cli, "_open_vault", lambda: admin)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda vault: None)
    monkeypatch.setattr(admin, "lock", lambda: None)
    runner = CliRunner()

    listed = runner.invoke(cli.main, ["team-log", "queue"])
    assert listed.exit_code == 0, listed.output
    assert "1. member.add" in listed.output and "member_exists" in listed.output

    kept = runner.invoke(cli.main, ["team-log", "discard", "--all"], input="n\n")
    assert kept.exit_code != 0 and client.set_aside_team_changes() == aside
    dropped = runner.invoke(cli.main, ["team-log", "discard", "1"], input="y\n")
    assert dropped.exit_code == 0, dropped.output
    assert client.set_aside_team_changes() == []

    _set_aside(client._db, aside)
    retried = runner.invoke(cli.main, ["team-log", "retry"])
    assert retried.exit_code == 0, retried.output
    assert client.set_aside_team_changes() == []
    assert client.pending_team_changes() == [["member.add", _member(bob)]]


def test_a_stale_queued_add_does_not_bring_back_a_member_removed_meanwhile(
    team, server, tmp_path, monkeypatch  # noqa: F811
):
    url, _ = server
    db, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    carol = _carol(url, client, tmp_path, monkeypatch)
    carol_id = carol.db.get_meta("user_id")
    real = _offline_team_log(client, monkeypatch)
    with pytest.raises(RuntimeError, match="Network error"):
        client.append_team_log([("member.add", _member(carol))])
    monkeypatch.setattr(client, "_request", real)
    # Another device of the admin added Carol and removed her again.
    _post_elsewhere(client, real, [("member.add", _member(carol)), ("member.remove", {"user_id": carol_id})])
    client.pull()

    client.push()

    assert not client.team_state().members[carol_id].active  # 8595ec1: active again
    assert _aside(client) == [["member.add", _member(carol)]]
    assert "removed_meanwhile" in client.set_aside_team_changes()[0]["reason"]
    # Re-adding her on purpose (the log already shows her removed) still works.
    client.append_team_log([("member.add", _member(carol))])
    assert client.team_state().members[carol_id].active
    carol.lock()


def _found_elsewhere(real, admin, changes) -> None:
    """Another device of the same admin founds the log (this one has none yet)."""
    from sezam import teamlog

    state = teamlog.TeamState()
    signing_key = admin.keypair.to_nacl_signing_key()
    records = []
    for kind, data in changes:
        record = teamlog.sign_record(teamlog.next_body(state, kind, admin.db.get_meta("user_id"), data), signing_key)
        state = teamlog.apply_record(state, record)
        records.append(record)
    real("POST", "/api/team-log", {"records": records}, auth=True)


def test_a_founding_that_lost_the_race_does_not_lower_access(team, monkeypatch):  # noqa: F811
    from sezam.models import new_ulid

    db, admin, client, bob, _ = team
    bob_id = bob.db.get_meta("user_id")
    ops = _ops(admin)
    dek = admin.dek_mgr.get_dek_for_node(ops)[0]
    admin_id = admin.db.get_meta("user_id")

    def founding(level):
        return [
            ("genesis", {"org": new_ulid(), "user_id": admin_id,
                         "signing_pk": bytes(admin.keypair.signing_pk).hex(),
                         "encryption_pk": bytes(admin.keypair.encryption_pk).hex()}),
            ("member.add", _member(bob)),
            ("folder.key", {"folder": ops, "dek_id": dek, "prev_dek_id": None, "gen": 0}),
            ("access.set", {"folder": ops, "user_id": bob_id, "level": level}),
        ]

    real = client._request
    raced = []

    def first_elsewhere(method, path, *args, **kwargs):
        if method == "POST" and path == "/api/team-log" and not raced:
            raced.append(1)
            _found_elsewhere(real, admin, founding("write"))
        return real(method, path, *args, **kwargs)

    monkeypatch.setattr(client, "_request", first_elsewhere)
    mine = founding("read")
    mine[2] = ("folder.key", {"folder": ops, "dek_id": dek, "prev_dek_id": None})
    with pytest.raises(RuntimeError, match="founded_elsewhere"):
        client.append_team_log(mine)

    assert client.team_state().access[ops] == {bob_id: "write"}  # 8595ec1: lowered to read
    assert [kind for kind, _ in _aside(client)] == ["genesis", "member.add", "folder.key", "access.set"]
    assert client.pending_team_changes() == []
    client.push()
    assert client.team_state().access[ops] == {bob_id: "write"}
