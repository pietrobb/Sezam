"""Desktop copy of the team log (TL4a; docs/DESIGN_TEAM_LOG.md §6-7).

Real desktop clients against the real server: the admin founds the log, a
member follows it on pull (also when only the log moved), and a server that
rolls the log back, forks it or drops it is refused, not followed.
"""

from __future__ import annotations

import pytest

from sezam.crypto.keys import compute_fingerprint
from sezam.models import new_ulid
from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META
from sezam.vault.team_log_local import TeamLogMismatch
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)


@pytest.fixture
def team(server, tmp_path, monkeypatch):  # noqa: F811
    from sezam import cli

    url, db = server
    admin = _vault(tmp_path / "admin", "admin")
    admin.create_node("Ops")
    cli._server_connect_flow(url, admin, PASSWORD)
    admin_client = _client(admin, url)
    invitation = admin_client.create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    bob_client = _client(bob, url)
    yield db, admin, admin_client, bob, bob_client
    admin.lock()
    bob.lock()


def _found_with_bob(admin_client, bob) -> None:
    admin_client.found_team_log(new_ulid())
    admin_client.append_team_log([("member.add", {
        "user_id": bob.db.get_meta("user_id"),
        "signing_pk": bytes(bob.keypair.signing_pk).hex(),
        "encryption_pk": bytes(bob.keypair.encryption_pk).hex(),
        "role": "member",
    })])


def _confirm_founder(admin, member) -> None:
    member.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {
        admin.db.get_meta("user_id"): admin.keypair.fingerprint,
    })


def _forget_server_cache() -> None:
    from server.app import team_log

    team_log.forget_cache()


@pytest.mark.parametrize("with_log", [False, True])
def test_invitation_exports_only_locally_trusted_genesis(team, monkeypatch, with_log):
    _, admin, admin_client, bob, bob_client = team
    if with_log:
        _found_with_bob(admin_client, bob)
    original = admin_client._request

    def lying_response(method, path, *args, **kwargs):
        response = original(method, path, *args, **kwargs)
        if path == "/api/users/invite":
            response["genesis_hash"] = "f" * 64
        return response

    monkeypatch.setattr(admin_client, "_request", lying_response)
    invitation = admin_client.create_invitation()
    expected = admin_client.team_state().genesis_hash if with_log else None
    assert invitation.get("genesis_hash") == expected
    if with_log:
        bob_client._refresh_team_log()
        calls = []
        monkeypatch.setattr(bob_client, "_request", lambda *a, **k: calls.append(a))
        with pytest.raises(RuntimeError, match="founder.*not confirmed"):
            bob_client.create_invitation()
        assert calls == []


@pytest.mark.parametrize("with_log", [False, True])
def test_provisioning_exports_only_locally_trusted_genesis(team, monkeypatch, with_log):
    _, admin, client, bob, bob_client = team
    if with_log:
        _found_with_bob(client, bob)
    original = client._request

    def lying_response(method, path, *args, **kwargs):
        response = original(method, path, *args, **kwargs)
        if path == "/api/auth/provisioning-token":
            response["genesis_hash"] = "f" * 64
        return response

    monkeypatch.setattr(client, "_request", lying_response)
    issued = client.create_provisioning_token()
    expected = client.team_state().genesis_hash if with_log else None
    assert issued.get("genesis_hash") == expected
    if with_log:
        bob_client._refresh_team_log()
        calls = []
        monkeypatch.setattr(bob_client, "_request", lambda *a, **k: calls.append(a))
        with pytest.raises(RuntimeError, match="founder.*not confirmed"):
            bob_client.create_provisioning_token()
        assert calls == []
        _confirm_founder(admin, bob)
        bob.lock()
        bob.unlock(PASSWORD)
        assert _client(bob, bob.db.get_meta("server_url")).create_provisioning_token()["genesis_hash"] == expected


@pytest.mark.parametrize("with_log", [False, True])
def test_cli_provisioning_link_carries_trusted_anchor(team, monkeypatch, with_log):
    from click.testing import CliRunner
    from urllib.parse import parse_qs, urlsplit
    from sezam import cli

    _, admin, client, bob, _ = team
    if with_log:
        _found_with_bob(client, bob)
    expected = client.team_state().genesis_hash if with_log else None
    monkeypatch.setattr(cli, "_open_vault", lambda: admin)
    monkeypatch.setattr(cli, "_unlock_vault", lambda vault: None)
    result = CliRunner().invoke(cli.main, ["provision-device"])
    assert result.exit_code == 0, result.output
    link = next(line for line in result.output.splitlines() if line.startswith("sezam://"))
    parsed = urlsplit(link)
    assert parse_qs(parsed.fragment) == ({"g": [expected]} if with_log else {})
    assert "g" not in parse_qs(parsed.query)
    assert parse_qs(parsed.query)["username"] == ["admin"]
    admin.unlock(PASSWORD)


@pytest.mark.parametrize("as_link", [False, True])
def test_external_genesis_anchor_survives_restart_and_rejects_server_lies(team, monkeypatch, as_link):
    from click.testing import CliRunner
    from sezam import cli

    _, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    genesis = admin_client.team_state().genesis_hash
    argument = f"https://sync.invalid/?invite=abc#g={genesis}" if as_link else genesis
    monkeypatch.setattr(cli, "_open_vault", lambda: bob)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda vault: None)
    result = CliRunner().invoke(cli.main, ["team-log", "confirm-genesis", argument])
    assert result.exit_code == 0, result.output
    bob.unlock(PASSWORD)
    bob_client = _client(bob, bob.db.get_meta("server_url"))
    for head in (None, {"seq": 0, "hash": "f" * 64, "genesis_hash": "f" * 64}):
        with pytest.raises(TeamLogMismatch):
            bob_client._sync_team_log(head)
        assert bob_client.team_state() is None
    from tests.team_log_vectors import Log
    forged = Log().genesis()
    with monkeypatch.context() as patch:
        patch.setattr(bob_client, "_request", lambda *a, **k: {"records": forged.records})
        with pytest.raises(TeamLogMismatch):
            bob_client._sync_team_log({"seq": 0, "hash": forged.state.head_hash, "genesis_hash": genesis})
        assert bob_client.team_state() is None
    bob_client.pull()
    assert bob_client.team_log_trusted()
    assert bob_client.team_state().genesis_hash == genesis
    assert not bob.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META)
    from tests.test_review9_team_identity import _rotate
    admin_client = _rotate(admin, admin_client, admin.db.get_meta("server_url"))
    admin_client.push()
    bob_client._refresh_team_log()
    assert bob_client.team_log_trusted()
    assert admin_client.create_invitation()["genesis_hash"] == genesis
    assert admin_client.create_provisioning_token()["genesis_hash"] == genesis
    result = CliRunner().invoke(cli.main, ["team-log", "confirm-genesis", "f" * 64])
    assert result.exit_code != 0
    bob.unlock(PASSWORD)
    assert _client(bob, bob.db.get_meta("server_url")).team_log_trusted()


@pytest.mark.parametrize("operation", ["invite", "provision", "sign", "push", "create_node"])
def test_expected_but_not_downloaded_log_cannot_authorize_writes(team, operation):
    from sezam.vault.team_log_local import CONFIRMED_GENESIS_META

    _, admin, client, _, _ = team
    admin.db.set_meta(CONFIRMED_GENESIS_META, "a" * 64)
    before = admin.db.fetchall("SELECT id FROM nodes")
    # 662ebe2 pulls a pinned log before the write: the server serving no log
    # under the pin is then refused as a genesis mismatch (still fail-closed).
    with pytest.raises(RuntimeError, match="not confirmed|not downloaded|independently confirmed genesis"):
        if operation == "invite":
            client.create_invitation()
        elif operation == "provision":
            client.create_provisioning_token()
        elif operation == "sign":
            client.team_log_records([])
        elif operation == "push":
            client.push()
        else:
            admin.create_node("must not be created")
    assert admin.db.fetchall("SELECT id FROM nodes") == before


@pytest.mark.parametrize("anchor", ["", "a" * 63, "A" * 64, "g" * 64,
    "https://sync.invalid/?g=" + "a" * 64,
    "https://sync.invalid/#g=" + "a" * 64 + "&g=",
    "https://sync.invalid/#g=" + "a" * 64 + "&g=" + "b" * 64])
def test_malformed_genesis_anchor_never_opens_vault(monkeypatch, anchor):
    from click.testing import CliRunner
    from sezam import cli

    monkeypatch.setattr(cli, "_open_vault", lambda: pytest.fail("invalid anchor opened the vault"))
    result = CliRunner().invoke(cli.main, ["team-log", "confirm-genesis", anchor])
    assert result.exit_code == 2, result.output
    assert "Expected a 64-character" in result.output


@pytest.mark.parametrize("genesis", [None, "a" * 64])
def test_desktop_invitation_dialog_copies_anchor_fragment(monkeypatch, genesis):
    from unittest.mock import MagicMock

    # Review c78fd19 R13-12: PySide6 is the optional gui extra.
    QtWidgets = pytest.importorskip("PySide6.QtWidgets")
    from sezam.gui import team_dialog

    message = MagicMock()
    clipboard = MagicMock()
    monkeypatch.setattr(team_dialog, "QMessageBox", message)
    monkeypatch.setattr(QtWidgets, "QApplication", MagicMock(clipboard=lambda: clipboard))
    team_dialog.TeamDialog._show_invitation(None, "https://sync.invalid", {
        "invitation_token": "a&b", "expires_at": 1800000000000, "genesis_hash": genesis,
    })
    expected = "https://sync.invalid/?invite=a%26b" + (f"#g={genesis}" if genesis else "")
    clipboard.setText.assert_called_once_with(expected)
    message.return_value.setDetailedText.assert_called_once_with(expected)


def test_member_follows_the_log_and_trusts_it_once_the_founder_is_confirmed(team):
    db, admin, admin_client, bob, bob_client = team
    assert bob_client.pull() is not None
    assert bob_client.team_state() is None
    _found_with_bob(admin_client, bob)
    assert admin_client.team_log_trusted()  # founded it
    with pytest.raises(RuntimeError, match="founder.*not confirmed"):
        bob_client.pull()
    assert bob_client.team_state().to_json() == admin_client.team_state().to_json()
    assert not bob_client.team_log_trusted()
    admin_id = admin.db.get_meta("user_id")
    bob.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {
        admin_id: compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk),
    })
    assert bob_client.team_log_trusted()
    # An append alone (no object pushed) still reaches the member's pull.
    bob_client.pull()
    # The admin hands the role over (one admin per organisation for now, TL7).
    admin_client.append_team_log([
        ("member.role", {"user_id": bob.db.get_meta("user_id"), "role": "admin"}),
        ("member.role", {"user_id": admin_id, "role": "member"}),
    ])
    bob_client.pull()
    assert bob_client.team_state().head_seq == 3
    assert bob_client.team_state().members[bob.db.get_meta("user_id")].role == "admin"
    assert bob_client.team_state().members[admin_id].role == "member"


def test_a_log_rolled_back_by_the_server_is_never_followed_back(team):
    """R9-E: the device puts back what it accepted; it never goes back itself
    (a refused restore and a fork: tests/test_review9_team_log_restore.py)."""
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    bob_client._refresh_team_log()
    db._storage["team_log"] = [r for r in db._storage["team_log"] if r["seq"] == 0]
    _forget_server_cache()
    bob_client._refresh_team_log()
    assert bob_client.team_state().head_seq == 1
    assert max(r["seq"] for r in db._storage["team_log"]) == 1


def test_a_forked_log_is_refused(team):
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    bob_client._refresh_team_log()
    # The server swaps record 1 for another valid one the admin signed
    # (say, for a device that never sent it) and adds one more on top.
    admin.db.execute("DELETE FROM team_log WHERE seq = 1")
    admin_client._team_state_cache = None
    db._storage["team_log"] = [r for r in db._storage["team_log"] if r["seq"] == 0]
    _forget_server_cache()
    admin_client.append_team_log([("folder.key", {"folder": new_ulid(), "dek_id": new_ulid(), "prev_dek_id": None})])
    admin_client.append_team_log([("member.add", {
        "user_id": bob.db.get_meta("user_id"),
        "signing_pk": bytes(bob.keypair.signing_pk).hex(),
        "encryption_pk": bytes(bob.keypair.encryption_pk).hex(),
        "role": "member",
    })])
    with pytest.raises(TeamLogMismatch, match="does not replay"):
        bob_client.pull()
    assert bob_client.team_state().members[bob.db.get_meta("user_id")].role == "member"
    assert bob_client.team_state().head_seq == 1


def test_a_server_without_the_log_gets_it_back(team):
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    bob_client._refresh_team_log()
    held = bob_client.team_state()
    db._storage["team_log"] = []
    _forget_server_cache()
    bob_client._refresh_team_log()
    assert [r["hash"] for r in sorted(db._storage["team_log"], key=lambda r: r["seq"])] == [
        row["hash"] for row in bob.db.fetchall("SELECT hash FROM team_log ORDER BY seq")]
    assert bob_client.team_state().head_hash == held.head_hash


def test_records_this_device_would_refuse_are_never_sent(team):
    from sezam import teamlog

    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    before = len(db._storage["team_log"])
    with pytest.raises(teamlog.TeamLogError):
        admin_client.append_team_log([("member.remove", {"user_id": admin.db.get_meta("user_id")})])
    assert len(db._storage["team_log"]) == before
