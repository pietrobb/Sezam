"""Idea #7: the desktop gives an approved member access to a shared folder.

An invited member could authenticate and pull, but nothing of the account
ever decrypted for them: the desktop created access envelopes only while
re-keying after a revocation. Here the admin's real desktop code shares one
folder with the member over the real server, and the member signs in with the
real web client (all of app.js in node): the shared record reads, the folder
that was not shared does not. A pending invitee, a key the server swapped in,
and keys that must stay private (personal folder, a subfolder borrowing its
parent's key) are refused before anything is sealed.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.vault.revocation import grant_member
from sezam.vault.sync_client import SyncClient, TofuKeyChangeError
from tests.test_cross_client_password_change import _web_login
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401


def _yes(fingerprint: str) -> bool:
    """The admin compared the fingerprint with the member's device."""
    return True


def _member_fingerprint(db, member_id: str) -> str:
    return next(u for u in db._storage["users"] if u["id"] == member_id)["key_fingerprint"]


def _envelopes(db, member_id: str) -> list[dict]:
    return [
        o for o in db._storage["vault_objects"]
        if o["object_type"] == "envelope" and o.get("target_user_id") == member_id
        and not o["is_deleted"]
    ]


def _readable_passwords(result: dict) -> dict:
    return {e["name"]: e["password"] for e in result["entries"] if not e["undecryptable"]}


@pytest.fixture
def team(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    admin = _vault(tmp_path / "admin", "admin")
    ops = admin.create_node("Ops")
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    hr = admin.create_node("HR")
    admin.create_entry(hr, "payroll", [{"key": "password", "value": "hr-pw", "sensitive": True}])
    cli._server_connect_flow(url, admin, PASSWORD)
    admin_client = _client(admin, url)
    invitation = admin_client.create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    bob.lock()
    yield url, db, admin, admin_client, bob_id, {"Ops": ops, "HR": hr}
    admin.lock()


def test_approved_member_reads_the_shared_folder_and_nothing_else(team):
    url, db, admin, admin_client, bob_id, folders = team

    # A pending invitee gets nothing.
    with pytest.raises(ValueError, match="approved member"):
        grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes)
    assert _envelopes(db, bob_id) == []
    assert _readable_passwords(_web_login(url, "admin", PASSWORD, {}))["vpn"] == "ops-pw"

    admin_client.approve_user(bob_id)
    before = _web_login(url, "bob", PASSWORD, {})
    assert before["error"] is None, before
    assert _readable_passwords(before) == {}

    envelope_id = grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes)
    ops_dek_id, _ = admin.dek_mgr.get_dek_for_node(folders["Ops"])
    [envelope] = _envelopes(db, bob_id)
    assert (envelope["id"], envelope["parent_ref"], envelope["access_level"]) == (
        envelope_id, ops_dek_id, "read"
    )
    # Granting the same access again is a no-op.
    assert grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes) == envelope_id
    assert len(_envelopes(db, bob_id)) == 1

    member = _web_login(url, "bob", PASSWORD, {})
    assert member["error"] is None, member
    assert _readable_passwords(member) == {"vpn": "ops-pw"}
    payroll = next(e for e in member["entries"] if e["id"] in {
        e2["id"] for e2 in _web_login(url, "admin", PASSWORD, {})["entries"]
        if e2["name"] == "payroll"
    })
    assert payroll["undecryptable"]

    audit = admin.db.fetchall("SELECT action FROM audit_log WHERE action = 'grant'")
    assert len(audit) == 1


def test_grant_refuses_private_keys_and_a_swapped_member_key(team):
    url, db, admin, admin_client, bob_id, folders = team
    admin_client.approve_user(bob_id)

    personal = admin.create_personal_folder("Mine")
    sub = admin.create_node("Shared-sub", parent_id=folders["Ops"], create_dek=False)
    for node_id, reason in ((personal, "personal"), (sub, "no key of its own")):
        with pytest.raises(ValueError, match=reason):
            grant_member(admin, admin_client, bob_id, node_id, confirm_fingerprint=_yes)
    with pytest.raises(ValueError, match="another member"):
        admin.grant_folder_access(
            folders["Ops"], admin.db.get_meta("user_id"), admin.keypair.encryption_pk
        )
    assert _envelopes(db, bob_id) == []

    grant_member(admin, admin_client, bob_id, folders["Ops"], "write", confirm_fingerprint=_yes)
    assert [e["access_level"] for e in _envelopes(db, bob_id)] == ["write"]
    with pytest.raises(ValueError, match="already has write access"):
        grant_member(admin, admin_client, bob_id, folders["Ops"], "read", confirm_fingerprint=_yes)

    # The server swaps the member's encryption key: the pinned key wins and
    # no DEK is sealed for the new one.
    user = next(u for u in db._storage["users"] if u["id"] == bob_id)
    user["encryption_pk"] = bytes(32).hex() if isinstance(user["encryption_pk"], str) else bytes(32)
    fresh = SyncClient(admin.db, url, admin.keypair, admin.db.get_meta("user_id"))
    fresh.set_dek_manager(admin.dek_mgr)
    with pytest.raises(TofuKeyChangeError):
        grant_member(admin, fresh, bob_id, folders["HR"], confirm_fingerprint=_yes)
    assert admin.db.fetchall(
        "SELECT 1 FROM access_envelopes WHERE user_id = ? AND dek_id = ?",
        (bob_id, admin.dek_mgr.get_dek_for_node(folders["HR"])[0]),
    ) == []
    assert len(_envelopes(db, bob_id)) == 1


def test_cli_grant_access_survives_an_offline_push(team, monkeypatch):
    url, db, admin, admin_client, bob_id, folders = team
    admin_client.approve_user(bob_id)
    monkeypatch.setattr(cli, "_open_vault", lambda: admin)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda vault, *a, **k: PASSWORD)
    monkeypatch.setattr(admin, "lock", lambda: None)
    real_push = SyncClient.push

    def offline_push(self):
        raise RuntimeError("Network error: connection refused")

    monkeypatch.setattr(SyncClient, "push", offline_push)
    result = CliRunner().invoke(
        cli.main,
        ["grant-access", bob_id, "HR", "--write", "--fingerprint", _member_fingerprint(db, bob_id)],
    )
    assert result.exit_code != 0
    assert "next push" in result.output
    assert _envelopes(db, bob_id) == []

    monkeypatch.setattr(SyncClient, "push", real_push)
    _client(admin, url).push()
    [envelope] = _envelopes(db, bob_id)
    assert envelope["access_level"] == "write"
    assert envelope["parent_ref"] == admin.dek_mgr.get_dek_for_node(folders["HR"])[0]

    result = CliRunner().invoke(cli.main, ["grant-access", bob_id, "Nope"])
    assert result.exit_code != 0 and "not found" in result.output


def test_team_dialog_shares_a_folder_with_the_selected_member(team, monkeypatch):
    pytest.importorskip("PySide6")
    import sys

    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QInputDialog, QMessageBox

    from sezam.gui import team_dialog

    url, db, admin, admin_client, bob_id, folders = team
    admin_client.approve_user(bob_id)
    _app = QApplication.instance() or QApplication(sys.argv)

    def run_now(owner, fn, on_success, on_error=None):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001 - the dialog's error path
            if on_error:
                on_error(exc)
            return
        on_success(result)

    shown = []
    monkeypatch.setattr(team_dialog, "run_in_background", run_now)
    monkeypatch.setattr(QMessageBox, "information", lambda *a: shown.append(("info", a[2])))
    monkeypatch.setattr(QMessageBox, "critical", lambda *a: shown.append(("error", a[2])))

    def confirm_key(_parent, title, text, *_args):
        shown.append(("ask", title))
        assert _member_fingerprint(db, bob_id) in text
        return QMessageBox.Yes

    monkeypatch.setattr(QMessageBox, "question", confirm_key)
    answers = iter(["Ops", "read"])

    def pick(_parent, _title, _label, items, *_args):
        wanted = next(answers)
        return next(i for i in items if i.startswith(wanted)), True

    monkeypatch.setattr(QInputDialog, "getItem", pick)

    dialog = team_dialog.TeamDialog(admin)
    table = dialog._users_table
    row = next(
        r for r in range(table.rowCount()) if table.item(r, 0).data(Qt.UserRole) == bob_id
    )
    table.setCurrentCell(row, 0)
    dialog._grant_folder()

    assert shown == [
        ("ask", "Confirm Member Key"), ("info", "'bob' now has read access to 'Ops'."),
    ], shown
    [envelope] = _envelopes(db, bob_id)
    assert envelope["parent_ref"] == admin.dek_mgr.get_dek_for_node(folders["Ops"])[0]
    dialog.deleteLater()


def test_first_grant_needs_the_member_fingerprint_confirmed(team, monkeypatch):
    """Review 688edcb, low: the first grant sealed the folder key for whatever
    key the server named, with no fingerprint shown or compared."""
    url, db, admin, admin_client, bob_id, folders = team
    admin_client.approve_user(bob_id)
    bob_fp = _member_fingerprint(db, bob_id)

    asked = []
    for answer in (None, lambda fp: asked.append(fp) or False):
        # (MemberKeyUnconfirmed, a RuntimeError naming the fingerprint)
        with pytest.raises(RuntimeError, match=bob_fp):
            grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=answer)
    assert asked == [bob_fp]
    assert _envelopes(db, bob_id) == []
    assert admin.db.fetchall("SELECT 1 FROM access_envelopes WHERE user_id = ?", (bob_id,)) == []

    # The CLI refuses a fingerprint that is not the member's, and seals nothing.
    monkeypatch.setattr(cli, "_open_vault", lambda: admin)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda vault, *a, **k: PASSWORD)
    monkeypatch.setattr(admin, "lock", lambda: None)
    runner = CliRunner()
    wrong = runner.invoke(cli.main, ["grant-access", bob_id, "Ops", "--fingerprint", "ab" * 32])
    assert wrong.exit_code != 0 and bob_fp in wrong.output, wrong.output
    declined = runner.invoke(cli.main, ["grant-access", bob_id, "Ops"], input="n\n")
    assert declined.exit_code != 0 and bob_fp in declined.output, declined.output
    assert _envelopes(db, bob_id) == []

    # Confirmed once (typed with separators), later grants are not asked again.
    spaced = " ".join(bob_fp[i:i + 4] for i in range(0, 64, 4)).upper()
    ok = runner.invoke(cli.main, ["grant-access", bob_id, "Ops", "--fingerprint", spaced])
    assert ok.exit_code == 0, ok.output
    grant_member(admin, admin_client, bob_id, folders["HR"])
    assert len(_envelopes(db, bob_id)) == 2

    # `sezam fingerprint` shows what the member reads out.
    assert runner.invoke(cli.main, ["fingerprint"]).output.strip() == admin.keypair.fingerprint
