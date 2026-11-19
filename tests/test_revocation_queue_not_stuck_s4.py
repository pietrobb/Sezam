"""Review 526419e S4: the queue of revoked members stuck on its first member.

An open sync conflict in the folders of the first queued member (bob) made
finish_queued_revocations raise at once, so the next member (carol), whose
folders had no conflict, was never re-keyed either. And only 'sezam push'
worked the queue: the desktop GUI had no way to finish it or settle the
conflicts it waited for.
"""

from __future__ import annotations

import sys
import time

import pytest
from click.testing import CliRunner

from sezam.vault import pending_states
from sezam import cli
from sezam.vault.revocation import finish_queued_revocations, queued_revocations
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    _client,
    server,
)
from tests.test_revoke_second_member_8b import _admin_with_two_members, _envelopes_live


def _queued_with_conflict_on_bob(url, db, tmp_path, monkeypatch):
    admin, bob_id, carol_id = _admin_with_two_members(url, db, tmp_path, monkeypatch)
    client = _client(admin, url)
    client.revoke_user(bob_id)
    client.revoke_user(carol_id)
    pending_states.set_revocation_queue(admin.db, [bob_id, carol_id])
    entry = admin.db.fetchone(  # in bob's folder (Ops)
        "SELECT e.id, e.version FROM entries e JOIN access_envelopes a ON a.dek_id = "
        "(SELECT dek_id FROM nodes WHERE id = e.node_id) WHERE a.user_id = ?", (bob_id,)
    )
    assert entry
    # The server's own copy, as a pull records it (the push checks the base
    # a kept local copy names against it).
    stored = next(o for o in db._storage["vault_objects"] if o["id"] == entry["id"])
    admin.db.execute(
        "INSERT INTO sync_conflicts (object_id, object_type, local_version, server_version, "
        "server_payload, server_parent_ref, server_is_deleted, server_payload_hash, detected_at) "
        "VALUES (?, 'entry', ?, ?, ?, ?, 0, ?, ?)",
        (entry["id"], entry["version"], stored["version"], bytes(stored["payload"]),
         stored["parent_ref"], stored["payload_hash"], int(time.time() * 1000)),
    )
    return admin, client, bob_id, carol_id, entry["id"]


def test_a_conflict_of_the_first_member_does_not_hold_up_the_next(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    admin, client, bob_id, carol_id, entry = _queued_with_conflict_on_bob(
        url, db, tmp_path, monkeypatch
    )
    with pytest.raises(RuntimeError, match="unresolved sync conflicts") as blocked:
        finish_queued_revocations(admin, client)
    assert getattr(blocked.value, "done", None) == {carol_id: 1}
    assert not _envelopes_live(db, carol_id)  # re-keyed despite bob's conflict
    assert _envelopes_live(db, bob_id)
    assert queued_revocations(admin) == [bob_id]


def test_cli_push_rekeys_the_free_member_and_names_the_waiting_one(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    admin, _client_, bob_id, carol_id, entry = _queued_with_conflict_on_bob(
        url, db, tmp_path, monkeypatch
    )
    result = CliRunner().invoke(cli.main, ["push"])
    assert result.exit_code == 0, result.output
    assert f"Re-keyed 1 folder(s) after revoking user {carol_id}" in result.output
    assert bob_id in result.output and entry in result.output
    assert queued_revocations(admin) == [bob_id]


def test_gui_finishes_the_queue_and_settles_the_conflict(server, tmp_path, monkeypatch):  # noqa: F811
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication, QMessageBox

    from sezam.gui import team_dialog

    url, db = server
    admin, _client_, bob_id, carol_id, entry = _queued_with_conflict_on_bob(
        url, db, tmp_path, monkeypatch
    )
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
    monkeypatch.setattr(QMessageBox, "warning", lambda *a: shown.append(("warn", a[2])))
    monkeypatch.setattr(QMessageBox, "exec", lambda self: shown.append(("ask", self.text())))
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda self: next(
        b for b in self.buttons() if self.buttonRole(b) == QMessageBox.AcceptRole
    ))

    dialog = team_dialog.TeamDialog(admin)
    dialog._finish_rekeys()

    assert any(kind == "ask" and entry in text for kind, text in shown)
    assert queued_revocations(admin) == []
    assert not _envelopes_live(db, bob_id)
    assert not _envelopes_live(db, carol_id)
    info = [text for kind, text in shown if kind == "info"]
    assert info and bob_id in info[-1] and carol_id in info[-1], shown
