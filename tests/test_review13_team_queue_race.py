"""Review c78fd19 high #3: a removal queued while the GUI pushed was lost.

The push emptied the whole team-change queue after it landed, and queueing
read and rewrote the queue without a lock or a transaction. 'sezam revoke
bob' during a GUI push: member.remove vanished, bob stayed in the log with
write access, and the CLI said he was removed.
"""

from __future__ import annotations

import threading
from pathlib import Path

from sezam.vault.crud import Vault
from tests.test_integration_client_server import PASSWORD, _client
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _carol, _member


def test_a_removal_queued_during_a_push_survives_it(team, server, tmp_path, monkeypatch):  # noqa: F811
    url, _ = server
    db, admin, gui, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    carol = _carol(url, gui, tmp_path, monkeypatch)
    _found_with_bob(gui, bob)
    gui.queue_team_changes([("member.add", _member(carol))])  # what the GUI pushes

    cli_vault = Vault(Path(admin.db.path).parent)  # the CLI: another program on the vault
    cli_vault.unlock(PASSWORD)
    cli = _client(cli_vault, url)
    revoked = threading.Thread(target=lambda: cli.queue_team_changes([("member.remove", {"user_id": bob_id})]))
    real = gui._request

    def sending(method, path, *a, **k):
        if method == "POST" and path in ("/api/team-log", "/api/sync") and not revoked.is_alive() \
                and revoked.ident is None:
            revoked.start()
            revoked.join(timeout=1.0)  # it runs now, unless the push holds the queue
        return real(method, path, *a, **k)

    monkeypatch.setattr(gui, "_request", sending)
    gui.push()
    revoked.join(timeout=30)
    assert not revoked.is_alive()

    assert ["member.remove", {"user_id": bob_id}] in gui.pending_team_changes()
    monkeypatch.setattr(gui, "_request", real)
    gui.flush_team_log()
    state = gui.team_state()
    assert state.members[carol.db.get_meta("user_id")].active
    assert not state.members[bob_id].active
    assert not gui.pending_team_changes()
    cli_vault.lock()
    carol.lock()
