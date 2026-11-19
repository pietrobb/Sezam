"""Review main@7c10379 (R7-H, desktop Z-table): a snapshot taken across a
password change in another process.

d0543be: after a password change no snapshot may open with the old password
(only the change's own, until the new password opens the vault). A folder
delete in the GUI copied the vault before the change committed and published
the copy after the change had swept the snapshot directory: the copy opened
with the old, perhaps leaked password and its keys decrypted today's data.
"""

from __future__ import annotations

import sqlite3
import threading

import sezam.vault.snapshots as snapshots_mod
from sezam.vault.crud import KEY_CHANGE_SNAPSHOT_META, Vault
from sezam.vault.snapshots import list_snapshots
from tests.test_ai_p3_session_limits import FAST_PARAMS

OLD = "snapshot-race-old-password"
NEW = "snapshot-race-new-password"


def _salt(path) -> str:
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        return conn.execute("SELECT value FROM vault_meta WHERE key = 'argon2_salt'").fetchone()[0]
    finally:
        conn.close()


def test_no_snapshot_of_the_old_password_outlives_a_racing_change(tmp_path, monkeypatch):
    Vault.create(tmp_path, OLD, FAST_PARAMS).lock()
    gui, cli = Vault(tmp_path), Vault(tmp_path)
    gui.unlock(OLD)
    cli.unlock(OLD)
    folder = gui.create_node("to delete")
    real_publish = snapshots_mod.publish
    main = threading.get_ident()
    other: list[threading.Thread] = []

    def publish_late(tmp, dest):
        if not other and threading.get_ident() == main:
            other.append(threading.Thread(target=cli.change_password, args=(OLD, NEW)))
            other[0].start()
            other[0].join(timeout=30)  # the change commits and sweeps the snapshots here
        return real_publish(tmp, dest)

    monkeypatch.setattr(snapshots_mod, "publish", publish_late)
    try:
        try:
            gui.delete_node(folder)
        except Exception:  # noqa: BLE001, S110 - refusing is fine; an old-password copy is not
            pass
    finally:
        assert other, "the delete took no snapshot"
        monkeypatch.undo()
        gui.lock()

    current = cli.db.get_meta("argon2_salt")
    spare = cli.db.get_meta(KEY_CHANGE_SNAPSHOT_META)
    cli.lock()
    old_password_copies = [
        info.name for info in list_snapshots(tmp_path)
        if info.name != spare and _salt(info.path) != current
    ]
    assert old_password_copies == []  # old code: the delete-folder snapshot
