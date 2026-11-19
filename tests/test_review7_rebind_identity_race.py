"""Review main@7c10379 (R7-H, desktop Z-table): binding the server's user id
while the password changed in another process.

``rebind_server_identity`` checked for a stale KEK, wrapped the keypair under
the KEK it had, and only then opened its transaction. 'sezam change-password'
committing in that gap had re-wrapped the keypair under the new KEK; the
rebind wrote the old-KEK wrap over it, bound to the old kek_dek_id, and from
then on neither password unlocked the vault.
"""

from __future__ import annotations

import threading

import sezam.crypto.aead as aead_mod
from sezam.models import new_ulid
from sezam.vault.crud import Vault
from tests.test_ai_p3_session_limits import FAST_PARAMS

OLD = "rebind-race-old-password"
NEW = "rebind-race-new-password"


def test_a_password_change_in_the_gap_leaves_a_vault_one_password_opens(tmp_path, monkeypatch):
    Vault.create(tmp_path, OLD, FAST_PARAMS).lock()
    gui, cli = Vault(tmp_path), Vault(tmp_path)
    gui.unlock(OLD)
    cli.unlock(OLD)
    real = aead_mod.encrypt_keypair_wrap
    main = threading.get_ident()
    other: list[threading.Thread] = []
    refused: list[Exception] = []  # refused while the rebind writes: also fine

    def change_password_elsewhere():
        try:
            cli.change_password(OLD, NEW)
        except Exception as exc:  # noqa: BLE001
            refused.append(exc)

    def in_the_gap(**kwargs):
        if not other and threading.get_ident() == main:
            other.append(threading.Thread(target=change_password_elsewhere))
            other[0].start()
            other[0].join(timeout=3)  # old code: the change commits right here
        return real(**kwargs)

    monkeypatch.setattr(aead_mod, "encrypt_keypair_wrap", in_the_gap)
    server_user_id = new_ulid()
    try:
        try:
            gui.rebind_server_identity(server_user_id)
        except Exception as exc:  # noqa: BLE001 - refusing is fine, a vault nobody opens is not
            refused.append(exc)
    finally:
        assert other, "the rebind never wrapped the keypair"
        other[0].join(timeout=30)
        monkeypatch.undo()
        gui.lock()
        cli.lock()

    opened = []
    for password in (NEW, OLD):
        probe = Vault(tmp_path)
        try:
            probe.unlock(password)  # old code: 'Wrong master password' for both
        except ValueError:
            continue
        opened.append(password)
        for row in probe.db.fetchall("SELECT id FROM deks"):
            probe.dek_mgr.unlock_dek(row["id"])
        probe.lock()
    assert len(opened) == 1, (opened, refused)
