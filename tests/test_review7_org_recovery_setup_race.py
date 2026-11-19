"""Review main@7c10379 (R7-H, desktop Z-table): org recovery set up while the
password changed in another process.

``setup_org_recovery`` checked for a stale KEK and then wrapped the KEK it had
for the recovery key, outside the cross-process lock 'sezam change-password'
holds. A password change in the gap (or one that read the recovery key before
the setup stored it) left ``org_recovery_wrapped_kek`` wrapping the old KEK,
marked current: the shares then restored a key that opens nothing.
"""

from __future__ import annotations

import threading

import pytest
from nacl.public import PrivateKey, SealedBox

import sezam.vault.crud as crud_mod
from sezam.crypto.shamir import reconstruct_secret
from sezam.vault.crud import Vault
from tests.test_ai_p3_session_limits import FAST_PARAMS

OLD = "org-race-old-password"
NEW = "org-race-new-password"


def _kek_of(path) -> bytes:
    for password in (NEW, OLD):
        probe = Vault(path)
        try:
            probe.unlock(password)
        except ValueError:
            continue
        try:
            return bytes(probe.current_kek)
        finally:
            probe.lock()
    raise AssertionError("neither password opens the vault")


@pytest.mark.parametrize("replace", [False, True])
def test_the_shares_open_the_kek_the_vault_has_after_a_racing_password_change(
    tmp_path, monkeypatch, replace
):
    Vault.create(tmp_path, OLD, FAST_PARAMS).lock()
    gui, cli = Vault(tmp_path), Vault(tmp_path)
    gui.unlock(OLD)
    cli.unlock(OLD)
    if replace:
        gui.setup_org_recovery(2, 3)
    real = crud_mod.org_recovery_signing_key
    main = threading.get_ident()
    other: list[threading.Thread] = []

    def in_the_gap(secret):
        if not other and threading.get_ident() == main:
            other.append(threading.Thread(target=cli.change_password, args=(OLD, NEW)))
            other[0].start()
            other[0].join(timeout=3)  # old code: the change commits right here
        return real(secret)

    monkeypatch.setattr(crud_mod, "org_recovery_signing_key", in_the_gap)
    try:
        shares = gui.setup_org_recovery(2, 3, replace=replace)
    finally:
        assert other, "the setup never reached the recovery key"
        other[0].join(timeout=150)
        monkeypatch.undo()
        gui.lock()
        cli.lock()

    secret = reconstruct_secret(shares[:2])
    fresh = Vault(tmp_path)
    fresh.db.open()
    try:
        wrapped = bytes.fromhex(fresh.db.get_meta("org_recovery_wrapped_kek"))
        stale = fresh.db.get_meta("org_recovery_stale")
    finally:
        fresh.db.close()
    restored = SealedBox(PrivateKey(bytes(secret))).decrypt(wrapped)
    assert stale == "1" or restored == _kek_of(tmp_path)  # old code: the old KEK, not stale
