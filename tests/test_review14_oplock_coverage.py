"""Review 8bc70f7 #3 (H3): the member re-key lost the cross-process lock.

3975939 moved ``@oplock.held`` from ``rekey_after_revocation`` to the new
``rekey_after_handover``. Two removals at once (GUI and CLI) then wrote their
batches over each other; the folder stayed on a key the log does not know and
every push conflicted.

INV-6 (docs/ROOT_CAUSE_PLAN.md): the account-level state another process
reads and rewrites - a re-key batch, a key change journal, the revocation
queue, an org recovery body, the last key epoch the server took - is written
only under the vault lock. The first fix scanned the source for callers of a
hand-kept list of writer names; the list missed ``set_revocation_queue``, and
every removal (revoke_member, the queued re-keys of a push, 'sezam
abandon-rekey --queued') rewrote the queue unlocked. The rule is now checked
where that state is written (``oplock.require`` in outbox and pending_states):
any caller that forgets the lock fails on its first write, in every test that
runs it, with no list of callers to keep.
"""

from __future__ import annotations

import threading

import pytest

from sezam.vault import oplock, outbox, pending_states
from sezam.vault.crud import Vault
from tests.test_integration_client_server import server  # noqa: F401
from tests.test_rekey_rebase_review8 import _folder_shared_with_member
from tests.test_review6_vault_oplock import PASSWORD, _hold_in_another_process, vault  # noqa: F401

WRITES = {
    "rekey batch": lambda db: pending_states.set_rekey_batch(db, {"object_ids": ["x"]}),
    "rekey batch cleared": pending_states.clear_rekey_batch,
    "key change journal": lambda db: pending_states.set_key_change_journal(db, {"epoch": 2}),
    "key change journal cleared": pending_states.clear_key_change_journal,
    "revocation queue": lambda db: pending_states.set_revocation_queue(db, ["M"]),
    "org recovery registration": lambda db: pending_states.set_org_recovery_registration(db, {}),
    "org recovery rewrap": lambda db: pending_states.set_org_recovery_rewrap(db, {}),
    "last pushed key epoch": lambda db: pending_states.set_last_pushed_key_epoch(db, 3),
    **{
        f"outbox.{name}({kind})": (lambda name, kind: lambda db: getattr(outbox, name)(db, kind, "o"))(
            name, kind
        )
        for kind in sorted(outbox.LOCKED)
        for name in ("queue", "requeue", "refuse", "sent")
    },
}


def _state(db) -> tuple:
    return (
        [tuple(r) for r in db.fetchall("SELECT kind, object_id, body, state FROM outbox ORDER BY seq")],
        db.get_meta(pending_states.LAST_PUSHED_KEY_EPOCH),
    )


@pytest.mark.parametrize("what", sorted(WRITES))
def test_pending_state_is_written_only_under_the_lock(vault, what):  # noqa: F811
    before = _state(vault.db)
    with pytest.raises(oplock.Unlocked):
        WRITES[what](vault.db)
    assert _state(vault.db) == before
    with oplock.exclusive(vault.db.path):
        WRITES[what](vault.db)


def test_another_threads_hold_is_not_this_threads(vault):  # noqa: F811
    held, release = threading.Event(), threading.Event()

    def hold():
        with oplock.exclusive(vault.db.path):
            held.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    held.wait(5)
    try:
        with pytest.raises(oplock.Unlocked):
            pending_states.set_revocation_queue(vault.db, ["M"])
    finally:
        release.set()
        t.join(5)


def test_the_3975939_regression_fails_at_its_first_write(server, tmp_path, monkeypatch):  # noqa: F811
    """3975939 itself: the member re-key without its decorator."""
    url, db = server
    laptop, phone, folder, _entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    monkeypatch.setattr(Vault, "rekey_after_revocation", Vault.rekey_after_revocation.__wrapped__)
    try:
        with pytest.raises(oplock.Unlocked):
            laptop.rekey_after_revocation(member_id)
        assert pending_states.rekey_batch(laptop.db) == {}
        assert laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"] == old_dek
    finally:
        laptop.lock()
        phone.lock()


def test_a_member_rekey_waits_for_another_process(vault, monkeypatch):  # noqa: F811
    monkeypatch.setattr(oplock, "DEFAULT_TIMEOUT", 0.3)
    proc = _hold_in_another_process(vault.db.path, 3.0)
    try:
        with pytest.raises(oplock.VaultBusy):
            vault.rekey_after_revocation("01HZZZZZZZZZZZZZZZZZZZZZZZ")
        with pytest.raises(oplock.VaultBusy):
            vault.rekey_after_handover("01HZZZZZZZZZZZZZZZZZZZZZZZ")
    finally:
        proc.wait(10)
    assert vault.rekey_after_revocation("01HZZZZZZZZZZZZZZZZZZZZZZZ") == 0


def test_a_removal_waits_for_another_process(vault, monkeypatch):  # noqa: F811
    from sezam.vault import revocation

    monkeypatch.setattr(oplock, "DEFAULT_TIMEOUT", 0.3)
    proc = _hold_in_another_process(vault.db.path, 3.0)
    try:
        with pytest.raises(oplock.VaultBusy):
            revocation.revoke_member(vault, None, "01HZZZZZZZZZZZZZZZZZZZZZZZ")
    finally:
        proc.wait(10)
