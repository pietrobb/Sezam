"""Leaving a pinned team log on purpose (review c78fd19, medium).

A device pins the team log's genesis (first sight, an invitation's #g=, a
confirmed founder, the account bundle) and from then on follows no other log.
A server that lost the log for good (moved, reseeded, restored from before the
log and refusing its restore) left every device with TEAM LOG MISMATCH and no
way out on any client. Here the user, having typed the pinned genesis, drops
this device's pin and its copy of the old log; the device then treats the
server's log as a new one (trusted only once its founder is confirmed again).

Nothing is ever forgotten on its own: a mismatch stays a mismatch. The
account bundle on the server may still name the old genesis (other devices
are not asked); the device remembers that it left it and does not take it
back from there (``import_account_anchor``). Confirming that genesis again
('sezam team-log confirm-genesis') ends that.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import ulid_to_bytes
from . import outbox, pending_states
from .sync_rekey import ROTATION_SEALED_META
from .team_log_local import (
    ACCOUNT_ANCHOR_META, CONFIRMED_GENESIS_META, FORGOTTEN_GENESIS_META, GENESIS_META, held_genesis,
    readable_forgotten_genesis,
    queued_changes, set_aside_changes,
)

if TYPE_CHECKING:
    from .crud import Vault
    from .sync_client import SyncClient

MIN_CONFIRM_CHARS = 16


def pinned_genesis(vault: Vault) -> set[str]:
    """Every genesis this device holds on to: pins, its log copy, its keys."""
    db = vault.db
    return {
        pin for pin in (
            db.get_meta(CONFIRMED_GENESIS_META), db.get_meta(GENESIS_META),
            held_genesis(db), vault.keypair.confirmed_genesis,
        ) if pin
    }


def forget_team_log_pin(vault: Vault, typed: str, client: SyncClient) -> set[str]:
    """Drop the team log pin of this device; the genesis hashes it left.

    ``typed``: the pinned genesis, at least its first 16 characters. Refused
    while a team change of this device waits for the old log, and (INV-8)
    unless ``client`` follows the server's log now and refuses it as lost
    (MISMATCH_CAUSES): never for a server that forks or goes back.
    """
    from ..crypto.aead import encrypt_keypair_wrap

    db = vault.db
    pins = pinned_genesis(vault)
    if not pins:
        raise ValueError("This device pins no team log; nothing to forget.")
    # Conflicting pins (anchor_conflict: the account keys name another log
    # than this device holds) are left together, each one typed.
    parts = typed.replace(",", " ").lower().split()
    if (not parts or any(len(part) < MIN_CONFIRM_CHARS for part in parts)
            or not all(any(pin.startswith(part) for part in parts) for pin in pins)
            or not all(any(pin.startswith(part) for pin in pins) for part in parts)):
        raise ValueError(
            f"Type the pinned genesis, every one (at least its first {MIN_CONFIRM_CHARS} characters), to forget it: "
            + ", ".join(sorted(pins))
        )
    waiting = []
    if queued_changes(db) or outbox.items(db, outbox.TEAM_GRANT):
        waiting.append("team changes not sent yet ('sezam push', or 'sezam team-log discard')")
    if set_aside_changes(db):
        waiting.append("set-aside team changes ('sezam team-log discard')")
    if pending_states.rekey_batch(db):
        waiting.append("a re-key not sent yet ('sezam push' or 'sezam abandon-rekey')")
    if waiting:
        raise RuntimeError("These wait for the pinned team log; settle them first: " + "; ".join(waiting))
    refusal = client.team_log_refusal()
    if refusal is None or not refusal.offers_forget:
        raise ValueError(
            "The server's team log is not lost, so it is not forgotten: "
            + (str(refusal) if refusal else "this device follows it.")
        )

    keypair = vault.keypair
    with db.transaction(immediate=True):
        db.execute("DELETE FROM team_log")
        db.execute(
            "DELETE FROM vault_meta WHERE key IN (?, ?, ?, ?)",
            (GENESIS_META, CONFIRMED_GENESIS_META, ACCOUNT_ANCHOR_META, ROTATION_SEALED_META),
        )
        # An unreadable list is replaced (INV-7, capability run 411).
        db.set_meta_json(FORGOTTEN_GENESIS_META, sorted(set(readable_forgotten_genesis(db) or []) | pins))
        if keypair.confirmed_genesis is not None:
            # The local keys stop carrying the anchor (unlock would pin it again).
            anchor, pre_anchor = keypair.confirmed_genesis, keypair.pre_anchor
            keypair.confirmed_genesis, keypair.pre_anchor = None, b""
            data = keypair.serialize_private()
            try:
                wrapped = encrypt_keypair_wrap(
                    keypair_data=data, kek=vault.dek_mgr._kek,
                    kek_dek_id=ulid_to_bytes(vault.dek_mgr._wrapping_kek_id()),
                    user_object_id=ulid_to_bytes(db.get_meta("user_id")),
                )
                db.set_meta("encrypted_keypair", wrapped.hex())
            except Exception:
                keypair.confirmed_genesis, keypair.pre_anchor = anchor, pre_anchor
                raise
            finally:
                data[:] = bytes(len(data))
    return pins
