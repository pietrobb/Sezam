"""AI kill switch: persistent ``ai_access_enabled`` / ``ai_access_epoch``.

The state lives in ``vault_meta`` so it survives restarts of ``mcp-serve``.
Turning AI access off needs no password and works on a locked vault (it is
the emergency brake); turning it on needs an unlocked vault, which callers
open with a freshly typed master password. Any value that cannot be read
or parsed counts as off, and so does 'on' without a valid MAC under the KEK.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import logging
import os
import socket
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

from .db import VaultDB

if TYPE_CHECKING:
    from .crud import Vault

logger = logging.getLogger(__name__)

ENABLED_KEY = "ai_access_enabled"
EPOCH_KEY = "ai_access_epoch"
PENDING_AUDIT_KEY = "ai_access_audit_pending"
# Review d615826: vault_meta is plain SQLite, so an agent with a shell could
# turn AI access on (DELETE the row: unset meant on) or blind the phone's
# brake (raise the applied remote epoch). 'On' and the applied remote epoch
# now count only with an HMAC under a key derived from the KEK; turning off
# needs no key and an unverifiable value counts as off / as nothing applied.
STATE_MAC_KEY = "ai_access_mac"
REMOTE_APPLIED_KEY = "ai_remote_policy_epoch"
REMOTE_APPLIED_MAC_KEY = "ai_remote_policy_mac"
_MAC_CONTEXT = b"sezam/ai-access-state/v1"


@dataclass(frozen=True)
class AIAccessState:
    enabled: bool
    epoch: int


@contextmanager
def _meta_db(vault: "Vault") -> Iterator[VaultDB]:
    """The vault's open connection, or a short-lived one while locked."""
    # Held throughout, so a lock() from another thread cannot close the
    # shared connection between this check and the reads.
    with vault.db._guard:
        if vault.db._conn is not None:
            yield vault.db
            return
    if not vault.db.exists():
        raise FileNotFoundError("Vault not found.")
    db = VaultDB(vault.db.path)
    db.open()
    try:
        yield db
    finally:
        db.close()


def _parse(enabled: str | None, epoch: str | None) -> AIAccessState:
    # Unset is off: a vault from before the kill switch needs 'sezam ai on'.
    try:
        epoch_value = 0 if epoch is None else int(epoch)
    except ValueError:
        return AIAccessState(False, 0)
    if epoch_value < 0:
        return AIAccessState(False, 0)
    return AIAccessState(enabled == "1", epoch_value)


def _vault_kek(vault: "Vault") -> bytes | None:
    """A copy of the KEK while the vault is unlocked, else None."""
    manager = getattr(vault, "_dek_mgr", None)
    kek = getattr(manager, "_kek", None) if vault.is_unlocked else None
    return bytes(kek) if kek else None


def _mac(kek: bytes, *fields: str | None) -> str:
    key = hmac.new(kek, _MAC_CONTEXT, hashlib.sha256).digest()
    message = json.dumps(list(fields), separators=(",", ":")).encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _state_mac(kek: bytes, db: VaultDB) -> str:
    return _mac(kek, STATE_MAC_KEY, db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY))


def _remote_mac(kek: bytes, db: VaultDB) -> str:
    return _mac(kek, REMOTE_APPLIED_MAC_KEY, db.get_meta(REMOTE_APPLIED_KEY))


def _verified(db: VaultDB, mac_key: str, expected: str) -> bool:
    stored = db.get_meta(mac_key)
    return isinstance(stored, str) and hmac.compare_digest(stored, expected)


def seal_new_vault(db: VaultDB, kek: bytes | bytearray) -> None:
    """A newly created vault starts with AI access on, sealed under its KEK."""
    db.set_meta(ENABLED_KEY, "1")
    db.set_meta(EPOCH_KEY, "0")
    db.set_meta(STATE_MAC_KEY, _state_mac(bytes(kek), db))


def rewrap_macs(db: VaultDB, old_kek: bytes | bytearray, new_kek: bytes | bytearray) -> None:
    """KEK change (password change, adopted rotation): what verified under
    the old KEK is sealed under the new one; anything else stays unverified."""
    old, new = bytes(old_kek), bytes(new_kek)
    if _verified(db, STATE_MAC_KEY, _state_mac(old, db)):
        db.set_meta(STATE_MAC_KEY, _state_mac(new, db))
    if _verified(db, REMOTE_APPLIED_MAC_KEY, _remote_mac(old, db)):
        db.set_meta(REMOTE_APPLIED_MAC_KEY, _remote_mac(new, db))


def read_state(vault: "Vault") -> AIAccessState:
    """Current kill switch state; any failure to read it means off.

    On an unlocked vault 'on' also needs a valid MAC. A locked vault cannot
    check it, so there it is only what the vault claims (for display and the
    start of mcp-serve); every tool call needs the vault unlocked anyway.
    """
    try:
        kek = _vault_kek(vault)
        with _meta_db(vault) as db:
            state = _parse(db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY))
            if state.enabled and kek is not None and not _verified(
                db, STATE_MAC_KEY, _state_mac(kek, db)
            ):
                logger.warning("AI access state does not verify; treating it as off")
                return AIAccessState(False, state.epoch)
            return state
    except Exception:
        logger.warning("AI access state is unreadable; treating it as off", exc_info=True)
        return AIAccessState(False, 0)


def verified_on_epoch(vault: "Vault") -> int | None:
    """The epoch of a verified 'on' (unlocked vault, valid MAC), else None.
    What a broker's in-memory brake may be released by (review 7c10379 H6):
    a locked vault's claim of 'on' is not checked and must not count."""
    kek = _vault_kek(vault)
    if kek is None:
        return None
    try:
        with _meta_db(vault) as db:
            state = _parse(db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY))
            if state.enabled and _verified(db, STATE_MAC_KEY, _state_mac(kek, db)):
                return state.epoch
    except Exception:
        logger.warning("AI access state is unreadable; treating it as off", exc_info=True)
    return None


def remote_applied_epoch(vault: "Vault") -> int:
    """Epoch of the last remote policy applied here. Only a value sealed
    under the KEK counts; anything else is 0, so any valid policy brakes again."""
    kek = _vault_kek(vault)
    if kek is None:
        return 0
    db = vault.db
    if not _verified(db, REMOTE_APPLIED_MAC_KEY, _remote_mac(kek, db)):
        return 0
    try:
        return max(int(db.get_meta(REMOTE_APPLIED_KEY) or 0), 0)
    except (TypeError, ValueError):
        return 0


def record_remote_applied(vault: "Vault", epoch: int) -> None:
    """Seal the epoch of a remote policy just applied (vault unlocked)."""
    kek = _vault_kek(vault)
    if kek is None:
        raise PermissionError("Recording a remote AI policy needs the unlocked vault.")
    db = vault.db
    with db.transaction():
        db.set_meta(REMOTE_APPLIED_KEY, str(epoch))
        db.set_meta(REMOTE_APPLIED_MAC_KEY, _remote_mac(kek, db))


def _origin(source: str) -> dict:
    try:
        user = getpass.getuser()
    except Exception:
        user = None
    return {
        "source": source,
        "host": socket.gethostname(),
        "os_user": user,
        "pid": os.getpid(),
        "at": int(time.time()),
    }


def disable(vault: "Vault", source: str, extra: dict | None = None) -> AIAccessState:
    """Turn AI access off and bump the epoch. Never needs a password.

    The audit record is written now when the vault is unlocked; otherwise
    (or if writing it fails) it is queued and written at the next unlock,
    so the brake itself never depends on the audit log. ``extra`` goes
    into the audit detail (e.g. the epoch of a remote policy).

    Review 7c10379 H6: the MAC of the 'on' state stayed, so writing back
    ('1', old epoch) turned AI on at the next unlock. It is deleted with the
    switch; only 'sezam ai on' seals a new one.
    """
    with _meta_db(vault) as db:
        # Write lock before the read: another broker's 'off' committed in
        # between failed this one with 'database is locked' (review 7c10379).
        with db.transaction(immediate=True):
            current = _parse(db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY))
            state = AIAccessState(False, current.epoch + 1)
            db.set_meta(ENABLED_KEY, "0")
            db.set_meta(EPOCH_KEY, str(state.epoch))
            db.execute("DELETE FROM vault_meta WHERE key = ?", (STATE_MAC_KEY,))
        detail = {**(extra or {}), "epoch": state.epoch, **_origin(source)}
        if not _write_audit(vault, "ai_off", detail):
            with db.transaction(immediate=True):  # another broker may queue one too
                pending = _pending(db)
                pending.append({"action": "ai_off", "detail": detail})
                db.set_meta_json(PENDING_AUDIT_KEY, pending)
    return state


def off_in_copy(conn) -> None:
    """Review 1141a20 M-AI4: a copy of sezam.db (snapshot, encrypted backup)
    never carries 'on'. Its rows with a valid MAC were a ready 'on' for an
    agent under the owner's OS user (L1) to write back after 'sezam ai off'.
    A restore turns access off anyway (off_for_restore). ``conn`` is a
    sqlite3 connection to the copy, not the live vault."""
    with conn:
        conn.execute("DELETE FROM vault_meta WHERE key = ?", (STATE_MAC_KEY,))
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, '0')", (ENABLED_KEY,)
        )


def off_for_restore(db: VaultDB, live_epoch: int) -> AIAccessState:
    """Turn AI access off in a snapshot or backup about to replace the vault.

    Review a159e97: the copy held 'on' with a MAC under the same KEK, so a
    restore turned AI access back on after it had been switched off. The
    restored vault starts off, at an epoch past both the copy's and the live
    vault's; the audit record is written at the next unlock.
    """
    with db.transaction(immediate=True):
        current = _parse(db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY))
        state = AIAccessState(False, max(current.epoch, live_epoch) + 1)
        db.set_meta(ENABLED_KEY, "0")
        db.set_meta(EPOCH_KEY, str(state.epoch))
        db.execute("DELETE FROM vault_meta WHERE key = ?", (STATE_MAC_KEY,))
        pending = _pending(db)
        pending.append({"action": "ai_off", "detail": {"epoch": state.epoch, **_origin("restore")}})
        db.set_meta_json(PENDING_AUDIT_KEY, pending)
    return state


def enable(vault: "Vault", source: str) -> AIAccessState:
    """Turn AI access on; the vault must be unlocked (fresh password)."""
    if not vault.is_unlocked:
        raise PermissionError("Turning AI access on requires the master password.")
    db = vault.db
    current = read_state(vault)
    state = AIAccessState(True, current.epoch)
    # Audit first: if it cannot be recorded, access stays off.
    vault._audit_log(
        "ai_on",
        json.dumps({"epoch": state.epoch, **_origin(source)}, sort_keys=True).encode(),
        strict=True,
    )
    kek = _vault_kek(vault)
    if kek is None:
        raise PermissionError("Turning AI access on requires the master password.")
    # Review 8595ec1: an 'ai off' from another process committed after the
    # read above was overwritten. Read again under the write lock; a brake
    # applied meanwhile wins.
    with db.transaction(immediate=True):
        now = _parse(db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY))
        if now.epoch != state.epoch:
            raise RuntimeError(
                f"AI access was switched off meanwhile (epoch {state.epoch} -> {now.epoch}); "
                "it stays off. Run 'sezam ai on' again to turn it on."
            )
        db.set_meta(ENABLED_KEY, "1")
        db.set_meta(EPOCH_KEY, str(state.epoch))
        db.set_meta(STATE_MAC_KEY, _state_mac(kek, db))
    return state


def _write_audit(vault: "Vault", action: str, detail: dict) -> bool:
    if not vault.is_unlocked:
        return False
    try:
        vault._audit_log(
            action, json.dumps(detail, sort_keys=True).encode(), strict=True
        )
    except Exception:
        logger.warning("Audit record %r queued for the next unlock", action, exc_info=True)
        return False
    return True


def _pending(db: VaultDB) -> list:
    try:
        value = db.get_meta_json(PENDING_AUDIT_KEY)
    except ValueError:
        value = None
    return value if isinstance(value, list) else []


def flush_pending_audit(vault: "Vault") -> None:
    """Write kill switch audit records queued while the vault was locked."""
    db = vault.db
    pending = _pending(db)
    if not pending:
        return
    remaining = []
    for record in pending:
        detail = dict(record.get("detail") or {}, recorded_at_unlock=True)
        if not _write_audit(vault, str(record.get("action")), detail):
            remaining.append(record)
    if remaining:
        db.set_meta_json(PENDING_AUDIT_KEY, remaining)
    else:
        db.execute("DELETE FROM vault_meta WHERE key = ?", (PENDING_AUDIT_KEY,))
