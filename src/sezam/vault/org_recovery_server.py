"""Keeping the server in step with this vault's org recovery (review 526419e V5).

After a Shamir recovery the server takes the new password only on a proof
signed with the recovery key it registered; a lone admin has nobody to grant
a key reset. A recovery set up before the server learned recovery keys, or
whose registration failed, used to be noticed only after the password was
forgotten. It is now checked where the password is known (unlock, push), and
a replacement that the server does not take keeps the old, working setup.
"""

from __future__ import annotations

import http.client
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from . import oplock, pending_states
from .sync_client import SyncClient
from .sync_common import ServerError

if TYPE_CHECKING:
    from .crud import Vault

UNREGISTERED_HINT = (
    "The server does not know this vault's org recovery (it was set up before the "
    "server learned recovery keys, or the server was restored from an older backup). The shares would reset this vault, but the server "
    "would then refuse the new password. While you still know the password, run "
    "'sezam org-recovery-setup --replace' and hand out the new shares."
)
REGISTERED_NOTICE = (
    "The server now knows this vault's org recovery: after 'sezam org-recovery' it "
    "accepts the new password without the old one."
)
# Review 526419e S3: the server keeps ONE org recovery; another admin's is not a
# dead end (another admin can allow the reset), and '--replace' only got a 409.
OTHER_ADMIN_NOTE = (
    "The server's org recovery was set up by another admin, so it does not take this "
    "vault's recovery key. After 'sezam org-recovery' another admin has to run "
    "'sezam allow-key-reset' for you. Replacing their recovery "
    "('sezam org-recovery-setup --replace-other-admin') voids every share they "
    "handed out; agree on it with them first."
)
OTHER_ADMIN_NOTED_META = "org_recovery_other_admin_noted"
# Review 8595ec1 #3/#4: a team log has one admin, so nobody can allow a key
# reset; the server takes this vault's recovery key once the log names it.
LOG_ADMIN_NOTE = (
    "The server's org recovery blob was set up by another (former) admin. A team log "
    "has one admin, so nobody can run 'sezam allow-key-reset' for you; after 'sezam "
    "org-recovery' the server takes the reset signed by the recovery key the team log "
    "names for you ('sezam push' names this vault's there)."
)


def _log_admin(vault: "Vault") -> bool:
    from .. import teamlog
    from .team_log_local import local_team_state

    state = local_team_state(vault.db)
    return state is not None and teamlog.is_admin(state, vault.db.get_meta("user_id"))

_SETUP_META = (
    "org_recovery_pk", "org_recovery_wrapped_kek", "org_recovery_stale",
    "org_recovery_threshold", "org_recovery_shares", "org_recovery_signing_pk",
    "org_recovery_server_wrap",
)


class OrgRecoveryNotReplaced(RuntimeError):
    """The server did not take a new recovery key; the old setup is kept."""


class OrgRecoveryOnServer(RuntimeError):
    """The server already holds an org recovery this setup would replace
    (review 526419e S2/S3). ``other_admin`` says whose it is; nothing changed."""

    def __init__(self, other_admin: Optional[str], log_admin: bool = False):
        self.other_admin = other_admin
        if other_admin and log_admin:
            # Review 8595ec1 #3: no other admin of a team log can allow a reset.
            text = (
                f"Org recovery on the server was set up by another (former) admin ({other_admin}). "
                "A new setup voids every share they handed out; run 'sezam "
                "org-recovery-setup --replace-other-admin' to replace it."
            )
        elif other_admin:
            text = (
                f"Org recovery on the server was set up by another admin ({other_admin}). "
                "A new setup voids every share they handed out. Agree on it with them, "
                "then run 'sezam org-recovery-setup --replace-other-admin'; or keep "
                "theirs: after 'sezam org-recovery' another admin runs "
                "'sezam allow-key-reset' for you."
            )
        else:
            text = (
                "Org recovery of this account is already on the server (set up on the "
                "web or another device). A new setup voids every share of it; run "
                "'sezam org-recovery-setup --replace' to replace it anyway."
            )
        super().__init__(text)


def server_status(vault: "Vault") -> dict:
    """/api/org-recovery/status; {} when the server cannot be asked."""
    try:
        return _client(vault)._request("GET", "/api/org-recovery/status") or {}
    except RuntimeError:
        return {}


@dataclass
class OrgRecoverySetup:
    shares: list[tuple[int, bytes]]
    registered: Optional[bool]  # None: the vault is not connected
    error: Optional[str] = None


def _client(vault: "Vault") -> SyncClient:
    client = SyncClient(
        vault.db, vault.db.get_meta("server_url") or "", vault.keypair,
        vault.db.get_meta("user_id"),
    )
    client.set_dek_manager(vault.dek_mgr)
    return client


def registration_issue(vault: "Vault") -> Optional[str]:
    """``'pending'`` (a saved registration waits for the password),
    ``'unregistered'`` (the server holds no recovery key of this account),
    ``'other_admin'`` (the server holds another admin's recovery) or None.
    Raises RuntimeError when the server cannot be asked."""
    if not vault.org_recovery_configured() or not vault.db.get_meta("server_url"):
        return None
    # Always asked: a server restored from a backup taken before the
    # registration lost it, and a local "registered" mark hid that.
    status = _client(vault)._request("GET", "/api/org-recovery/status") or {}
    owner = status.get("created_by") if status.get("configured") else None
    if owner and owner != vault.db.get_meta("user_id"):
        return "other_admin"  # a saved registration would only get a 409
    if pending_states.org_recovery_registration(vault.db) is not None:
        return "pending"
    return None if owner else "unregistered"


def register_while_password_known(vault: "Vault", password: str) -> Optional[str]:
    """Register a saved recovery key, or say how to get one registered.

    Returns what to tell the user, or None. An unreachable server is no news.
    """
    if vault.key_change_unpushed():
        return None  # the proof would be of a password the server lacks yet
    try:
        issue = registration_issue(vault)
    except RuntimeError:
        return None
    if issue == "pending":
        try:
            SyncClient.register_org_recovery(vault, password)
        except (RuntimeError, ValueError) as exc:
            return f"Warning: the server did not take this vault's org recovery ({exc})."
        return REGISTERED_NOTICE
    if issue == "unregistered":
        return UNREGISTERED_HINT
    if issue == "other_admin":
        recovery_pk = vault.db.get_meta("org_recovery_pk")
        if vault.db.get_meta(OTHER_ADMIN_NOTED_META) == recovery_pk:
            return None  # said once for this setup; not on every unlock
        vault.db.set_meta(OTHER_ADMIN_NOTED_META, recovery_pk or "")
        return LOG_ADMIN_NOTE if _log_admin(vault) else OTHER_ADMIN_NOTE
    return None


UNKNOWN_OUTCOME = (
    "the server's answer was lost ({error}), so it is not known whether it took the "
    "new recovery key. These new shares are the valid ones: the old setup was not "
    "restored. The next unlock or 'sezam push' registers the new key again"
)


def _server_holds(vault: "Vault", wrapped_kek: str) -> bool:
    """Whether the server's org recovery blob is ``wrapped_kek``; False when
    the server cannot be asked."""
    try:
        blob = _client(vault)._request("GET", "/api/org-recovery/blob") or {}
    except (RuntimeError, OSError, ValueError, http.client.HTTPException):
        return False
    if not isinstance(blob, dict):
        return False
    return str(blob.get("wrapped_kek") or "").lower() == wrapped_kek.lower()


def _outcome_unknown(exc: BaseException) -> bool:
    """Whether a failed registration may have been stored by the server: only
    a clear refusal (a 4xx, a wrong password before sending) is not."""
    if isinstance(exc, (OSError, http.client.HTTPException, json.JSONDecodeError, UnicodeDecodeError)):
        return True
    return isinstance(exc, ServerError) and exc.status >= 500


def setup_and_register(
    vault: "Vault", password: str, threshold: int, shares: int, *, replace: bool = False,
    replace_other_admin: bool = False,
) -> OrgRecoverySetup:
    """Review a159e97 H9: setup, registration and rollback hold the vault's
    sync lock, so a push or a password change in another process cannot run
    between them (see _setup_and_register)."""
    path = getattr(vault.db, "path", None)
    if path is None:
        return _setup_and_register(
            vault, password, threshold, shares, replace=replace,
            replace_other_admin=replace_other_admin,
        )
    with oplock.exclusive(path):
        result = _setup_and_register(
            vault, password, threshold, shares, replace=replace,
            replace_other_admin=replace_other_admin,
        )
        if vault.db.get_meta("server_url"):
            # Review 8595ec1 #4: the team log names the key (next push sends it).
            _client(vault).anchor_org_recovery(replace=True)
        return result


def _setup_and_register(
    vault: "Vault", password: str, threshold: int, shares: int, *, replace: bool = False,
    replace_other_admin: bool = False,
) -> OrgRecoverySetup:
    """Set up org recovery and register it on the server.

    A replacement the server does not take is rolled back and raises
    OrgRecoveryNotReplaced: the shares handed out before keep working. It is
    refused up front while a password change of this vault is unsent - the
    proof would be of a password the server lacks and count as a wrong one.
    A first setup is kept locally; the next unlock or push registers it.

    An org recovery already on the server (from the web, another device or
    another admin) is replaced only when asked for: OrgRecoveryOnServer
    otherwise, before anything changes (review 526419e S2/S3).
    """
    connected = bool(vault.db.get_meta("server_url"))
    unpushed = connected and vault.key_change_unpushed()
    if replace and unpushed:
        raise OrgRecoveryNotReplaced(
            "this device's password change has not reached the server yet; run "
            "'sezam push' first"
        )
    if connected and not unpushed:
        status = server_status(vault)
        owner = status.get("created_by") if status.get("configured") else None
        if owner and owner != vault.db.get_meta("user_id"):
            if not replace_other_admin:
                raise OrgRecoveryOnServer(owner, _log_admin(vault))
        elif owner and not (replace or replace_other_admin):
            raise OrgRecoveryOnServer(None)
        if owner:
            replace = True  # refused by the server: roll back, keep the old one
    old = {key: vault.db.get_meta(key) for key in _SETUP_META}
    old_registration = pending_states.org_recovery_registration(vault.db)
    new_shares = vault.setup_org_recovery(threshold=threshold, shares=shares, replace=replace)
    if not connected:
        return OrgRecoverySetup(new_shares, None)
    if unpushed:
        return OrgRecoverySetup(
            new_shares, False,
            "the password change of this device has to reach the server first; "
            "the next 'sezam push' after it registers the recovery",
        )
    registration = pending_states.org_recovery_registration(vault.db) or {}
    try:
        SyncClient.register_org_recovery(
            vault, password, replace_other_admin=replace_other_admin
        )
    except (RuntimeError, ValueError, OSError, http.client.HTTPException) as exc:
        # Review a159e97 H9: rolled back like a refusal, a server that took
        # the key would hold it with the new shares wiped and the old ones void
        # there. Whether it took it is asked first; an answer that does not say
        # (a broken connection, a proxy's 5xx, a garbled or cut body - capability
        # review run 201) keeps the new setup and its registration waits.
        if _server_holds(vault, str(registration.get("wrapped_kek") or "")):
            pending_states.clear_org_recovery_registration(vault.db)
            return OrgRecoverySetup(new_shares, True)
        if _outcome_unknown(exc):
            return OrgRecoverySetup(new_shares, False, UNKNOWN_OUTCOME.format(error=exc))
        if not replace:
            return OrgRecoverySetup(new_shares, False, str(exc))
        for _index, share in new_shares:
            if isinstance(share, bytearray):
                share[:] = b"\x00" * len(share)
        vault.db.begin()
        try:
            for key, value in old.items():
                if value is None:
                    vault.db.execute("DELETE FROM vault_meta WHERE key = ?", (key,))
                else:
                    vault.db.set_meta(key, value)
            if old_registration is None:
                pending_states.clear_org_recovery_registration(vault.db)
            else:
                pending_states.set_org_recovery_registration(vault.db, old_registration)
            vault.db.commit()
        except Exception:
            vault.db.rollback()
            raise
        raise OrgRecoveryNotReplaced(str(exc)) from exc
    return OrgRecoverySetup(new_shares, True)
