"""`sezam server reseed`: rebuild an empty (wiped or new) server from this vault.

The server accepts the bootstrap with the vault's EXISTING account id when the
identity key signs a fresh, username-bound challenge over the whole request
(``reseed_message``). The vault then marks everything it owns for push and
sends it, so the account, its key epoch and its object ids are the same as
before the loss and other devices of the account keep working.

The steps are journalled in vault_meta (``RESEED_STATE``) so an interrupted
reseed resumes on the next run instead of leaving a half-seeded server.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..models import ulid_to_bytes
from ..usernames import normalize_username
from . import ai_access, oplock, outbox, pending_states
from .onboarding import complete_bootstrap_upload
from .snapshots import take_snapshot
from .sync_client import (
    _CHECKPOINT_META_KEY,
    COMMIT_ANCHOR_META,
    RESEED_ARCHIVES_META,
    SERVER_ROLLBACK_META,
    ServerError,
    SyncClient,
)
from .sync_common import USERNAME_TAKEN, server_error

if TYPE_CHECKING:
    from .crud import Vault

logger = logging.getLogger(__name__)

RESEED_CONTEXT = b"sezam-reseed-v1"
REJOIN_CONTEXT = b"sezam-rejoin-v1"


class ReseedError(RuntimeError):
    """The reseed was refused before anything changed on the server."""


def reseed_message(
    challenge: bytes,
    user_id: str,
    username: str,
    signing_pk: bytes,
    encryption_pk: bytes,
    key_epoch: int,
    context: bytes = RESEED_CONTEXT,
) -> bytes:
    """Must equal server.app.auth.reseed_message byte for byte."""
    name = username.encode("utf-8")
    return (
        context
        + bytes(challenge)
        + ulid_to_bytes(user_id)
        + len(name).to_bytes(2, "big")
        + name
        + bytes(signing_pk)
        + bytes(encryption_pk)
        + int(key_epoch).to_bytes(8, "big")
    )


@oplock.held
def reseed_server(vault: Vault, server_url: str, password: str) -> dict:
    """Seed ``server_url`` with this vault's account and data.

    Returns ``{"pushed": n, "conflicts": [...], "resumed": bool}``.
    """
    server_url = server_url.rstrip("/")
    db = vault.db
    user_id = db.get_meta("user_id")
    # N3: the server signs/verifies the trimmed name.
    username = normalize_username(db.get_meta("username") or "")
    if not user_id or not username:
        raise ReseedError("The vault has no account identity to reseed.")
    client = SyncClient(db, server_url, vault.keypair, user_id)
    client.set_dek_manager(vault.dek_mgr)

    status = client._request("GET", "/api/bootstrap-status") or {}
    state = (pending_states.reseed_state(db) or "")
    resumed = not status.get("needs_setup")
    if resumed:
        if state not in (f"bootstrap {server_url}", f"push {server_url}"):
            raise ReseedError(
                "The server is not empty; reseed only works on an empty server."
            )
    else:
        take_snapshot(db, "server-reseed")
        _bootstrap(vault, client, server_url, user_id, username)
        state = f"bootstrap {server_url}"

    return _upload_and_push(vault, server_url, password, state, resumed)


@oplock.held
def rejoin_server(vault: Vault, server_url: str, password: str, username: str | None = None) -> dict:
    """Bring this vault's member account back on a server whose backup was
    older than the account (review 8595ec1 #1), then send what it owns.

    The team log (put back by any device holding it) names the account's id
    and keys; the server takes them only with a fresh proof by those keys.
    ``username`` rejoins under another name: the log names the member by id,
    and an account registered after the backup may hold the old name
    (review 4acfdde R11, low). Returns like reseed_server.
    """
    server_url = server_url.rstrip("/")
    db = vault.db
    user_id = db.get_meta("user_id")
    previous_name = db.get_meta("username")
    if username is not None:
        username = normalize_username(username)
        if not username:
            raise ReseedError("The new username is empty.")
    else:
        username = normalize_username(previous_name or "")
    if not user_id or not username:
        raise ReseedError("The vault has no account identity to rejoin with.")
    client = SyncClient(db, server_url, vault.keypair, user_id)
    client.set_dek_manager(vault.dek_mgr)
    state = pending_states.reseed_state(db) or ""
    resumed = state in (f"rejoin {server_url}", f"push {server_url}")
    if state != f"push {server_url}":
        if not client._named_by_team_log(vault.keypair):
            raise ReseedError(
                "This device's team log does not name its account as a current "
                "member with its keys; there is nothing to rejoin."
            )
        if not resumed:
            take_snapshot(db, "server-rejoin")
        keypair = vault.keypair
        key_epoch = int(db.get_meta("key_epoch") or "0")
        challenge_hex = client._request(
            "POST", "/api/auth/challenge", {"username": username}
        )["challenge"]
        message = reseed_message(
            bytes.fromhex(challenge_hex), user_id, username,
            keypair.signing_pk, keypair.encryption_pk, key_epoch, REJOIN_CONTEXT,
        )
        pending_states.set_reseed_state(db, f"rejoin {server_url}")
        # The sign-in and a resumed run use the vault's name: the new one
        # goes in with the rejoin it is sent with.
        db.set_meta("username", username)
        try:
            client._request("POST", "/api/auth/rejoin", {
                "username": username,
                "user_id": user_id,
                "signing_pk": keypair.signing_pk.hex(),
                "encryption_pk": keypair.encryption_pk.hex(),
                "key_epoch": key_epoch,
                "challenge": challenge_hex,
                "signature": keypair.to_nacl_signing_key().sign(message).signature.hex(),
            })
        except RuntimeError as exc:
            if resumed and server_error(exc, 409) and not server_error(exc, 409, USERNAME_TAKEN):
                pass  # the earlier run's rejoin landed, only its answer was lost
            elif isinstance(exc, ServerError) and 400 <= exc.status < 500:
                pending_states.clear_reseed_state(db)
                if previous_name is not None:
                    db.set_meta("username", previous_name)
                if server_error(exc, 409, USERNAME_TAKEN):
                    raise ReseedError(
                        f"Another account on the server took the name '{username}' after "
                        "the backup. Rejoin under another name: "
                        "'sezam server rejoin --username NEW_NAME'."
                    ) from exc
                raise ReseedError(f"The server refused the rejoin: {exc}") from exc
            else:
                raise
        pending_states.mark_bootstrap_upload_pending(db, True)
        state = f"rejoin {server_url}"
    return _upload_and_push(vault, server_url, password, state, resumed)


def _upload_and_push(vault: Vault, server_url: str, password: str, state: str, resumed: bool) -> dict:
    db = vault.db
    # Signs in with the identity key: fails closed if someone else's account
    # took the server meanwhile.
    client = complete_bootstrap_upload(vault, server_url, password)
    ai_access.name_server(vault, server_url)
    if state.startswith(("bootstrap ", "rejoin ")):
        # A rejoining member sends only its own items: envelopes, key
        # archives and audit records are the admin's to send.
        _mark_everything_for_push(vault, client, server_url, admin=state.startswith("bootstrap "))
    result = client.push()
    # 'admin only': no run of this device can send it (a member's audit record).
    conflicts = [c for c in result.get("conflicts") or [] if c.get("error") != "admin only"]
    if conflicts:
        # Stays journalled: the next run pushes what is still dirty.
        return {
            "pushed": len(result.get("accepted", [])),
            "conflicts": conflicts,
            "resumed": resumed,
        }
    client.pull()
    pending_states.clear_reseed_state(db)
    return {"pushed": len(result.get("accepted", [])), "conflicts": [], "resumed": resumed}


def _bootstrap(vault: Vault, client: SyncClient, server_url: str,
               user_id: str, username: str) -> None:
    db = vault.db
    keypair = vault.keypair
    key_epoch = int(db.get_meta("key_epoch") or "0")
    challenge_hex = client._request(
        "POST", "/api/auth/challenge", {"username": username}
    )["challenge"]
    message = reseed_message(
        bytes.fromhex(challenge_hex), user_id, username,
        keypair.signing_pk, keypair.encryption_pk, key_epoch,
    )
    signature = keypair.to_nacl_signing_key().sign(message).signature
    # Journal first: if the reply is lost, the next run sees a non-empty
    # server and resumes instead of refusing.
    pending_states.set_reseed_state(db, f"bootstrap {server_url}")
    try:
        resp = client._request("POST", "/api/bootstrap", {
            "username": username,
            "signing_pk": keypair.signing_pk.hex(),
            "encryption_pk": keypair.encryption_pk.hex(),
            "user_id": user_id,
            "key_epoch": key_epoch,
            "challenge": challenge_hex,
            "signature": signature.hex(),
        }) or {}
    except RuntimeError as exc:
        if isinstance(exc, ServerError) and 400 <= exc.status < 500:
            # The server answered and refused: nothing to resume.
            pending_states.clear_reseed_state(db)
            raise ReseedError(f"The server refused the reseed: {exc}") from exc
        raise
    if resp.get("user_id") != user_id:
        raise RuntimeError("The server bootstrapped a different account id")
    ai_access.name_server(vault, server_url)
    pending_states.mark_bootstrap_upload_pending(db, True)


def _mark_everything_for_push(vault: Vault, client: SyncClient, server_url: str, admin: bool = True) -> None:
    """Make the next push send every object this account can send.

    Objects of folders shared by other users (foreign DEKs) stay as they are:
    their owner has to reseed them. Audit records whose signature does not
    verify against the keys the new server knows would block every push, so
    they stay local.
    """
    db = vault.db
    foreign = set(db.get_meta_json("foreign_dek_ids") or [])
    node_ids = [
        row["id"] for row in db.fetchall("SELECT id, dek_id FROM nodes")
        if row["dek_id"] not in foreign
    ]
    archive_ids = [
        row["id"] for row in db.fetchall("SELECT id, replaced_by FROM dek_archive")
        if admin and row["replaced_by"] not in foreign
    ]
    audit_ids = []
    for row in [] if not admin else db.fetchall(
        "SELECT a.id, a.parent_ids, a.actor_id, a.action, a.encrypted_details, "
        "a.timestamp, a.signature FROM audit_log a "
        "WHERE NOT EXISTS (SELECT 1 FROM outbox o WHERE o.kind = 'audit' AND o.object_id = a.id)"
    ):
        try:
            client._verify_audit_payload(row["id"], client._serialize_audit_row(row))
        except Exception:
            logger.warning("Reseed keeps unverifiable audit record %s local", row["id"])
            continue
        audit_ids.append(row["id"])

    db.begin()
    try:
        for node_id in node_ids:
            outbox.queue_write(db, node_id)
            outbox.queue_writes(db, "entries", "node_id = ?", (node_id,))
        for audit_id in audit_ids:
            outbox.queue(db, outbox.AUDIT, audit_id)
        for row in db.fetchall("SELECT id, dek_id FROM access_envelopes"):
            if admin and row["dek_id"] not in foreign:
                outbox.requeue(db, outbox.ENVELOPE, row["id"])
        db.execute("DELETE FROM sync_conflicts")
        db.set_meta_json("pushed_dek_versions", {})
        db.set_meta_json(RESEED_ARCHIVES_META, archive_ids)
        # The new server starts at commit_seq 0 and at the local key epoch
        # (sent with the bootstrap): no rollback alarm, no pending rewrap.
        db.set_meta("last_known_commit_seq", "0")
        pending_states.set_last_pushed_key_epoch(db, db.get_meta("key_epoch") or "0")
        pending_states.clear_key_change_journal(db)
        # Review a159e97: a rollback flagged on the old server stopped the
        # closing pull here for good, so the reseed never finished.
        for key in (_CHECKPOINT_META_KEY, COMMIT_ANCHOR_META, SERVER_ROLLBACK_META):
            db.execute("DELETE FROM vault_meta WHERE key = ?", (key,))
        pending_states.set_reseed_state(db, f"push {server_url}")
        db.commit()
    except Exception:
        db.rollback()
        raise
