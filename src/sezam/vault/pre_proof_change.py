"""A password change an older version left without the server's proof.

Review 4acfdde R11 (medium): versions before 688edcb K1 kept no proof of the
password the server has. The server now refuses such a change; this adds the
proof so the next push sends it and the new password stays.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional
from urllib.parse import quote

from . import oplock, pending_states
from .sync_common import server_error

if TYPE_CHECKING:
    from .crud import Vault
    from .sync_client import SyncClient


@oplock.held
def finish_pending_change(client: "SyncClient", vault: "Vault", account_password: str) -> None:
    """The server checks the password first (/auth/recover, rate-limited like
    a login); nothing changes on a wrong one."""
    from .crud import recover_with_password, server_account_kdf
    from .key_rotation import with_current_auth_proof

    db = client._db
    if not pending_states.change_lacks_server_proof(db):
        raise RuntimeError("No unsent password change here lacks the server's password")
    journal = pending_states.key_change_journal(db)
    username = client._get_username()
    meta = client._request("GET", f"/api/meta?username={quote(username)}") or {}
    if not meta.get("argon2_salt"):
        raise RuntimeError("Server did not return the account KDF parameters")
    proved: dict = {}

    def post(body: dict) -> Optional[dict]:
        resp = client._request("POST", "/api/auth/recover", body)
        proved["proof"] = bytearray.fromhex(body["auth_proof"])
        return resp

    try:
        kek, resp = recover_with_password(
            post, username, account_password,
            bytes.fromhex(meta["argon2_salt"]), server_account_kdf(meta, db),
        )
    except RuntimeError as exc:
        if server_error(exc, 401) or server_error(exc, 403):
            raise RuntimeError("Wrong current account password") from exc
        raise
    kek[:] = b"\x00" * len(kek)
    proof = proved["proof"]
    try:
        if resp.get("user_id") != db.get_meta("user_id"):
            raise RuntimeError("Server returned a different account")
        if int(resp.get("key_epoch") or 0) != int(journal["epoch"]) - 1:
            raise RuntimeError(
                "The server's password is not the one this change replaces (changed on "
                "another device?); 'sezam abandon-pending-change' takes the server's over"
            )
        pending_states.set_key_change_journal(db, with_current_auth_proof(
            journal, vault.dek_mgr._kek, db.get_meta("user_id"), proof
        ))
    finally:
        proof[:] = b"\x00" * len(proof)
