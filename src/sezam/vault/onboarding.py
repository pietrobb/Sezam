"""Server onboarding helpers shared by the CLI and the desktop GUI."""

from __future__ import annotations

import hashlib
import os
from typing import TYPE_CHECKING

from ..crypto.kdf import Argon2Params, derive_kek_and_proof
from . import pending_states

if TYPE_CHECKING:
    from .crud import Vault


class BootstrapKeyMaterialElsewhere(RuntimeError):
    """The pending bootstrap account got key material other than ours: the
    connect continues as for any existing account (recovery)."""


def keypair_upload_body(vault: Vault, password: str) -> dict:
    """PUT /api/me/keypair body: the local key material plus its auth proof."""
    argon2_salt_hex = vault.db.get_meta("argon2_salt")
    params_dict = vault.db.get_meta_json("argon2_params")
    params = Argon2Params.from_dict(params_dict) if params_dict else Argon2Params()
    # The proof must come from the password form that opens the uploaded
    # keypair; a vault from before NFC normalization may need another one
    # (lockout review M8).
    form = vault.password_form(password)
    if form is None:
        raise ValueError("Wrong master password")
    # Single Argon2id → 64B, split into KEK[0:32] + auth_proof[32:64] (spec 2.2 note B)
    kek, auth_proof = derive_kek_and_proof(
        form, bytes.fromhex(argon2_salt_hex), params, exact=True
    )
    try:
        return {
            "encrypted_keypair": vault.db.get_meta("encrypted_keypair"),
            "argon2_salt": argon2_salt_hex,
            "auth_salt": os.urandom(16).hex(),
            "auth_proof": auth_proof.hex(),
            "argon2_params": params.account_dict(),
        }
    finally:
        kek[:] = b"\x00" * len(kek)
        auth_proof[:] = b"\x00" * len(auth_proof)


def bootstrap_upload_pending(vault: Vault, server_url: str) -> bool:
    """Whether this vault bootstrapped ``server_url`` but never uploaded its keypair."""
    return bool(
        pending_states.bootstrap_upload_flag(vault.db)
        and vault.db.get_meta("server_url") == server_url
        and vault.db.get_meta("user_id")
    )


def finish_bootstrap_upload(vault: Vault, server_url: str, password: str) -> dict:
    """Finish a bootstrap whose keypair upload failed, then push the vault.

    The admin account exists (bootstrap-status no longer offers setup) but
    has no key material, so neither recovery nor an invitation can complete
    it. The device keypair still signs in, and the server accepts the first
    upload with a fresh signed challenge. Returns the push result.
    """
    return complete_bootstrap_upload(vault, server_url, password).push()


def complete_bootstrap_upload(vault: Vault, server_url: str, password: str):
    """Upload the key material of a pending bootstrap; returns a signed-in SyncClient."""
    from .sync_client import SyncClient

    client = SyncClient(vault.db, server_url, vault.keypair, vault.db.get_meta("user_id"))
    client.set_dek_manager(vault.dek_mgr)
    client.authenticate()
    # The earlier upload may have reached the server with only its reply lost
    # (capability finding, run 13): a repeated PUT would then be refused on
    # every connect, so ask the server which key material it holds first.
    probe = client._request("GET", "/api/sync?since_commit_seq=0", auth=True) or {}
    server_hash = probe.get("key_material_hash")
    if server_hash is not None:
        pending_states.mark_bootstrap_upload_pending(vault.db, False)
        local_hash = hashlib.sha256(bytes.fromhex(vault.db.get_meta("encrypted_keypair"))).hexdigest()
        if server_hash != local_hash:
            raise BootstrapKeyMaterialElsewhere(
                "The server account already has other key material; "
                "continuing with recovery."
            )
        # Our upload was stored, and this token was issued after it.
        return client
    challenge, signature = client._signed_challenge()
    body = keypair_upload_body(vault, password)
    body.update(challenge=challenge, signature=signature)
    resp = client._request("PUT", "/api/me/keypair", body, auth=True) or {}
    pending_states.mark_bootstrap_upload_pending(vault.db, False)
    if resp.get("token"):
        client.token = resp["token"]
    return client
