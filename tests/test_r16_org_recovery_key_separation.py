"""Review 18c300f R16-L4: one org recovery secret, one key per use.

The Shamir shares rebuild a 32-byte secret. Before, that secret itself was the
AEAD key of the server's KEK blob, the Ed25519 seed the server and the team log
know the recovery by, and (desktop) the X25519 key of the local KEK wrap. Every
new setup (desktop and web) now derives each with HKDF-SHA256 under its own
label (version 2). A recovery set up before (version 1) keeps working: the
server and the log know it by its Ed25519 key, and that key says the version.
"""

from __future__ import annotations

import hashlib
import hmac
import os

import pytest
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, SealedBox
from nacl.signing import SigningKey

from sezam.crypto.shamir import reconstruct_secret, split_secret
from sezam.vault import pending_states
from sezam.vault.crud import Vault
from tests.node_support import requires_node
from tests.test_grant_folder_access import team  # noqa: F401  (fixture)
from tests.test_integration_client_server import PASSWORD, _client
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_lone_admin_org_recovery import RECOVERED, _recover
from tests.test_review_web import _function, _run_source

V1_AAD = b"sezam-org-recovery-v1"
V2_AAD = b"sezam-org-recovery-v2"
PURPOSES = ("kek-wrap", "ed25519", "x25519")


def _hkdf(secret: bytes, purpose: str) -> bytes:
    """RFC 5869 HKDF-SHA256 (salt 'sezam-org-recovery-v2'), 32 bytes."""
    prk = hmac.new(b"sezam-org-recovery-v2", secret, hashlib.sha256).digest()
    info = b"sezam/org-recovery/v2/" + purpose.encode()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def _open(blob: bytes, key: bytes, aad: bytes) -> bytes:
    return crypto_aead_xchacha20poly1305_ietf_decrypt(blob[24:], aad, blob[:24], key)


def _stored_blob(db) -> bytes:
    stored = db._storage["org_recovery_blobs"][-1]["wrapped_kek"]
    return bytes(stored) if isinstance(stored, (bytes, bytearray)) else bytes.fromhex(stored)


def _v1_wrap(kek: bytes, secret: bytes) -> bytes:
    nonce = os.urandom(24)
    return nonce + crypto_aead_xchacha20poly1305_ietf_encrypt(bytes(kek), V1_AAD, nonce, secret)


def test_a_new_setup_uses_no_key_twice_nor_the_secret_itself(team):  # noqa: F811
    _, _, admin, _, _, _ = team
    shares = admin.setup_org_recovery(threshold=2, shares=3)
    secret = reconstruct_secret(shares[:2])
    registration = pending_states.org_recovery_registration(admin.db)
    blob = bytes.fromhex(registration["wrapped_kek"])
    kek = bytes(admin.dek_mgr._kek)

    # Before: all three were the secret.
    assert registration["recovery_signing_pk"] != bytes(SigningKey(secret).verify_key).hex()
    assert admin.db.get_meta("org_recovery_pk") != bytes(PrivateKey(secret).public_key).hex()
    with pytest.raises(CryptoError):
        _open(blob, secret, V1_AAD)
    # Each is its own HKDF key of the secret.
    assert _open(blob, _hkdf(secret, "kek-wrap"), V2_AAD) == kek
    assert registration["recovery_signing_pk"] == bytes(SigningKey(_hkdf(secret, "ed25519")).verify_key).hex()
    assert admin.db.get_meta("org_recovery_signing_pk") == registration["recovery_signing_pk"]
    assert admin.db.get_meta("org_recovery_pk") == bytes(PrivateKey(_hkdf(secret, "x25519")).public_key).hex()
    assert len({secret, *(_hkdf(secret, purpose) for purpose in PURPOSES)}) == 4


def test_a_new_desktop_setup_recovers_and_syncs(team, tmp_path):  # noqa: F811
    url, db, admin, admin_client, _, _ = team
    shares = admin.setup_org_recovery(threshold=2, shares=3)
    admin_client.store_org_recovery(
        pending_states.org_recovery_registration(admin.db), admin.current_auth_proof(PASSWORD)
    )
    admin.lock()
    secret = reconstruct_secret(shares[1:])

    recovered = Vault(tmp_path / "admin")
    recovered.org_recovery(shares[1:], RECOVERED)
    recovered.lock()
    recovered.unlock(RECOVERED)
    try:
        client = _client(recovered, url)
        assert client.push()["conflicts"] == []  # the version 2 key proved the reset
        assert (pending_states.key_change_journal(recovered.db) or None) is None
        assert _recover(recovered, url, RECOVERED)["user_id"] == recovered.db.get_meta("user_id")
        # The server blob was re-wrapped under the version 2 wrap key.
        assert _open(_stored_blob(db), _hkdf(secret, "kek-wrap"), V2_AAD) == bytes(recovered.dek_mgr._kek)
    finally:
        recovered.lock()


def _legacy_setup(vault: Vault) -> tuple[list, dict]:
    """What setup_org_recovery wrote before R16-L4 (version 1): the secret is
    the X25519 key, the Ed25519 seed and the blob's AEAD key."""
    key = PrivateKey.generate()
    secret = bytes(key)
    kek = bytes(vault.dek_mgr._kek)
    signing_pk = bytes(SigningKey(secret).verify_key).hex()
    server_blob = {
        "wrapped_kek": _v1_wrap(kek, secret).hex(), "recovery_signing_pk": signing_pk,
        "threshold": 2, "total_shares": 3, "key_epoch": int(vault.db.get_meta("key_epoch") or "0"),
    }
    db = vault.db
    db.set_meta("org_recovery_pk", bytes(key.public_key).hex())
    db.set_meta("org_recovery_signing_pk", signing_pk)
    db.set_meta("org_recovery_wrapped_kek", SealedBox(key.public_key).encrypt(kek).hex())
    db.set_meta("org_recovery_stale", "0")
    db.set_meta("org_recovery_threshold", "2")
    db.set_meta("org_recovery_shares", "3")
    db.set_meta_json("org_recovery_server_wrap", server_blob)
    db.conn.commit()
    return split_secret(secret, 2, 3), server_blob


def test_a_version_1_setup_still_recovers_and_syncs(team, tmp_path):  # noqa: F811
    url, db, admin, admin_client, _, _ = team
    shares, server_blob = _legacy_setup(admin)
    admin_client.store_org_recovery(server_blob, admin.current_auth_proof(PASSWORD))
    admin.lock()
    secret = reconstruct_secret(shares[:2])

    recovered = Vault(tmp_path / "admin")
    recovered.org_recovery(shares[:2], RECOVERED)
    recovered.lock()
    recovered.unlock(RECOVERED)
    try:
        client = _client(recovered, url)
        assert client.push()["conflicts"] == []  # the version 1 key proved the reset
        assert (pending_states.key_change_journal(recovered.db) or None) is None
        status = client._request("GET", "/api/org-recovery/status")
        assert status["recovery_signing_pk"] == server_blob["recovery_signing_pk"] and not status["stale"]
        # Still version 1: the web rebuilds the same secret and opens it.
        assert _open(_stored_blob(db), secret, V1_AAD) == bytes(recovered.dek_mgr._kek)
    finally:
        recovered.lock()


# ── The page: the same keys, and a version 1 recovery still found ──

PAGE = "var API_BASE = '';\n"


@requires_node
def test_the_page_derives_the_same_keys_as_the_desktop():
    secret = bytes(range(32))
    out = _run_source(PAGE + _function("orgRecoveryKeys"), f"""
      (async () => {{
        const secret = hex('{secret.hex()}');
        const v2 = await orgRecoveryKeys(secret, 2, sodium);
        const v1 = await orgRecoveryKeys(secret, 1, sodium);
        return {{
          v2: [bytesToHex(v2.wrapKey), bytesToHex(v2.signing.publicKey), Buffer.from(v2.aad).toString()],
          v1: [bytesToHex(v1.wrapKey), bytesToHex(v1.signing.publicKey), Buffer.from(v1.aad).toString()],
          secretKept: bytesToHex(secret),
        }};
      }})()
    """)
    assert out["v2"] == [
        _hkdf(secret, "kek-wrap").hex(), bytes(SigningKey(_hkdf(secret, "ed25519")).verify_key).hex(),
        V2_AAD.decode(),
    ]
    assert out["v1"] == [secret.hex(), bytes(SigningKey(secret).verify_key).hex(), V1_AAD.decode()]
    assert out["secretKept"] == secret.hex()  # the shares' secret is not zeroed under the caller


@requires_node
@pytest.mark.parametrize("known", [2, 1])
def test_the_page_finds_the_blob_of_either_version(known):
    secret = os.urandom(32)
    pks = {
        2: bytes(SigningKey(_hkdf(secret, "ed25519")).verify_key).hex(),
        1: bytes(SigningKey(secret).verify_key).hex(),
    }
    out = _run_source(PAGE + _function("orgRecoveryKeys") + "\n" + _function("fetchOrgRecoveryBlob"), f"""
      (async () => {{
        const asked = [];
        fetch = async (url) => {{
          const pk = url.split('recovery_signing_pk=')[1];
          asked.push(pk);
          const found = pk === '{pks[known]}';
          return {{ ok: found, status: found ? 200 : 404 }};
        }};
        const {{ recoveryKeys, blobResp }} = await fetchOrgRecoveryBlob(hex('{secret.hex()}'), sodium);
        return {{ asked, version: recoveryKeys.version, ok: blobResp.ok,
                  pk: bytesToHex(recoveryKeys.signing.publicKey) }};
      }})()
    """)
    assert out["ok"] and out["version"] == known and out["pk"] == pks[known]
    assert out["asked"] == ([pks[2]] if known == 2 else [pks[2], pks[1]])
