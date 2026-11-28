"""Review d615826 (server): re-storing the same org recovery key skipped the
password check, so a stolen identity key alone replaced the blob the shares
open. Without the password the server now wants the recovery key's own
signature; desktop and web sign the same bytes the server checks."""

from __future__ import annotations

import os

from nacl.signing import SigningKey, VerifyKey

from server.app.routers.recovery import org_recovery_rewrap_message as server_message
from sezam.vault.key_rotation import org_recovery_rewrap_message as desktop_message
from tests.test_review_web import _run, pytestmark  # noqa: F401


def test_web_rewrap_signature_verifies_on_the_server():
    seed = os.urandom(32)
    wrapped = os.urandom(72)
    user_id = "01JABCDEFGHJKMNPQRSTVWXYZ0"
    script = f"""
      const kp = sodium.crypto_sign_seed_keypair(hex('{seed.hex()}'));
      const msg = orgRecoveryRewrapMessage(
        '{user_id}', 7, 2, 3, hex('{wrapped.hex()}'));
      return [bytesToHex(msg), bytesToHex(sodium.crypto_sign_detached(msg, kp.privateKey))];
    """
    message_hex, signature_hex = _run(["orgRecoveryRewrapMessage"], f"(() => {{ {script} }})()")

    expected = server_message(user_id, 7, 2, 3, wrapped)
    assert bytes.fromhex(message_hex) == expected == desktop_message(user_id, 7, 2, 3, wrapped)
    VerifyKey(bytes(SigningKey(seed).verify_key)).verify(expected, bytes.fromhex(signature_hex))
