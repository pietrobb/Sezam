"""Regressions for code review HEAD 2c7e809, section 2 (server trust model)."""

from __future__ import annotations

import hashlib
import os

from nacl.signing import SigningKey

from sezam.vault.sync_client import SyncClient, key_rotation_message as client_message
from server.app.auth import key_rotation_message as server_message
from tests.node_support import node_cmd

USER_ID = "01J00000000000000000000001"


def _key() -> tuple[SigningKey, bytes, bytes]:
    sk = SigningKey.generate()
    return sk, bytes(sk.verify_key), os.urandom(32)


def _archive(old, successor, cert: bytes | None) -> dict:
    _, old_sig, old_enc = old
    entry = {
        "signing_pk": old_sig.hex(),
        "encryption_pk": old_enc.hex(),
        "key_fingerprint": hashlib.sha256(old_sig + old_enc).hexdigest(),
        "archived_at": 1,
    }
    if cert is not None:
        entry["successor_signing_pk"] = successor[1].hex()
        entry["rotation_signature"] = cert.hex()
    return entry


def _certify(old, successor) -> bytes:
    return successor[0].sign(
        server_message(USER_ID, old[1], old[2], successor[1], successor[2])
    ).signature


def test_client_and_server_rotation_message_match():
    _, a_sig, a_enc = _key()
    _, b_sig, b_enc = _key()
    assert client_message(USER_ID, a_sig, a_enc, b_sig, b_enc) == server_message(
        USER_ID, a_sig, a_enc, b_sig, b_enc
    )


def test_key_ring_follows_certificate_chain():
    oldest, middle, current = _key(), _key(), _key()
    response = {"archived_keys": [
        # Deliberately out of order: the chain is resolved iteratively.
        _archive(oldest, middle, _certify(oldest, middle)),
        _archive(middle, current, _certify(middle, current)),
    ]}
    ring = SyncClient._key_ring_from_response(USER_ID, current[1], current[2], response)
    assert ring == (current[1], middle[1], oldest[1])


def test_server_cannot_inject_historical_keys():
    current, injected, attacker = _key(), _key(), _key()
    response = {"archived_keys": [
        _archive(injected, current, None),                         # no certificate
        _archive(injected, current, _certify(injected, attacker)),  # wrong signer
        _archive(injected, attacker, _certify(injected, attacker)),  # untrusted successor
    ]}
    # The third entry claims attacker as successor; it is signed by attacker,
    # but attacker is not in the trusted chain, so it must be ignored too.
    response["archived_keys"][2]["successor_signing_pk"] = attacker[1].hex()
    ring = SyncClient._key_ring_from_response(USER_ID, current[1], current[2], response)
    assert ring == (current[1],)


def test_certificate_is_bound_to_user_id():
    old, current = _key(), _key()
    cert = current[0].sign(
        server_message("01J0000000000000000OTHERUSR", old[1], old[2], current[1], current[2])
    ).signature
    response = {"archived_keys": [_archive(old, current, cert)]}
    ring = SyncClient._key_ring_from_response(USER_ID, current[1], current[2], response)
    assert ring == (current[1],)


def test_web_verifies_the_same_certificate_chain():
    import json
    import shutil
    import subprocess
    from pathlib import Path

    import pytest

    from tests.node_support import node_cmd

    node_cmd()  # skips without Node >= 24.7
    marker = "// Must match server/app/auth.py:key_rotation_message."
    src = (Path(__file__).resolve().parents[1] / "web" / "static" / "js" / "app.js").read_text(
        encoding="utf-8"
    )
    helpers = marker + src.split(marker, 1)[1].split("async function getUserSigningPks", 1)[0]
    id_start = src.index("function idBytes26(")
    helpers = src[id_start:src.index("\n}\n", id_start) + 3] + helpers

    oldest, middle, current, attacker = _key(), _key(), _key(), _key()
    candidates = [
        (oldest, middle, _certify(oldest, middle)),
        (middle, current, _certify(middle, current)),
        (attacker, current, _certify(attacker, attacker)),  # not signed by current
    ]
    data = {
        "current": [current[1].hex(), current[2].hex()],
        "candidates": [
            [old[1].hex(), old[2].hex(), succ[1].hex(), cert.hex()]
            for old, succ, cert in candidates
        ],
    }
    script = f"""
const nodeCrypto = require('crypto');
function hexToBytes(h) {{ return Uint8Array.from(Buffer.from(h, 'hex')); }}
function bytesToHex(b) {{ return Buffer.from(b).toString('hex'); }}
const _sodium = {{
  crypto_sign_verify_detached(sig, msg, pk) {{
    const key = nodeCrypto.createPublicKey({{
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(pk)]),
      format: 'der', type: 'spki',
    }});
    return nodeCrypto.verify(null, Buffer.from(msg), key, Buffer.from(sig));
  }},
}};
{helpers}
const data = {json.dumps(data)};
const candidates = data.candidates.map(([s, e, succ, cert]) => ({{
  signingPk: hexToBytes(s), encryptionPk: hexToBytes(e),
  successorHex: succ, certificate: hexToBytes(cert),
}}));
const keys = verifyArchivedKeyChain('{USER_ID}', hexToBytes(data.current[0]),
  hexToBytes(data.current[1]), candidates, _sodium);
console.log(JSON.stringify(keys.map(bytesToHex)));
"""
    out = subprocess.run([node_cmd(), "-e", script], check=True, capture_output=True, text=True)
    assert json.loads(out.stdout) == [current[1].hex(), middle[1].hex(), oldest[1].hex()]
