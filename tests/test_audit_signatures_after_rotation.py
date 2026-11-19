"""Idea #4: audit records signed before a key rotation stay verifiable.

The audit log is append-only, so after a user rotates the identity key every
older record carries a signature of the archived key. A client verifying
pulled audit records only against the *current* key rejected all of them
(the pull fails for good); one trusting any key the server lists would let
the server forge history. The archived key is trusted only through the
rotation certificate its successor signed (/api/users/:id/keys).
"""

from __future__ import annotations

import base64
import json

import pytest

from sezam.crypto.kdf import Argon2Params
from sezam.crypto.keys import generate_keypair
from sezam.vault.crud import Vault
from sezam.vault.sync_client import SyncClient
from tests.test_review_web import _run
from tests.test_review_web import pytestmark as _node_mark

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
AUDIT_ROWS = (
    "SELECT id, parent_ids, actor_id, action, encrypted_details, timestamp, signature "
    "FROM audit_log ORDER BY timestamp"
)



def key_rotation_message(user_id, old_signing, old_encryption, new_signing, new_encryption):
    """server/app/auth.py:key_rotation_message, signed by the successor key."""
    return (
        b"sezam-key-rotation-v1" + user_id.encode().ljust(26, b"\x00")[:26]
        + old_signing + old_encryption + new_signing + new_encryption
    )


@pytest.fixture
def actor(tmp_path):
    """Alice's vault: audit records signed by her original (now archived) key."""
    v = Vault.create(tmp_path / "alice", "alice-before-rotation!", FAST_PARAMS)
    v.create_entry(v.create_node("Servers"), "ssh", [{"key": "password", "value": "x"}])
    yield v
    v.lock()


@pytest.fixture
def reader(tmp_path):
    """Bob's vault, pulling Alice's audit records."""
    v = Vault.create(tmp_path / "bob", "bob-reads-the-audit!", FAST_PARAMS)
    yield v
    v.lock()


def _archive(user_id, old, successor, signer=None):
    certificate = (signer or successor).to_nacl_signing_key().sign(key_rotation_message(
        user_id, old.signing_pk, old.encryption_pk,
        successor.signing_pk, successor.encryption_pk,
    )).signature
    return {
        "signing_pk": old.signing_pk.hex(),
        "encryption_pk": old.encryption_pk.hex(),
        "key_fingerprint": old.fingerprint,
        "archived_at": 1,
        "successor_signing_pk": successor.signing_pk.hex(),
        "rotation_signature": certificate.hex(),
    }


def _verify_all(reader, actor, current, archives) -> list[str]:
    client = SyncClient(reader.db, "https://sync.invalid", reader.keypair, reader._user_id)
    client.token = "t"
    client._request = lambda method, path, body=None, auth=False, extra_headers=None: {
        "signing_pk": current.signing_pk.hex(),
        "encryption_pk": current.encryption_pk.hex(),
        "archived_keys": archives,
    }
    verdicts = []
    for row in actor.db.fetchall(AUDIT_ROWS):
        try:
            client._verify_audit_payload(row["id"], client._serialize_audit_row(row))
            verdicts.append("ok")
        except ValueError:
            verdicts.append("rejected")
    return verdicts


def test_desktop_verifies_audit_signed_by_a_certified_archived_key(reader, actor):
    rotated = generate_keypair()
    verdicts = _verify_all(
        reader, actor, rotated, [_archive(actor._user_id, actor.keypair, rotated)]
    )
    assert len(verdicts) >= 2 and set(verdicts) == {"ok"}


def test_desktop_verifies_audit_across_two_rotations(reader, actor):
    middle, current = generate_keypair(), generate_keypair()
    verdicts = _verify_all(reader, actor, current, [
        _archive(actor._user_id, actor.keypair, middle),
        _archive(actor._user_id, middle, current),
    ])
    assert set(verdicts) == {"ok"}


@pytest.mark.parametrize("case", ["no-archive", "forged-certificate"])
def test_desktop_rejects_history_the_rotation_does_not_vouch_for(reader, actor, case):
    rotated = generate_keypair()
    archives = [] if case == "no-archive" else [
        _archive(actor._user_id, actor.keypair, rotated, signer=generate_keypair())
    ]
    assert set(_verify_all(reader, actor, rotated, archives)) == {"rejected"}


def test_desktop_reader_who_pinned_the_old_key_verifies_after_confirming(reader, actor):
    """The usual case: Bob synced with Alice before, so her old key is pinned.

    After her rotation the pull raises a TOFU change; Bob confirms the new
    fingerprint and the SAME client retries (cli.py `sezam pull`). The
    retry must still trust the archive the rotation certificate vouches for.
    """
    from sezam.vault.sync_client import TofuKeyChangeError

    old = actor.keypair
    reader.db.execute(
        "INSERT INTO known_keys (user_id, signing_pk, encryption_pk, fingerprint, "
        "first_seen, last_verified) VALUES (?, ?, ?, ?, 1, 1)",
        (actor._user_id, old.signing_pk, old.encryption_pk, old.fingerprint),
    )
    rotated = generate_keypair()
    client = SyncClient(reader.db, "https://sync.invalid", reader.keypair, reader._user_id)
    client.token = "t"
    client._request = lambda method, path, body=None, auth=False, extra_headers=None: {
        "signing_pk": rotated.signing_pk.hex(),
        "encryption_pk": rotated.encryption_pk.hex(),
        "archived_keys": [_archive(actor._user_id, old, rotated)],
    }
    rows = actor.db.fetchall(AUDIT_ROWS)
    with pytest.raises(TofuKeyChangeError) as raised:
        client._verify_audit_payload(rows[0]["id"], client._serialize_audit_row(rows[0]))
    client.confirm_tofu_key_change(raised.value, raised.value.new_fingerprint)

    verdicts = []
    for row in rows:
        try:
            client._verify_audit_payload(row["id"], client._serialize_audit_row(row))
            verdicts.append("ok")
        except ValueError:
            verdicts.append("rejected")
    assert len(verdicts) >= 2 and set(verdicts) == {"ok"}


WEB_FUNCTIONS = [
    "hexToBytes", "bytesToBase64", "parseCanonicalAuditRecord", "buildAuditCanonical", "verifyAuditGraph",
    "keyRotationMessage", "verifyArchivedKeyChain", "getUserSigningPks",
]


def _web_verdict(actor, current, archives) -> str:
    objects = {}
    for row in actor.db.fetchall(AUDIT_ROWS):
        payload = SyncClient._serialize_audit_row(row)
        objects[row["id"]] = {
            "id": row["id"], "object_type": "audit", "version": 2, "is_deleted": 0,
            "owner_id": row["actor_id"], "payload": base64.b64encode(payload).decode(),
        }
    response = {
        "signing_pk": current.signing_pk.hex(),
        "encryption_pk": current.encryption_pk.hex(),
        "archived_keys": archives,
    }
    script = f"""
    (async () => {{
      btoa = value => Buffer.from(value, 'binary').toString('base64');
      state.userKeys = {{}}; state.userEncryptionKeys = {{}}; state.archivedKeyBounds = {{}};
      apiFetch = async () => ({json.dumps(response)});
      ensureSodium = async () => sodium;
      displayFingerprint = async (s, e) => ({{
        hex: bytesToHex(sodium.crypto_hash_sha256(new Uint8Array([...s, ...e]))),
      }});
      checkKnownKey = async () => 'same';
      tofuKeyChange = () => new Error('tofu');
      try {{ await verifyAuditGraph({json.dumps(objects)}, sodium); return 'ok'; }}
      catch (e) {{ return /invalid audit signature/.test(e.message) ? 'rejected' : e.message; }}
    }})()
    """
    return _run(WEB_FUNCTIONS, script)


@_node_mark
def test_web_verifies_audit_signed_by_a_certified_archived_key(actor):
    rotated = generate_keypair()
    assert _web_verdict(
        actor, rotated, [_archive(actor._user_id, actor.keypair, rotated)]
    ) == "ok"
    assert _web_verdict(actor, rotated, []) == "rejected"
    assert _web_verdict(actor, rotated, [
        _archive(actor._user_id, actor.keypair, rotated, signer=generate_keypair())
    ]) == "rejected"
