"""Review 688edcb V4: an archived (leaked) identity key vouches only for what
was committed before its rotation.

After `sezam rotate-identity` the old key stays in every client's key ring
so the records it signed keep verifying. But the ring had no bound: whoever
holds the leaked key and the server (a compromised server is the case
signatures exist for) could sign a new DEK envelope "from the admin", and a
member would open the folder with the attacker's DEK and write under it. The
server now records the last commit_seq the old key could have signed
(``retired_seq``) and the old key's own authorization of the rotation; the
desktop, the web (all of app.js in node) and the mobile client (dart test)
accept an archived key only for objects up to that seq, and a desktop pins
the first bound it saw so the server cannot stretch it later.
"""

from __future__ import annotations

import hashlib

import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from ulid import ULID

from sezam.crypto.envelope_crypto import create_envelope
from sezam.vault.crud import Vault
from sezam.vault.revocation import grant_member
from sezam.vault.sync_client import SyncClient, key_rotation_message
from tests.test_cross_client_password_change import _web_login
from tests.test_grant_folder_access import _envelopes, _readable_passwords, _yes, team  # noqa: F401
from tests.test_identity_rotation import _rotate, _user
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401


def _hex(value) -> str:
    return value if isinstance(value, str) else bytes(value).hex()


def _forge_envelope(db, admin_id: str, member_id: str, dek_id: str, old_signer, old_box_sk):
    """What the server does with the leaked key: a fresh envelope sealing its
    own DEK for the member, signed by the archived admin key."""
    member = _user(db, member_id)
    payload = create_envelope(b"\x42" * 32, old_box_sk, bytes.fromhex(_hex(member["encryption_pk"])))
    payload_hash = hashlib.sha256(payload).hexdigest()
    object_id = str(ULID())
    counter = db._storage["commit_counter"][0]
    commit_seq = counter["next_seq"]
    counter["next_seq"] += 1
    canonical = SyncClient._build_signature_payload(
        id=object_id, object_type="envelope", parent_ref=dek_id, target_user_id=member_id,
        is_deleted=0, version=1, payload_hash=payload_hash,
    )
    [template] = _envelopes(db, member_id)
    row = dict(template)
    row.update(
        id=object_id, payload=payload, payload_hash=payload_hash, version=1,
        commit_seq=commit_seq, is_deleted=0, owner_id=admin_id, signature_user_id=admin_id,
        client_signature=old_signer.sign(canonical).signature,
    )
    db._storage["vault_objects"].append(row)
    return object_id


def _rotated_team(team, monkeypatch):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes)
    ops_dek_id, _ = admin.dek_mgr.get_dek_for_node(folders["Ops"])
    old_signer = SigningKey(bytes(admin.keypair.to_nacl_signing_key()))
    old_box_sk = bytes(PrivateKey(bytes(admin.keypair.encryption_sk)))
    assert _rotate(admin, monkeypatch).exit_code == 0
    return url, db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk


def _bob_desktop(tmp_path, url):
    bob = Vault(tmp_path / "bob")
    bob.unlock(PASSWORD)
    return bob, _client(bob, url)


def test_server_keeps_and_serves_the_rotation_authorization_and_bound(team, monkeypatch):  # noqa: F811
    url, db, admin_id, bob_id, _, old_signer, _ = _rotated_team(team, monkeypatch)
    [archive] = db._storage["user_key_archives"]
    served = _client(team[2], url)._request("GET", f"/api/users/{admin_id}/keys", auth=True)
    [entry] = served["archived_keys"]
    assert entry["signing_pk"] == old_signer.verify_key.encode().hex()
    assert entry["authorization_signature"] == _hex(archive["authorization_signature"])
    # The bound sits between what the old key signed and the rotation push.
    admin_seqs = sorted(
        o["commit_seq"] for o in db._storage["vault_objects"]
        if (o.get("signature_user_id") or o.get("owner_id")) == admin_id
    )
    assert admin_seqs[0] <= entry["retired_seq"] < admin_seqs[-1]
    message = key_rotation_message(
        admin_id, old_signer.verify_key.encode(), bytes.fromhex(entry["encryption_pk"]),
        bytes.fromhex(served["signing_pk"]), bytes.fromhex(served["encryption_pk"]),
    )
    old_signer.verify_key.verify(message, bytes.fromhex(entry["authorization_signature"]))


def test_member_desktop_rejects_an_envelope_the_leaked_key_signed_after_rotation(
    team, monkeypatch, tmp_path  # noqa: F811
):
    url, db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk = _rotated_team(
        team, monkeypatch
    )
    forged = _forge_envelope(db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk)
    bob, client = _bob_desktop(tmp_path, url)
    try:
        # Before: the archived key verified it, and the member took the
        # attacker's DEK for the shared folder.
        with pytest.raises(RuntimeError, match=forged):
            client.pull()
        # What the old key signed before the rotation still verifies.
        db._storage["vault_objects"] = [
            o for o in db._storage["vault_objects"] if o["id"] != forged
        ]
        retired_seq = db._storage["user_key_archives"][0]["retired_seq"]
        old_key_signed = [
            o["id"] for o in db._storage["vault_objects"]
            if o["object_type"] == "entry" and o["parent_ref"] == team[5]["Ops"]
            and o["commit_seq"] <= retired_seq
        ]
        assert client.pull()["pulled"] > 0
        assert old_key_signed and all(
            bob.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (entry_id,))
            for entry_id in old_key_signed
        )
    finally:
        bob.lock()


def test_desktop_pins_the_bound_so_the_server_cannot_stretch_it(
    team, monkeypatch, tmp_path  # noqa: F811
):
    url, db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk = _rotated_team(
        team, monkeypatch
    )
    bob, client = _bob_desktop(tmp_path, url)
    try:
        client.pull()
        [archive] = db._storage["user_key_archives"]
        archive["retired_seq"] = 10**9
        forged = _forge_envelope(db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk)
        with pytest.raises(RuntimeError, match=forged):
            client.pull()
        # A second process of the same vault keeps the pin too.
        with pytest.raises(RuntimeError, match=forged):
            _client(bob, url).pull()
    finally:
        bob.lock()


def test_a_forged_rotation_authorization_drops_the_archived_key(team, monkeypatch):  # noqa: F811
    url, db, admin_id, *_ = _rotated_team(team, monkeypatch)
    response = _client(team[2], url)._request("GET", f"/api/users/{admin_id}/keys", auth=True)
    current_signing = bytes.fromhex(response["signing_pk"])
    current_encryption = bytes.fromhex(response["encryption_pk"])
    ring = SyncClient._key_ring_from_response(
        admin_id, current_signing, current_encryption, response
    )
    assert len(ring) == 2
    response["archived_keys"][0]["authorization_signature"] = "00" * 64
    assert SyncClient._key_ring_from_response(
        admin_id, current_signing, current_encryption, response
    ) == (current_signing,)


def test_member_web_rejects_the_forged_envelope(team, monkeypatch):  # noqa: F811
    url, db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk = _rotated_team(
        team, monkeypatch
    )
    honest = _web_login(url, "bob", PASSWORD, {})
    assert honest["error"] is None, honest
    assert _readable_passwords(honest) == {"vpn": "ops-pw"}

    forged = _forge_envelope(db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk)
    member = _web_login(url, "bob", PASSWORD, {})
    assert member["error"] is not None and forged in str(member["error"]), member
    assert _readable_passwords(member) == {}


def test_admin_desktop_delta_rejects_new_records_under_the_old_key(team, monkeypatch):  # noqa: F811
    admin = team[2]
    url, db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk = _rotated_team(
        team, monkeypatch
    )
    fresh = SyncClient(admin.db, url, admin.keypair, admin_id)
    fresh.set_dek_manager(admin.dek_mgr)
    fresh.pull()
    forged = _forge_envelope(db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk)
    with pytest.raises(RuntimeError, match=forged):
        fresh.pull()
