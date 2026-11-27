"""Capability review run 677 on R17-N1 (goal #471): an identity rotation of a
vault upgraded from c02cc47 (no held_signed row) carried a served copy forward
under the new key when its version, payload hash and (folders and entries
only) parent matched the copy held. Type, target and tombstone flag were never
compared, nor the parent of a DEK, archived DEK or envelope: the old key's
signature on another message of a held version got a voucher of the new key.
"""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from sezam import cli, key_vouchers
from sezam.vault.sync_client import SyncClient
from tests.test_integration_client_server import _client, _vault, PASSWORD, server  # noqa: F401
from tests.test_review_web import pytestmark  # noqa: F401


def _forge(obj: dict, signer: SigningKey, **changed) -> dict:
    forged = {**obj, **changed}
    forged["signature"] = signer.sign(SyncClient._build_signature_payload(
        id=forged["id"], object_type=forged["object_type"], parent_ref=forged.get("parent_ref"),
        target_user_id=forged.get("target_user_id"), is_deleted=forged.get("is_deleted", 0),
        version=forged.get("version", 1), payload_hash=forged["payload_hash"],
    )).signature.hex()
    forged.pop("client_signature", None)
    return forged


@pytest.mark.parametrize("change", ["entry deleted", "entry as node", "dek parent"])
def test_a_rotation_of_an_upgraded_vault_vouches_only_the_copy_it_holds(
    server, tmp_path, change  # noqa: F811
):
    url, _db = server
    vault = _vault(tmp_path / "laptop", "admin")
    root = vault.db.get_meta("root_node_id")
    other = vault.create_node("Other", root)
    entry = vault.create_entry(root, "E", [{"key": "password", "value": "s", "sensitive": True}])
    cli._server_connect_flow(url, vault, PASSWORD)
    client = _client(vault, url)
    try:
        client.pull()
        with vault.db.transaction():  # a vault upgraded from before held_signed
            vault.db.execute("DELETE FROM held_signed")
        client = _client(vault, url)
        served = list(client._signed_objects())
        by_type = {}
        for obj in served:
            by_type.setdefault(obj["object_type"], obj)
        kind, field = change.split(" ", 1)
        target = next(o for o in served if o["id"] == entry) if kind == "entry" else by_type[kind]
        changed = {
            "deleted": {"is_deleted": 1},
            "as node": {"object_type": "node"},
            "parent": {"parent_ref": other if target.get("parent_ref") != other else root},
        }[field]
        old_pk = vault.keypair.signing_pk
        forged = _forge(target, SigningKey(bytes(vault.keypair.to_nacl_signing_key())), **changed)
        honest = key_vouchers.object_entry(target, client._user_id, old_pk)
        bad = key_vouchers.object_entry(forged, client._user_id, old_pk)
        assert honest != bad

        signed = []
        client._signed_objects = lambda: iter([forged if o["id"] == target["id"] else o for o in served])
        client._signed_lists = lambda entries: signed.extend(entries) or []
        client._rotation_authorizer = old_pk
        client._rotation_vouchers()
        assert bad not in signed, f"the new key vouched a {change} the device never held"
        # The rest it holds is still carried forward.
        others = [key_vouchers.object_entry(o, client._user_id, old_pk) for o in served if o is not target]
        assert set(others) <= set(signed)
    finally:
        vault.lock()


def test_a_rotation_of_an_upgraded_vault_carries_every_copy_it_holds(server, tmp_path):  # noqa: F811
    """The legacy comparison reads each type's signed fields as it was sent: a
    personal root's DEK names no folder (TL7), an entry its folder."""
    url, _db = server
    vault = _vault(tmp_path / "laptop", "admin")
    root = vault.db.get_meta("root_node_id")
    vault.create_node("Other", root)
    vault.create_entry(root, "E", [{"key": "password", "value": "s", "sensitive": True}])
    cli._server_connect_flow(url, vault, PASSWORD)
    try:
        _client(vault, url).pull()
        with vault.db.transaction():
            vault.db.execute("DELETE FROM held_signed")
        client = _client(vault, url)
        served = list(client._signed_objects())
        signed = []
        client._signed_lists = lambda entries: signed.extend(entries) or []
        client._rotation_authorizer = vault.keypair.signing_pk
        client._rotation_vouchers()
        expected = {key_vouchers.object_entry(o, client._user_id, vault.keypair.signing_pk) for o in served}
        assert {o["object_type"] for o in served} >= {"node", "entry", "dek", "audit"}
        assert set(signed) == expected
    finally:
        vault.lock()
