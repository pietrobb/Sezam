"""Review c02cc47 R17-N1 (INV-2/INV-3): a key voucher names the whole signed
message, not only (id, version, payload_hash).

A retired key's signature counted for any served object whose (id, version,
payload_hash) a voucher list named. The object's signature covers more: its
type, parent, target, tombstone flag and (through the key ring) its signer. A
server holding the leaked retired key signed a vouched version again with
another parent or as deleted, and every client took it: a private folder
"moved" under a team folder was folded onto the team key.
"""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from sezam import cli
from sezam.vault.revocation import grant_member
from sezam.vault.team_migration import found_team_log
from sezam.vault.sync_client import SyncClient
from sezam.vault.sync_common import TofuKeyChangeError
from tests.test_archived_key_bound_v4 import _bob_desktop, _rotated_team
from tests.test_grant_folder_access import _yes, team  # noqa: F401
from tests.test_identity_rotation import _rotate
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_inv3_replay_over_tombstone import _capture, _live_entries, _serve_again
from tests.test_review_web import pytestmark  # noqa: F401


def _re_sign(db, folder_id: str, old_signer, **changed) -> dict:
    """The server signs a vouched version of an entry in ``folder_id`` again
    with the leaked retired key, with other signed fields."""
    row = next(
        o for o in db._storage["vault_objects"]
        if o["object_type"] == "entry" and o["parent_ref"] == folder_id and not o["is_deleted"]
    )
    row.update(changed)
    canonical = SyncClient._build_signature_payload(
        id=row["id"], object_type=row["object_type"], parent_ref=row["parent_ref"],
        target_user_id=row.get("target_user_id"), is_deleted=row["is_deleted"],
        version=row["version"], payload_hash=row["payload_hash"],
    )
    row["client_signature"] = old_signer.sign(canonical).signature
    return row


@pytest.mark.parametrize("change", ["deleted", "parent"])
def test_a_retired_key_cannot_re_sign_a_vouched_version_with_other_fields(
    team, monkeypatch, tmp_path, change  # noqa: F811
):
    url, db, admin_id, bob_id, ops_dek_id, old_signer, _ = _rotated_team(team, monkeypatch)
    folders = team[5]
    changed = {"is_deleted": 1} if change == "deleted" else {"parent_ref": folders["HR"]}
    forged = _re_sign(db, folders["Ops"], old_signer, **changed)
    bob, client = _bob_desktop(tmp_path, url)
    try:
        with pytest.raises(RuntimeError, match=forged["id"]):
            client.pull()
    finally:
        bob.lock()


@pytest.mark.parametrize("legacy", [False, True], ids=["held_signed", "held before held_signed"])
@pytest.mark.parametrize("change", ["deleted", "parent"])
def test_the_signer_s_own_key_on_other_fields_of_a_held_version_is_an_equivocation(
    server, tmp_path, change, legacy  # noqa: F811
):
    """against_held compared the payload hash alone: the same version with
    another parent or as deleted was the copy held ("same"), and the device
    then held (and would vouch for) a message it never kept. A copy held
    from before held_signed (an upgraded vault) compares its own parent and
    tombstone flag too."""
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    root = laptop.db.get_meta("root_node_id")
    other = laptop.create_node("Other", root)
    entry = laptop.create_entry(root, "E", [{"key": "password", "value": "s", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    phone_client = _client(phone, url)
    held = _capture(phone_client, entry)
    forged = {**held, **({"is_deleted": 1} if change == "deleted" else {"parent_ref": other})}
    signer = SigningKey(bytes(laptop.keypair.to_nacl_signing_key()))
    forged["client_signature"] = signer.sign(SyncClient._build_signature_payload(
        id=forged["id"], object_type=forged["object_type"], parent_ref=forged["parent_ref"],
        target_user_id=forged.get("target_user_id"), is_deleted=forged["is_deleted"],
        version=forged["version"], payload_hash=forged["payload_hash"],
    )).signature.hex()
    if legacy:
        with phone.db.transaction():
            phone.db.execute("DELETE FROM held_signed WHERE object_id = ?", (entry,))
    try:
        _serve_again(phone_client, forged, floor_lie=False)
        result = phone_client.pull()
        assert [e["id"] for e in result.get("equivocations", [])] == [entry], result
        assert entry in _live_entries(phone)
        assert phone.db.fetchone("SELECT node_id FROM entries WHERE id = ?", (entry,))[0] == root
        # Only the message held is held: no voucher of this device names the other.
        assert len(_digests(phone, entry)) == (0 if legacy else 1)
    finally:
        laptop.lock()
        phone.lock()


def _digests(vault, obj_id: str) -> set[str]:
    return {r["digest"] for r in vault.db.fetchall("SELECT digest FROM held_signed WHERE object_id = ?", (obj_id,))}


@pytest.mark.parametrize("retired", [True, False], ids=["retired key", "current key"])
def test_a_folder_a_retired_key_put_below_a_team_folder_is_not_folded(
    team, tmp_path, retired  # noqa: F811
):
    """fold_unlogged_folder_keys resealed what a private folder's key sealed
    under the team folder's key once the folder sat below it, also when the
    copy that put it there came signed by a (leaked) retired key."""
    url, db, admin, admin_client, bob_id, folders = team
    admin_client.approve_user(bob_id)
    grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes)
    found_team_log(admin, admin_client, confirm_fingerprint=_yes)
    admin_client.pull()
    hr, ops = folders["HR"], folders["Ops"]
    own_key = admin.dek_mgr.get_dek_for_node(hr)[0]
    version = admin.db.fetchone("SELECT version FROM nodes WHERE id = ?", (hr,))["version"]
    with admin.db.transaction():
        # What applying the served copy left: HR below Ops, held as signed so.
        admin.db.execute("UPDATE nodes SET parent_id = ? WHERE id = ?", (ops, hr))
        admin.db.execute("DELETE FROM held_signed WHERE object_id = ?", (hr,))
        admin.db.execute(
            "INSERT INTO held_signed (object_id, version, payload_hash, digest, retired) VALUES (?, ?, ?, ?, ?)",
            (hr, version, "00" * 32, "11" * 32, int(retired)),
        )
    admin_client.fold_unlogged_folder_keys()
    folded = admin.dek_mgr.get_dek_for_node(hr)[0]
    if retired:
        assert folded == own_key, "a retired key's move resealed a private folder to the team"
    else:
        assert folded == admin.dek_mgr.get_dek_for_node(ops)[0]


def test_a_held_version_served_with_other_fields_is_an_equivocation(
    team, monkeypatch, tmp_path  # noqa: F811
):
    """Bob held the version before the rotation; the server serves it again
    with other signed fields under the retired key."""
    url, db, admin, admin_client, bob_id, folders = team
    admin_client.approve_user(bob_id)
    grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes)
    bob, client = _bob_desktop(tmp_path, url)
    try:
        client.pull()
    finally:
        bob.lock()
    old_signer = SigningKey(bytes(admin.keypair.to_nacl_signing_key()))
    assert _rotate(admin, monkeypatch).exit_code == 0
    forged = _re_sign(db, folders["Ops"], old_signer, is_deleted=1)
    bob.unlock(PASSWORD)
    try:
        client = _client(bob, url)
        with pytest.raises(TofuKeyChangeError) as raised:
            client.pull()
        client.confirm_tofu_key_change(raised.value, raised.value.new_fingerprint)
        with pytest.raises(RuntimeError, match=forged["id"] + ".*equivocation"):
            client.full_resync(confirmed=True)
    finally:
        bob.lock()
