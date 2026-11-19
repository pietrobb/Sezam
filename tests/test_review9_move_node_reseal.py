"""Review 1141a20 (R9-E, M-DESK4, goal #361): move_node across the personal boundary.

A personal tree has one key, the owner's. ``move_node`` resealed only the
moved folder's name under the target's key: the folder kept pointing at the
personal key, and its items (and subfolders, history) stayed sealed with it.
Moved into a team folder, nobody else could read them (the team log does not
know that key; the server refuses such items in a team folder). Moved out of a
team folder into the personal tree, they stayed under the team key every
member of the folder holds. Now the moved subtree takes the target's key.
"""

from __future__ import annotations

import pytest
from nacl.exceptions import CryptoError

from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid
from sezam.vault import revocation
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _ops


def _sealed_with(vault, table: str, object_id: str, column: str = "encrypted_meta") -> str:
    row = vault.db.fetchone(f"SELECT {column} FROM {table} WHERE id = ?", (object_id,))
    return bytes_to_ulid(parse_envelope(bytes(row[column])).dek_id)


def _subtree_keys(vault, folder, child, entry, deep_entry) -> set[str]:
    return {
        vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"],
        vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (child,))["dek_id"],
        _sealed_with(vault, "nodes", child),
        _sealed_with(vault, "entries", entry),
        _sealed_with(vault, "entries", entry, "encrypted_data"),
        _sealed_with(vault, "entries", deep_entry),
        _sealed_with(vault, "entries", deep_entry, "encrypted_data"),
    }


def test_a_folder_moved_out_of_the_personal_tree_is_readable_by_the_target_folder_members(
    team, server  # noqa: F811
):
    _, admin, admin_client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    assert admin_client.push()["conflicts"] == []

    personal = admin.create_personal_folder("Mine")
    personal_key = admin.dek_mgr.get_dek_for_node(personal)[0]
    folder = admin.create_node("for-ops", parent_id=personal)
    child = admin.create_node("deeper", parent_id=folder)
    entry = admin.create_entry(folder, "vpn", [{"key": "password", "value": "vpn-pw"}])
    deep = admin.create_entry(child, "db", [{"key": "password", "value": "db-pw"}])
    admin.update_entry(entry, name="vpn")  # a history snapshot under the personal key
    assert admin_client.push()["conflicts"] == []

    admin.move_node(folder, ops)

    ops_key = admin.dek_mgr.get_dek_for_node(ops)[0]
    assert _subtree_keys(admin, folder, child, entry, deep) == {ops_key}
    assert not admin.db.fetchone(
        "SELECT 1 FROM entry_history WHERE entry_id IN (?, ?) AND dek_id = ?", (entry, deep, personal_key)
    )
    # The personal tree keeps its key and stays readable.
    assert admin.dek_mgr.get_dek_for_node(personal)[0] == personal_key
    assert admin.read_entry(entry)["fields"][0]["value"] == "vpn-pw"
    assert admin_client.push()["conflicts"] == []

    _confirm_founder(admin, bob)
    bob_client.pull()
    assert bob.read_entry(entry)["fields"][0]["value"] == "vpn-pw"
    assert bob.read_entry(deep)["fields"][0]["value"] == "db-pw"
    assert bob.read_node(child)["name"] == "deeper"
    # The personal key never went to Bob.
    assert not bob.db.fetchone("SELECT 1 FROM access_envelopes WHERE dek_id = ?", (personal_key,))
    with pytest.raises(CryptoError):
        bob.dek_mgr.unlock_dek(personal_key)


def test_a_team_folder_moved_into_the_personal_tree_leaves_the_team_key(team, server):  # noqa: F811
    _, admin, admin_client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    folder = admin.create_node("was-shared", parent_id=ops, create_dek=False)
    child = admin.create_node("deeper", parent_id=folder, create_dek=False)
    entry = admin.create_entry(folder, "vpn", [{"key": "password", "value": "vpn-pw"}])
    deep = admin.create_entry(child, "db", [{"key": "password", "value": "db-pw"}])
    personal = admin.create_personal_folder("Mine")
    assert admin_client.push()["conflicts"] == []

    admin.move_node(folder, personal)

    personal_key = admin.dek_mgr.get_dek_for_node(personal)[0]
    assert _subtree_keys(admin, folder, child, entry, deep) == {personal_key}
    assert admin.read_entry(deep)["fields"][0]["value"] == "db-pw"
    assert admin_client.push()["conflicts"] == []


def test_a_folder_without_its_own_key_takes_the_next_team_folders_key(team, server):  # noqa: F811
    _, admin, admin_client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    hr = admin.create_node("HR")
    revocation.grant_member(admin, admin_client, bob_id, hr, "read")
    folder = admin.create_node("was-ops", parent_id=ops, create_dek=False)
    child = admin.create_node("deeper", parent_id=folder, create_dek=False)
    entry = admin.create_entry(folder, "vpn", [{"key": "password", "value": "vpn-pw"}])
    deep = admin.create_entry(child, "db", [{"key": "password", "value": "db-pw"}])
    assert admin_client.push()["conflicts"] == []

    admin.move_node(folder, hr)

    assert _subtree_keys(admin, folder, child, entry, deep) == {admin.dek_mgr.get_dek_for_node(hr)[0]}
    assert admin_client.push()["conflicts"] == []
    _confirm_founder(admin, bob)
    bob_client.pull()
    assert bob.read_entry(deep)["fields"][0]["value"] == "db-pw"


def test_a_team_folder_of_the_log_does_not_go_into_a_personal_folder(team, server):  # noqa: F811
    _, admin, admin_client, bob, _ = team
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    revocation.grant_member(admin, admin_client, bob.db.get_meta("user_id"), ops, "read")
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "vpn-pw"}])
    personal = admin.create_personal_folder("Mine")
    tables = ("nodes", "entries", "deks", "entry_history")
    before = {t: [dict(r) for r in admin.db.fetchall(f"SELECT * FROM {t}")] for t in tables}
    with pytest.raises(ValueError, match="team folder cannot go into a personal folder"):
        admin.move_node(ops, personal)
    assert {t: [dict(r) for r in admin.db.fetchall(f"SELECT * FROM {t}")] for t in tables} == before
