"""TL7 on the desktop: a member's personal folder is a personal root.

docs/DESIGN_TEAM_LOG.md §10. Real desktop clients against the real server.
Carol reads Ops (from the team log). Her personal folder goes up as a
top-level folder of her own key, not below a root: the server takes it, her
listings and paths show it among the root's folders, her second device does
not take it for the account root, and the admin never sees it.
"""

from __future__ import annotations

import pytest

from sezam import cli
from sezam.vault import trash
from sezam.vault.personal_root import is_personal_root
from sezam.vault.sync_writers import WRITER_ACCOUNTS_META
from sezam.vault.team_migration import found_team_log
from tests.test_integration_client_server import PASSWORD, _client, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, team  # noqa: F401  (fixture)
from tests.test_team_log_migration import org  # noqa: F401  (fixture)


def test_a_members_personal_folder_is_a_personal_root(org, server, tmp_path):  # noqa: F811
    db, admin, admin_client, _bob, _bob_client, carol, _ids, ops, _dan = org
    found_team_log(admin, admin_client, lambda _uid, _fp: True)
    _confirm_founder(admin, carol)
    carol_client = _client(carol, server[0])
    carol_client.pull()

    mine = carol.create_personal_folder("Moje")
    carol.create_entry(mine, "bank", [{"key": "password", "value": "p"}])
    conflicts = carol_client.push()["conflicts"]
    kinds = {r["id"]: r["object_type"] for r in carol.db.fetchall(
        "SELECT id, 'node' AS object_type FROM nodes UNION ALL SELECT id, 'entry' FROM entries "
        "UNION ALL SELECT id, 'dek:' || scope FROM deks")}
    # (a member's audit records are refused as 'admin only', as before)
    assert [(kinds[c["id"]], c["error"]) for c in conflicts if c["id"] in kinds] == []
    row = next(o for o in db._storage["vault_objects"] if o["id"] == mine)
    assert row["parent_ref"] is None and row["owner_id"] == carol.db.get_meta("user_id")

    root = carol.db.get_meta("root_node_id")
    assert root != mine and is_personal_root(carol.db, carol.dek_mgr, mine)
    assert "Moje" in [n["name"] for n in carol.list_nodes()]
    assert carol.find_entry_by_path("Moje/bank")["fields"][0]["value"] == "p"
    assert carol._build_node_path(mine) == "Moje"

    # Her second device opens the personal root but keeps the account's root.
    second = _vault(tmp_path / "carol2", "carol")
    _confirm_founder(admin, second)
    cli._server_connect_flow(server[0], second, PASSWORD)
    second_client = _client(second, server[0])
    second_client.pull()
    assert second.db.get_meta("root_node_id") != mine
    assert second.find_entry_by_path("Moje/bank")["fields"][0]["value"] == "p"
    second.lock()

    # The admin neither opens nor lists it, and keeps the org root.
    admin_root = admin.db.get_meta("root_node_id")
    admin_client.pull()
    assert admin.db.get_meta("root_node_id") == admin_root
    assert "Moje" not in [n["name"] for n in admin.list_nodes()]
    assert ops in [n["id"] for n in admin.list_nodes()]

    # A personal root makes no admin: what Carol writes below a top-level
    # folder of the organisation still needs a write grant on Bob's desktop.
    bob, bob_client = _bob, _bob_client
    _confirm_founder(admin, bob)
    bob_client.pull()
    writers = bob.db.get_meta_json(WRITER_ACCOUNTS_META)
    assert carol.db.get_meta("user_id") not in writers
    assert admin.db.get_meta("user_id") in writers


def _refused(client) -> list:
    # (a member's audit records are refused as 'admin only', as before)
    return [c for c in client.push()["conflicts"] if c["error"] != "admin only"]


def test_a_tier2_entry_goes_into_a_folder_of_its_own_key(org, server, tmp_path):  # noqa: F811
    """TL7: a tier-2 entry's own key is not in the log, so not in a team folder."""
    db, admin, admin_client, _bob, _bob_client, carol, _ids, ops, _dan = org
    old = admin.create_entry(ops, "trezor", [{"key": "pin", "value": "1"}], tier=2)
    assert _refused(admin_client) == []  # before the log, as in an older organisation
    found_team_log(admin, admin_client, lambda _uid, _fp: True)

    with pytest.raises(ValueError, match="tier-2"):
        admin.create_entry(ops, "nove", [{"key": "pin", "value": "2"}], tier=2)
    with pytest.raises(ValueError, match="tier-2"):
        admin.update_entry(old, fields=[{"key": "pin", "value": "3"}])
    plain = admin.create_entry(ops, "bezne", [{"key": "pin", "value": "4"}])
    with pytest.raises(ValueError, match="tier-2"):
        admin.update_entry(plain, tier=2)

    # Its way out: a personal folder.
    mine = admin.create_personal_folder("Moje")
    admin.move_entry(old, mine)
    assert admin.read_entry(old)["fields"][0]["value"] == "1"
    admin.create_entry(mine, "nove", [{"key": "pin", "value": "2"}], tier=2)
    assert _refused(admin_client) == []

    _confirm_founder(admin, carol)
    carol_client = _client(carol, server[0])
    carol_client.pull()
    hers = carol.create_personal_folder("Moje")
    pin = carol.create_entry(hers, "pin", [{"key": "pin", "value": "5"}], tier=2)
    assert _refused(carol_client) == []
    # Her second device reads it; the key that names no folder is the item's.
    second = _vault(tmp_path / "carol2", "carol")
    _confirm_founder(admin, second)
    cli._server_connect_flow(server[0], second, PASSWORD)
    _client(second, server[0]).pull()
    assert second.read_entry(pin)["fields"][0]["value"] == "5"
    key = carol.db.fetchone("SELECT dek_id FROM entries WHERE id = ?", (pin,))["dek_id"]
    assert second.db.fetchone("SELECT scope FROM deks WHERE id = ?", (key,))["scope"] == "tier2"
    second.lock()


def test_a_folder_below_a_personal_root_reaches_the_other_devices(org, server, tmp_path):  # noqa: F811
    """A folder below a personal root goes up readable, not only its name."""
    _db, admin, admin_client, _bob, _bob_client, carol, _ids, _ops, _dan = org
    found_team_log(admin, admin_client, lambda _uid, _fp: True)
    _confirm_founder(admin, carol)
    carol_client = _client(carol, server[0])
    carol_client.pull()
    mine = carol.create_personal_folder("Moje")
    sub = carol.create_node("Banky", parent_id=mine)
    deeper = carol.create_node("Stare", parent_id=sub)
    carol.create_entry(sub, "tatra", [{"key": "password", "value": "t"}])
    carol.create_entry(deeper, "vub", [{"key": "password", "value": "v"}])
    assert _refused(carol_client) == []

    second = _vault(tmp_path / "carol2", "carol")
    _confirm_founder(admin, second)
    cli._server_connect_flow(server[0], second, PASSWORD)
    second_client = _client(second, server[0])
    second_client.pull()
    assert second.find_entry_by_path("Moje/Banky/tatra")["fields"][0]["value"] == "t"
    assert second.find_entry_by_path("Moje/Banky/Stare/vub")["fields"][0]["value"] == "v"
    # ... and writes there, read back on the first device.
    second.create_entry(sub, "csob", [{"key": "password", "value": "c"}])
    assert _refused(second_client) == []
    second.lock()
    carol_client.pull()
    assert carol.find_entry_by_path("Moje/Banky/csob")["fields"][0]["value"] == "c"


def test_a_folder_key_the_server_never_took_is_folded_into_the_tree(
    org, server, tmp_path, monkeypatch,  # noqa: F811
):
    """An older desktop gave a folder below a personal root a key of its own."""
    _db, admin, admin_client, _bob, _bob_client, carol, _ids, _ops, _dan = org
    found_team_log(admin, admin_client, lambda _uid, _fp: True)
    _confirm_founder(admin, carol)
    carol_client = _client(carol, server[0])
    carol_client.pull()
    mine = carol.create_personal_folder("Moje")
    with monkeypatch.context() as m:
        m.setattr("sezam.vault.crud.in_personal_tree", lambda *_a: False)
        sub = carol.create_node("Banky", parent_id=mine)
        deeper = carol.create_node("Stare", parent_id=sub)
    tatra = carol.create_entry(sub, "tatra", [{"key": "password", "value": "t0"}])
    carol.update_entry(tatra, fields=[{"key": "password", "value": "t"}])  # a history snapshot
    gone = carol.create_entry(sub, "zrusene", [{"key": "password", "value": "x"}])
    carol.delete_entry(gone)
    carol.create_entry(deeper, "vub", [{"key": "password", "value": "v"}])
    stray = {carol.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (n,))["dek_id"] for n in (sub, deeper)}
    assert {c["id"] for c in _refused(carol_client)} == stray  # as before the fix

    carol.lock()
    carol.unlock(PASSWORD)
    carol_client = _client(carol, server[0])  # (the old one holds the zeroed signing key)
    tree_key = carol.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (mine,))["dek_id"]
    assert {carol.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (n,))["dek_id"]
            for n in (sub, deeper)} == {tree_key}
    assert not carol.db.fetchone(f"SELECT 1 FROM deks WHERE id IN ({','.join('?' * len(stray))})",
                                 tuple(stray))
    assert carol.find_entry_by_path("Moje/Banky/tatra")["fields"][0]["value"] == "t"
    assert {h["dek_id"] for h in carol.db.fetchall(
        "SELECT dek_id FROM entry_history WHERE entry_id = ?", (tatra,))} == {tree_key}
    (snap,) = trash.list_history(carol, tatra)
    assert trash.read_history(carol, tatra, snap["id"])[0]["value"] == "t0"
    assert _refused(carol_client) == []
    assert not carol.db.get_meta_json("refused_folder_deks")

    second = _vault(tmp_path / "carol2", "carol")
    _confirm_founder(admin, second)
    cli._server_connect_flow(server[0], second, PASSWORD)
    _client(second, server[0]).pull()
    assert second.find_entry_by_path("Moje/Banky/tatra")["fields"][0]["value"] == "t"
    assert second.find_entry_by_path("Moje/Banky/Stare/vub")["fields"][0]["value"] == "v"
    second.lock()
