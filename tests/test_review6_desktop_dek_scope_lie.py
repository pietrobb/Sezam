"""Review main@d615826 run 149: the server's DEK scope label set a key's role.

The label is unsigned, yet the desktop pull stored it: a folder key the server
labelled 'root' or 'audit' on its way to a second device became one more root
or audit key there (get_root_dek / get_audit_dek take the first such row, so
top-level folders or audit details could be sealed under a key every member of
that folder holds), and a key the device already held took any label the
server sent with a newer version of it.
"""

from __future__ import annotations

import pytest

from sezam import cli
from sezam.vault.sync_client import SyncClient
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _two_devices


def _scope(vault, dek_id):
    return vault.db.fetchone("SELECT scope FROM deks WHERE id = ?", (dek_id,))["scope"]


@pytest.mark.parametrize("label", ["root", "audit", "tier2", "personal", "share"])
def test_a_new_folder_key_stays_a_folder_key_whatever_its_label(server, tmp_path, label):  # noqa: F811
    # Run 151: 'tier2' on a folder key made a tier-2 entry in that folder
    # reuse the folder key every member holds (crud._tier2_entry_dek) and
    # left the folder bound to its parent's key on a fresh device.
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    team = laptop.create_node("TEAM")
    team_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (team,))["dek_id"]
    entry = laptop.create_entry(team, "pin", [{"key": "pin", "value": "1"}])
    _client(laptop, url).push()
    next(o for o in db._storage["vault_objects"] if o["id"] == team_dek)["dek_scope"] = label

    _client(phone, url).pull()
    assert _scope(phone, team_dek) == "folder"
    assert phone.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (team,))["dek_id"] == team_dek
    phone.update_entry(entry, tier=2)
    entry_dek = phone.db.fetchone("SELECT dek_id FROM entries WHERE id = ?", (entry,))["dek_id"]
    assert entry_dek != team_dek
    assert _scope(phone, entry_dek) == "tier2"
    laptop.lock()
    phone.lock()


@pytest.mark.parametrize("label", ["tier2", "personal"])
def test_a_relabelled_folder_key_is_not_replaced_by_a_later_tier2_key(server, tmp_path, label):  # noqa: F811
    # A folder key stored as 'tier2' did not count as the folder's own, so the
    # next tier-2 key pulled for the folder became the folder key: new items
    # there were sealed under a key only the tier-2 entry's holders need.
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    team = laptop.create_node("TEAM")
    team_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (team,))["dek_id"]
    _client(laptop, url).push()
    next(o for o in db._storage["vault_objects"] if o["id"] == team_dek)["dek_scope"] = label
    _client(phone, url).pull()

    entry = laptop.create_entry(team, "pin", [{"key": "pin", "value": "1"}], tier=2)
    tier2_dek = laptop.db.fetchone("SELECT dek_id FROM entries WHERE id = ?", (entry,))["dek_id"]
    assert tier2_dek != team_dek
    _client(laptop, url).push()
    _client(phone, url).pull()
    assert phone.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (team,))["dek_id"] == team_dek
    assert _scope(phone, tier2_dek) == "tier2"
    laptop.lock()
    phone.lock()


@pytest.mark.parametrize("label", ["folder", "tier2", "root"])
def test_a_personal_folder_key_is_personal_whatever_its_label(server, tmp_path, label):  # noqa: F811
    # The role comes from the signed meta: only a personal root's meta is
    # sealed under its own key.
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    mine = laptop.create_personal_folder("Moje")
    mine_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (mine,))["dek_id"]
    _client(laptop, url).push()
    next(o for o in db._storage["vault_objects"] if o["id"] == mine_dek)["dek_scope"] = label

    _client(phone, url).pull()
    assert _scope(phone, mine_dek) == "personal"
    assert phone.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (mine,))["dek_id"] == mine_dek
    assert phone.read_node(mine)["name"] == "Moje"
    laptop.lock()
    phone.lock()


def test_a_tier2_key_pulled_after_its_folder_key_is_still_tier2(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    team = laptop.create_node("TEAM")
    team_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (team,))["dek_id"]
    entry = laptop.create_entry(team, "pin", [{"key": "pin", "value": "1"}], tier=2)
    tier2_dek = laptop.db.fetchone("SELECT dek_id FROM entries WHERE id = ?", (entry,))["dek_id"]
    _client(laptop, url).push()

    _client(phone, url).pull()
    assert phone.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (team,))["dek_id"] == team_dek
    assert _scope(phone, tier2_dek) == "tier2"
    assert phone.get_field_value(entry, "pin") == "1"
    laptop.lock()
    phone.lock()


@pytest.mark.parametrize("dek_order", ["as_sent", "reversed"])
def test_the_server_order_of_a_folders_keys_does_not_pick_its_own(server, tmp_path, monkeypatch, dek_order):  # noqa: F811
    # Run 155: the folder key and the tier-2 key both name the folder; the
    # first one in the (unsigned) pull order became the folder's own key.
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    team = laptop.create_node("TEAM")
    team_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (team,))["dek_id"]
    plain = laptop.create_entry(team, "plain", [{"key": "pin", "value": "0"}])
    entry = laptop.create_entry(team, "pin", [{"key": "pin", "value": "1"}], tier=2)
    tier2_dek = laptop.db.fetchone("SELECT dek_id FROM entries WHERE id = ?", (entry,))["dek_id"]
    _client(laptop, url).push()

    order = SyncClient._order_pulled_objects

    def lying_order(objects):
        ordered = order(objects)
        if dek_order == "reversed":
            deks = [o for o in ordered if o.get("object_type") == "dek"]
            ordered = deks[::-1] + [o for o in ordered if o.get("object_type") != "dek"]
        return ordered

    monkeypatch.setattr(SyncClient, "_order_pulled_objects", staticmethod(lying_order))
    _client(phone, url).pull()
    assert phone.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (team,))["dek_id"] == team_dek
    assert _scope(phone, team_dek) == "folder"
    assert _scope(phone, tier2_dek) == "tier2"
    assert phone.get_field_value(plain, "pin") == "0"
    assert phone.get_field_value(entry, "pin") == "1"
    laptop.lock()
    phone.lock()


def _audit_and_root_keys(url, db, tmp_path):
    """A laptop and a phone of one account, both pushed: the phone's audit
    key and the account root key are on the server, naming no folder."""
    laptop, phone = _two_devices(url, tmp_path)
    _client(phone, url).push()
    _client(laptop, url).pull()
    on_server = {o["id"] for o in db._storage["vault_objects"]}
    audit = next(r["id"] for r in phone.db.fetchall("SELECT id FROM deks WHERE scope = 'audit'")
                 if r["id"] in on_server)
    root = laptop.db.fetchone(
        "SELECT dek_id FROM nodes WHERE id = ?", (laptop.db.get_meta("root_node_id"),))["dek_id"]
    assert root in on_server
    return laptop, phone, audit, root


@pytest.mark.parametrize("label", ["root", "personal", "tier2", "bogus"])
def test_another_devices_audit_key_stays_an_audit_key(server, tmp_path, label):  # noqa: F811
    # Stateful test SM82: an audit key of the same account names no folder,
    # and the label made it one more root key on the next device.
    url, db = server
    laptop, phone, audit, _root = _audit_and_root_keys(url, db, tmp_path)
    next(o for o in db._storage["vault_objects"] if o["id"] == audit)["dek_scope"] = label
    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, PASSWORD)
    assert _scope(tablet, audit) == "audit"
    for vault in (laptop, phone, tablet):
        vault.lock()


@pytest.mark.parametrize("label", ["audit", "personal", "tier2"])
def test_the_root_key_stays_the_root_key(server, tmp_path, label):  # noqa: F811
    # Labelled audit it could seal audit details (the first 'audit' row is
    # taken once a full resync left this device without its own).
    url, db = server
    laptop, phone, _audit, root = _audit_and_root_keys(url, db, tmp_path)
    next(o for o in db._storage["vault_objects"] if o["id"] == root)["dek_scope"] = label
    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, PASSWORD)
    assert tablet.db.get_meta("root_node_id") == laptop.db.get_meta("root_node_id")
    assert _scope(tablet, root) == "root"
    for vault in (laptop, phone, tablet):
        vault.lock()


@pytest.mark.parametrize("label", ["personal", "tier2", "root"])
def test_a_key_this_device_holds_keeps_its_label(server, tmp_path, label):  # noqa: F811
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    team = laptop.create_node("TEAM")
    team_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (team,))["dek_id"]
    _client(laptop, url).push()
    client = _client(phone, url)
    client.pull()
    assert _scope(phone, team_dek) == "folder"

    row = phone.db.fetchone("SELECT encrypted_dek, version FROM deks WHERE id = ?", (team_dek,))
    with phone.db.transaction():
        client._apply_dek(team_dek, team, bytes(row["encrypted_dek"]), row["version"] + 1,
                          {"scope": label})
    assert _scope(phone, team_dek) == "folder"
    laptop.lock()
    phone.lock()
