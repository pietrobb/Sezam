"""Review 7c10379 H4, desktop: folders a read-only member wrote below the root.

Before b8c3cb8 the server let any member write a folder directly below the
shared root, sealed with the root's shared key, and items in it, which every
colleague's desktop showed as the company's own ('IT - new VPN login').
Such folders are still on the server, and a lying server can serve them
again. The desktop now applies a folder or item directly below a top-level
folder only when its signer could write it there (this account, an admin,
a member with a write grant, or - a folder - one sealed with a key of the
author's own), and nothing below a folder it left out.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.request

import pytest

import server.app.routers.sync as server_sync
from sezam import cli
from sezam.models import new_ulid
from sezam.vault.sync_client import SyncClient
from sezam.vault.sync_writers import IGNORED_WRITES_META, WRITES_AUDITED_META
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)
from tests.test_review6_web_member_personal_folder import sealed
from tests.test_server_spec import _create_regular_user, _sign_sync_object


def _post(url, path, body, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url + path, json.dumps(body).encode(), headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _login(url, sk, username):
    challenge = _post(url, "/api/auth/challenge", {"username": username})["challenge"]
    signature = sk.sign(bytes.fromhex(challenge)).signature.hex()
    return _post(url, "/api/auth/verify", {
        "username": username, "challenge": challenge, "signature": signature,
    })["token"]


def _server_base(url, token, obj_id) -> dict:
    """The server's current copy of obj_id as the base an update names (none for a new one)."""
    req = urllib.request.Request(
        url + "/api/sync?since_commit_seq=0", headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        objects = json.loads(resp.read())["objects"]
    current = next((o for o in objects if o["id"] == obj_id), None)
    if current is None:
        return {}
    return {"base_version": current["version"], "base_payload_hash": current["payload_hash"]}


def _push(url, token, sk, obj_id, kind, parent, payload, version=1):
    digest = hashlib.sha256(payload).hexdigest()
    result = _post(url, "/api/sync", {"atomic_batch": False, "objects": [{
        "id": obj_id, "object_type": kind, "payload": base64.b64encode(payload).decode(),
        "parent_ref": parent, "version": version, "is_deleted": 0, "payload_hash": digest,
        "signature": _sign_sync_object(sk, obj_id, kind, parent, None, 0, version, digest),
        "write_policy": "owner_only",
        **(_server_base(url, token, obj_id) if version > 1 else {}),
    }]}, token)
    assert len(result["accepted"]) == 1, result
    return result


def _forged_payloads(phone, root):
    """Folder and item sealed with the root's shared key, as the member made them."""
    folder = phone.create_node("IT - nove VPN prihlasenie", parent_id=root, create_dek=False)
    entry = phone.create_entry(folder, "VPN", [{"key": "password", "value": "phish"}])
    node_meta = bytes(phone.db.fetchone(
        "SELECT encrypted_meta FROM nodes WHERE id = ?", (folder,))["encrypted_meta"])
    row = phone.db.fetchone("SELECT encrypted_meta, encrypted_data FROM entries WHERE id = ?", (entry,))
    meta, data = bytes(row["encrypted_meta"]), bytes(row["encrypted_data"])
    return folder, node_meta, entry, len(meta).to_bytes(4, "big") + meta + data


@pytest.fixture
def forged(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    root = laptop.db.get_meta("root_node_id")
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    folder, folder_payload, entry, entry_payload = _forged_payloads(phone, root)
    phone.lock()

    alice = new_ulid()
    sk, _ = _create_regular_user(db._storage, alice, "alice")
    token = _login(url, sk, "alice")
    # The server before b8c3cb8 (or a lying one) takes the member's folder.
    monkeypatch.setattr(server_sync, "_has_write_authority", _always)
    _push(url, token, sk, folder, "node", root, folder_payload)
    _push(url, token, sk, entry, "entry", folder, entry_payload)
    personal_dek = new_ulid()
    _push(url, token, sk, personal_dek, "dek", None, b"k" * 72)
    personal = new_ulid()
    _push(url, token, sk, personal, "node", root, sealed(personal_dek))
    own_item, shared_key_item = new_ulid(), new_ulid()
    own_meta = sealed(personal_dek)
    _push(url, token, sk, own_item, "entry", personal, len(own_meta).to_bytes(4, "big") + own_meta + b"d")
    # Sealed with the shared root key inside her personal folder: readable by
    # every colleague, so the same phishing one level down.
    _push(url, token, sk, shared_key_item, "entry", personal, entry_payload)
    items = (entry, own_item, shared_key_item)
    yield url, laptop, root, folder, items, personal, (alice, token, sk)
    laptop.lock()


async def _always(*_args, **_kwargs):
    return True


def _names(vault, parent):
    return {node["name"] for node in vault.list_nodes(parent)}


def test_desktop_does_not_apply_a_members_folder_sealed_with_the_shared_key(forged, tmp_path):
    url, laptop, root, folder, (entry, own_item, shared_key_item), personal, (_alice, token, sk) = forged
    result = _client(laptop, url).pull()

    assert result["skipped"] == 3
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (folder,)) is None
    assert laptop.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (entry,)) is None
    assert "IT - nove VPN prihlasenie" not in _names(laptop, root)
    # The member's personal folder (sealed with her own key) is applied, and
    # in it what is sealed with her key, not what is sealed with the shared one.
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (personal,)) is not None
    assert laptop.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (own_item,)) is not None
    assert laptop.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (shared_key_item,)) is None
    assert set(laptop.db.get_meta_json(IGNORED_WRITES_META)) == {folder, entry, shared_key_item}

    # What she adds to the left-out folder later is left out as well.
    later = new_ulid()
    _push(url, token, sk, later, "entry", folder, len(b"m").to_bytes(4, "big") + b"m" + b"d")
    assert _client(laptop, url).pull()["skipped"] == 1
    assert laptop.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (later,)) is None

    # A new device and a full resync leave them out too.
    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, PASSWORD)
    assert tablet.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (folder,)) is None
    assert "IT - nove VPN prihlasenie" not in _names(tablet, root)
    tablet.lock()
    _client(laptop, url).full_resync(confirmed=True)
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (folder,)) is None
    assert laptop.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (later,)) is None
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (personal,)) is not None
    assert laptop.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (own_item,)) is not None
    assert laptop.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (shared_key_item,)) is None


def _applied_by_an_old_client(laptop, url, folder, monkeypatch):
    """The forgeries as a desktop from before this check applied them."""
    laptop.db.execute("DELETE FROM vault_meta WHERE key = ?", (WRITES_AUDITED_META,))
    with monkeypatch.context() as patch:
        patch.setattr(SyncClient, "_unauthorized_writes", lambda self, objects, full=False: set())
        _client(laptop, url).pull()
    laptop.db.execute("DELETE FROM vault_meta WHERE key = ?", (WRITES_AUDITED_META,))
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (folder,)) is not None


def _only_the_honest_writes_left(laptop, root, folder, entry, own_item, shared_key_item, personal):
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (folder,)) is None
    assert laptop.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (entry,)) is None
    assert laptop.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (shared_key_item,)) is None
    assert "IT - nove VPN prihlasenie" not in _names(laptop, root)
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (personal,)) is not None
    assert laptop.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (own_item,)) is not None


def test_the_next_pull_removes_forgeries_an_older_client_applied(forged, monkeypatch):
    """Capability run 174: a delta pull never brings them again."""
    url, laptop, root, folder, (entry, own_item, shared_key_item), personal, _alice = forged
    _applied_by_an_old_client(laptop, url, folder, monkeypatch)

    _client(laptop, url).pull()
    _only_the_honest_writes_left(laptop, root, folder, entry, own_item, shared_key_item, personal)
    assert laptop.db.get_meta(WRITES_AUDITED_META) == "1"
    _client(laptop, url).pull()  # once is enough, and the checkpoint still holds
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (folder,)) is None


def test_a_full_resync_removes_forgeries_an_older_client_applied(forged, monkeypatch):
    """Capability run 174: the forged ids are on the server, so prune kept them."""
    url, laptop, root, folder, (entry, own_item, shared_key_item), personal, _alice = forged
    _applied_by_an_old_client(laptop, url, folder, monkeypatch)
    laptop.db.set_meta(WRITES_AUDITED_META, "1")  # only the full resync judges them

    _client(laptop, url).full_resync(confirmed=True)
    _only_the_honest_writes_left(laptop, root, folder, entry, own_item, shared_key_item, personal)


def test_desktop_applies_what_a_member_with_a_write_grant_wrote_below_the_root(forged):
    url, laptop, root, folder, (entry, _own, _shared), _personal, (alice, _token, _sk) = forged
    # A write share on a key of the top-level folder: the server's write_acl.
    shared_key = new_ulid()
    laptop.db.execute(
        "INSERT INTO deks (id, node_id, scope, encrypted_dek, version) VALUES (?, ?, 'folder', ?, 1)",
        (shared_key, root, b"\x00" * 72),
    )
    laptop.db.execute(
        "INSERT INTO access_envelopes (id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, 'write', ?)",
        (new_ulid(), shared_key, alice, laptop.db.get_meta("user_id"), b"\x00" * 72),
    )
    assert _client(laptop, url).pull()["skipped"] == 0
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (folder,)) is not None
    assert laptop.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (entry,)) is not None
