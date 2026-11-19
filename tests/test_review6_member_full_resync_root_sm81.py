"""Stateful test finding SM81: a full resync took a team member's root away.

A member's desktop sees no top-level node on the server: its own root never
goes up (idea #24) and the admins' root is not shared with it. The full resync
(after a tombstone GC passed its checkpoint, or a restored server) set the
vault's root mark to the server's top-level node, i.e. to nothing, so the
member's root became a plain folder and new folders had no root to go under.
The root it still holds stays the root.
"""

from __future__ import annotations

from sezam.vault import revocation
from sezam.vault.crud import Vault
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_member_key_from_own_envelope_sm46 import _invite
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def test_member_full_resync_keeps_the_own_root(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    admin_client = _client(laptop, url)
    shared = _folder(laptop)
    admin_client.push()
    bob_id = _invite(url, admin_client, tmp_path, monkeypatch, "bob")
    revocation.grant_member(laptop, admin_client, bob_id, shared, confirm_fingerprint=lambda _f: True)

    bob = Vault(tmp_path / "bob")
    bob.unlock(PASSWORD)
    try:
        root = bob.db.get_meta("root_node_id")
        mine = bob.create_node("Mine")
        _client(bob, url).full_resync(confirmed=True)

        assert bob.db.get_meta("root_node_id") == root
        later = bob.create_node("Later")
        parents = {n["id"]: n["parent_id"] for n in bob.db.fetchall("SELECT id, parent_id FROM nodes")}
        assert parents[mine] == root and parents[later] == root
    finally:
        bob.lock()
        laptop.lock()
        phone.lock()


def test_member_with_nothing_shared_keeps_an_empty_root(server, tmp_path, monkeypatch):  # noqa: F811
    """The run that found it: nothing shared, so no top-level node on the server."""
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    admin_client = _client(laptop, url)
    _invite(url, admin_client, tmp_path, monkeypatch, "bob")

    bob = Vault(tmp_path / "bob")
    bob.unlock(PASSWORD)
    try:
        root = bob.db.get_meta("root_node_id")
        _client(bob, url).full_resync(confirmed=True)
        assert bob.db.get_meta("root_node_id") == root
    finally:
        bob.lock()
        laptop.lock()
        phone.lock()
