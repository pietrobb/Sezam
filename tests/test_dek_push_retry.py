"""Idea #3: a DEK counts as on the server only once the server took it.

Desktop used to stamp ``last_dek_push_ts`` while *collecting* the push, so a
push that then failed (network, 5xx, conflict) left root/audit/tier-2 DEKs,
which have no dirty node, never pushed again: other devices could not open
anything sealed with them. Tracking is per DEK and per version, written only
for DEKs the server accepted (or already holds at that version or newer).
"""

from __future__ import annotations

import pytest

from sezam.crypto.kdf import Argon2Params
from sezam.vault.crud import Vault
from sezam.vault.sync_client import SyncClient

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)


@pytest.fixture
def vault(tmp_path):
    v = Vault.create(tmp_path / "a", "dek-push-retry-pw!", FAST_PARAMS)
    yield v
    v.lock()


@pytest.fixture
def client(vault):
    folder = vault.create_node("Folder")
    vault.create_entry(folder, "t2", [{"key": "password", "value": "x"}], tier=2)
    client = SyncClient(vault.db, "https://sync.invalid", vault.keypair, vault._user_id)
    client.token = "test-token"
    client.set_dek_manager(vault.dek_mgr)
    return client


def _dek_ids(client) -> set[str]:
    return {o["id"] for o in client._collect_dirty_objects() if o["object_type"] == "dek"}


def _scopes(vault) -> dict[str, str]:
    return {row["id"]: row["scope"] for row in vault.db.fetchall("SELECT id, scope FROM deks")}


def _server(accept=lambda obj: True, conflicts=()):
    def request(method, path, body=None, auth=False, extra_headers=None):
        return {
            "accepted": [
                {"id": o["id"], "commit_seq": 1} for o in body["objects"] if accept(o)
            ],
            "conflicts": list(conflicts),
        }
    return request


def test_failed_push_leaves_every_dek_for_the_retry(vault, client):
    before = _dek_ids(client)
    assert set(_scopes(vault)[d] for d in before) >= {"root", "audit", "tier2"}

    def down(*args, **kwargs):
        raise RuntimeError("Network error: connection refused")

    client._request = down
    with pytest.raises(RuntimeError):
        client.push()
    assert _dek_ids(client) == before

    client._request = _server()
    client.push()
    assert _dek_ids(client) == set()


def test_only_the_deks_the_server_took_are_settled(vault, client):
    scopes = _scopes(vault)
    root = next(d for d, s in scopes.items() if s == "root")
    tier2 = next(d for d, s in scopes.items() if s == "tier2")
    version = vault.db.fetchone("SELECT version FROM deks WHERE id = ?", (tier2,))["version"]
    # Root DEK: no answer at all. Tier-2 DEK: the server holds an older version.
    client._request = _server(
        accept=lambda o: o["id"] not in {root, tier2},
        conflicts=[{"id": tier2, "server_version": version - 1}],
    )
    client.push()
    assert _dek_ids(client) == {root, tier2}

    client._request = _server()
    client.push()
    assert _dek_ids(client) == set()


def test_a_dek_the_server_already_holds_is_settled_by_its_conflict(vault, client):
    scopes = _scopes(vault)
    audit = next(d for d, s in scopes.items() if s == "audit")
    version = vault.db.fetchone("SELECT version FROM deks WHERE id = ?", (audit,))["version"]
    client._request = _server(
        accept=lambda o: o["id"] != audit,
        conflicts=[{"id": audit, "server_version": version}],
    )
    client.push()
    assert audit not in _dek_ids(client)


def test_a_new_version_of_a_pushed_dek_is_pushed_again(vault, client):
    client._request = _server()
    client.push()
    root = next(d for d, s in _scopes(vault).items() if s == "root")
    vault.db.execute("UPDATE deks SET version = version + 1 WHERE id = ?", (root,))
    assert _dek_ids(client) == {root}
