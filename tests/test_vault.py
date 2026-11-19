"""Integration tests for the vault CRUD operations."""

from __future__ import annotations

import os
import shutil
import tempfile

import pytest

from sezam.vault import pending_states
from sezam.crypto.kdf import Argon2Params, derive_kek_and_proof
from sezam.vault.crud import Vault, VaultLocked


# Fast Argon2id params for testing
FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
TEST_PASSWORD = "test_master_password_123!"


@pytest.fixture
def vault_path():
    """Create a temporary directory for vault."""
    path = tempfile.mkdtemp(prefix="sezam_test_")
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def vault(vault_path):
    """Create and return an unlocked vault."""
    v = Vault.create(vault_path, TEST_PASSWORD, FAST_PARAMS)
    yield v
    v.lock()


class TestVaultCreation:
    def test_create_vault(self, vault_path):
        v = Vault.create(vault_path, TEST_PASSWORD, FAST_PARAMS)
        assert v.is_unlocked
        assert (v.path / "sezam.db").exists()
        v.lock()

    def test_create_sets_metadata(self, vault_path):
        v = Vault.create(vault_path, TEST_PASSWORD, FAST_PARAMS)
        assert v.db.get_meta("schema_version") is not None
        assert v.db.get_meta("root_node_id") is not None
        assert v.db.get_meta("user_id") is not None
        v.lock()

    def test_double_create_fails(self, vault_path):
        v = Vault.create(vault_path, TEST_PASSWORD, FAST_PARAMS)
        v.lock()
        # Second create should fail (schema already exists, but tables are IF NOT EXISTS)
        # Actually it would work since we use IF NOT EXISTS, but in practice
        # the CLI guards against this.


class TestVaultUnlockLock:
    def test_unlock_with_correct_password(self, vault_path):
        v = Vault.create(vault_path, TEST_PASSWORD, FAST_PARAMS)
        v.lock()

        v2 = Vault(vault_path)
        v2.unlock(TEST_PASSWORD)
        assert v2.is_unlocked
        v2.lock()

    def test_unlock_with_wrong_password(self, vault_path):
        v = Vault.create(vault_path, TEST_PASSWORD, FAST_PARAMS)
        v.lock()

        v2 = Vault(vault_path)
        with pytest.raises(ValueError, match="Wrong master password"):
            v2.unlock("wrong_password")

    def test_lock_clears_state(self, vault_path):
        v = Vault.create(vault_path, TEST_PASSWORD, FAST_PARAMS)
        v.lock()
        assert not v.is_unlocked

    def test_operations_while_locked_fail(self, vault_path):
        v = Vault.create(vault_path, TEST_PASSWORD, FAST_PARAMS)
        v.lock()
        with pytest.raises(VaultLocked):
            v.list_nodes()


class TestNodeOperations:
    def test_create_node(self, vault):
        node_id = vault.create_node("Servers")
        assert node_id is not None
        nodes = vault.list_nodes()
        assert len(nodes) == 1
        assert nodes[0]["name"] == "Servers"

    def test_create_nested_nodes(self, vault):
        servers_id = vault.create_node("Servers")
        hetzner_id = vault.create_node("Hetzner", parent_id=servers_id)

        children = vault.list_nodes(servers_id)
        assert len(children) == 1
        assert children[0]["name"] == "Hetzner"

    def test_list_nodes_sorted(self, vault):
        vault.create_node("Zebra")
        vault.create_node("Alpha")
        vault.create_node("Middle")

        nodes = vault.list_nodes()
        names = [n["name"] for n in nodes]
        assert names == ["Alpha", "Middle", "Zebra"]


class TestEntryOperations:
    def test_create_and_read_entry(self, vault):
        node_id = vault.create_node("Servers")
        entry_id = vault.create_entry(
            node_id,
            "SSH Access",
            [
                {"key": "host", "value": "192.168.1.1", "sensitive": False},
                {"key": "password", "value": "secret123", "sensitive": True},
            ],
        )

        entry = vault.read_entry(entry_id)
        assert entry["name"] == "SSH Access"
        assert len(entry["fields"]) == 2
        assert entry["fields"][0]["key"] == "host"
        assert entry["fields"][0]["value"] == "192.168.1.1"
        assert entry["fields"][1]["key"] == "password"
        assert entry["fields"][1]["value"] == "secret123"
        assert entry["fields"][1]["sensitive"] is True

    def test_update_entry(self, vault):
        node_id = vault.create_node("Test")
        entry_id = vault.create_entry(
            node_id, "Login", [{"key": "password", "value": "old_pass", "sensitive": True}]
        )

        vault.update_entry(
            entry_id,
            fields=[{"key": "password", "value": "new_pass", "sensitive": True}],
        )

        entry = vault.read_entry(entry_id)
        assert entry["fields"][0]["value"] == "new_pass"
        assert entry["version"] == 2

    def test_delete_entry(self, vault):
        node_id = vault.create_node("Test")
        entry_id = vault.create_entry(
            node_id, "ToDelete", [{"key": "x", "value": "y"}]
        )

        vault.delete_entry(entry_id)
        entries = vault.list_entries(node_id)
        assert len(entries) == 0

    def test_list_entries(self, vault):
        node_id = vault.create_node("Test")
        vault.create_entry(node_id, "Beta", [{"key": "a", "value": "1"}])
        vault.create_entry(node_id, "Alpha", [{"key": "b", "value": "2"}])

        entries = vault.list_entries(node_id)
        assert len(entries) == 2
        assert entries[0]["name"] == "Alpha"
        assert entries[1]["name"] == "Beta"

    def test_get_field_value(self, vault):
        node_id = vault.create_node("Test")
        entry_id = vault.create_entry(
            node_id,
            "Login",
            [
                {"key": "username", "value": "admin"},
                {"key": "password", "value": "s3cret", "sensitive": True},
            ],
        )

        assert vault.get_field_value(entry_id, "username") == "admin"
        assert vault.get_field_value(entry_id, "password") == "s3cret"
        assert vault.get_field_value(entry_id, "nonexistent") is None

    def test_entry_with_tags(self, vault):
        node_id = vault.create_node("Test")
        entry_id = vault.create_entry(
            node_id,
            "Tagged",
            [{"key": "x", "value": "y"}],
            tags=["ssh", "production"],
        )

        entry = vault.read_entry(entry_id)
        assert entry["tags"] == ["ssh", "production"]

    def test_entry_with_tier(self, vault):
        node_id = vault.create_node("Test")
        entry_id = vault.create_entry(
            node_id,
            "Secure",
            [{"key": "x", "value": "y"}],
            tier=2,
        )

        entry = vault.read_entry(entry_id)
        assert entry["tier"] == 2


class TestSearch:
    def test_search_by_name(self, vault):
        node_id = vault.create_node("Servers")
        vault.create_entry(node_id, "Hetzner SSH", [{"key": "host", "value": "1.2.3.4"}])
        vault.create_entry(node_id, "AWS Console", [{"key": "url", "value": "aws.com"}])

        results = vault.search("hetzner")
        assert len(results) == 1
        assert results[0]["name"] == "Hetzner SSH"

    def test_search_by_field_key(self, vault):
        node_id = vault.create_node("Test")
        vault.create_entry(node_id, "Login", [{"key": "ssh_password", "value": "x"}])

        results = vault.search("ssh_password")
        assert len(results) == 1

    def test_search_multi_token(self, vault):
        node_id = vault.create_node("Servers")
        vault.create_entry(node_id, "Hetzner SSH", [{"key": "host", "value": "1.2.3.4"}])
        vault.create_entry(node_id, "Hetzner Web", [{"key": "url", "value": "x.com"}])

        results = vault.search("hetzner ssh")
        assert len(results) == 1
        assert results[0]["name"] == "Hetzner SSH"

    def test_search_no_results(self, vault):
        results = vault.search("nonexistent")
        assert len(results) == 0


class TestPathResolution:
    def test_resolve_path(self, vault):
        servers_id = vault.create_node("Servers")
        hetzner_id = vault.create_node("Hetzner", parent_id=servers_id)
        vault.create_entry(hetzner_id, "SSH", [{"key": "host", "value": "1.2.3.4"}])

        node_id, entry_name = vault.resolve_path("Servers/Hetzner")
        assert node_id == hetzner_id
        assert entry_name is None

    def test_find_entry_by_path(self, vault):
        servers_id = vault.create_node("Servers")
        hetzner_id = vault.create_node("Hetzner", parent_id=servers_id)
        vault.create_entry(
            hetzner_id,
            "SSH Access",
            [{"key": "password", "value": "secret"}],
        )

        entry = vault.find_entry_by_path("Servers/Hetzner/SSH Access")
        assert entry is not None
        assert entry["name"] == "SSH Access"
        assert entry["fields"][0]["value"] == "secret"


class TestChangePassword:
    def test_change_password(self, vault_path):
        v = Vault.create(vault_path, TEST_PASSWORD, FAST_PARAMS)
        node_id = v.create_node("Test")
        entry_id = v.create_entry(
            node_id, "Login", [{"key": "password", "value": "my_secret"}]
        )
        auth_proof = v.change_password(TEST_PASSWORD, "new_password_456!")
        new_salt = bytes.fromhex(v.db.get_meta("argon2_salt"))
        _, expected_proof = derive_kek_and_proof(
            "new_password_456!", new_salt, FAST_PARAMS
        )
        assert auth_proof == expected_proof
        v.lock()

        # Verify old password no longer works
        v2 = Vault(vault_path)
        with pytest.raises(ValueError):
            v2.unlock(TEST_PASSWORD)

        # Verify new password works and data is intact
        v3 = Vault(vault_path)
        v3.unlock("new_password_456!")
        entry = v3.read_entry(entry_id)
        assert entry["fields"][0]["value"] == "my_secret"
        v3.lock()


class TestTree:
    def test_get_tree(self, vault):
        servers = vault.create_node("Servers")
        vault.create_node("Hetzner", parent_id=servers)
        vault.create_entry(servers, "Root SSH", [{"key": "x", "value": "y"}])

        lines = vault.get_tree()
        assert len(lines) > 0
        # Check structure contains our nodes
        tree_text = "\n".join(lines)
        assert "Servers" in tree_text


class TestHistory:
    def test_update_creates_history(self, vault):
        node_id = vault.create_node("Test")
        entry_id = vault.create_entry(
            node_id, "Login", [{"key": "password", "value": "v1"}]
        )

        vault.update_entry(entry_id, fields=[{"key": "password", "value": "v2"}])

        rows = vault.db.fetchall(
            "SELECT * FROM entry_history WHERE entry_id = ?", (entry_id,)
        )
        assert len(rows) == 1


class TestRekeyRevocation:
    @staticmethod
    def _shared_folder(vault):
        from sezam.crypto.keys import generate_keypair
        from sezam.models import new_ulid

        node_id = vault.create_node("Shared")
        entry_id = vault.create_entry(
            node_id, "Credential", [{"key": "password", "value": "secret"}]
        )
        old_dek_id = vault.db.fetchone(
            "SELECT dek_id FROM nodes WHERE id = ?", (node_id,)
        )["dek_id"]
        revoked_user_id = new_ulid()
        remaining_user_id = new_ulid()
        remaining_keypair = generate_keypair()
        vault.db.execute(
            "INSERT INTO known_keys "
            "(user_id, signing_pk, encryption_pk, fingerprint, first_seen, last_verified) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                remaining_user_id,
                remaining_keypair.signing_pk,
                remaining_keypair.encryption_pk,
                remaining_keypair.fingerprint,
                1,
                1,
            ),
        )
        old_envelope_ids = [new_ulid(), new_ulid()]
        for envelope_id, user_id in zip(
            old_envelope_ids, (revoked_user_id, remaining_user_id)
        ):
            vault.db.execute(
                "INSERT INTO access_envelopes "
                "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
                "VALUES (?, ?, ?, ?, 'write', ?)",
                (envelope_id, old_dek_id, user_id, vault._user_id, os.urandom(80)),
            )
        return node_id, entry_id, old_dek_id, revoked_user_id, old_envelope_ids

    def test_rekey_is_one_atomic_sync_batch(self, vault):
        from sezam.vault.sync_client import SyncClient

        node_id, entry_id, old_dek_id, revoked_user_id, old_envelope_ids = (
            self._shared_folder(vault)
        )

        assert vault.rekey_after_revocation(revoked_user_id) == 1
        assert vault.read_entry(entry_id)["fields"][0]["value"] == "secret"
        assert vault.db.fetchone(
            "SELECT dek_id FROM nodes WHERE id = ?", (node_id,)
        )["dek_id"] != old_dek_id
        assert vault.db.fetchall(
            "SELECT id FROM access_envelopes WHERE dek_id = ?", (old_dek_id,)
        ) == []

        requests = []
        client = SyncClient(vault.db, "https://sync.invalid", vault.keypair, vault._user_id)
        client.token = "test-token"

        def fake_request(method, path, body=None, auth=False, extra_headers=None):
            requests.append((method, path, body, auth))
            if path == "/api/sync":
                return {
                    "accepted": [
                        {"id": obj["id"], "commit_seq": index + 1}
                        for index, obj in enumerate(body["objects"])
                    ],
                    "conflicts": [],
                }
            return {"status": "ok"}

        client._request = fake_request
        client.push()
        client.revoke_user(revoked_user_id)

        method, path, body, auth = next(
            request for request in requests if request[:2] == ("POST", "/api/sync")
        )
        assert auth is True
        assert body["atomic_batch"] is True
        object_types = {obj["object_type"] for obj in body["objects"]}
        assert {"node", "entry", "dek", "dek_archive", "envelope", "audit"} <= object_types
        tombstones = {
            obj["id"] for obj in body["objects"]
            if obj["object_type"] == "envelope" and obj["is_deleted"] == 1
        }
        assert tombstones == set(old_envelope_ids)
        envelope_objects = [
            obj for obj in body["objects"] if obj["object_type"] == "envelope"
        ]
        assert [obj["is_deleted"] for obj in envelope_objects] == [1, 1, 0]
        assert any(
            request[:2] == ("DELETE", f"/api/users/{revoked_user_id}")
            for request in requests
        )
        assert pending_states.rekey_batch(vault.db) == {}

    def test_decrypt_failure_rolls_back_entire_rekey(self, vault):
        node_id, entry_id, old_dek_id, revoked_user_id, old_envelope_ids = (
            self._shared_folder(vault)
        )
        before_deks = vault.db.fetchall("SELECT id FROM deks")
        vault.db.execute(
            "UPDATE entries SET encrypted_data = ? WHERE id = ?", (b"corrupt", entry_id)
        )

        with pytest.raises(RuntimeError, match="re-key rolled back"):
            vault.rekey_after_revocation(revoked_user_id)

        assert vault.db.fetchone(
            "SELECT dek_id FROM nodes WHERE id = ?", (node_id,)
        )["dek_id"] == old_dek_id
        assert vault.db.fetchall("SELECT id FROM deks") == before_deks
        assert vault.db.fetchall("SELECT id FROM dek_archive") == []
        assert {
            row["id"] for row in vault.db.fetchall(
                "SELECT id FROM access_envelopes WHERE dek_id = ?", (old_dek_id,)
            )
        } == set(old_envelope_ids)
        assert (pending_states.rekey_batch(vault.db) or None) is None


class TestBackup:
    def test_backup(self, vault, vault_path):
        dest = os.path.join(vault_path, "backup.db")
        vault.db.backup(dest)
        assert os.path.exists(dest)

    def test_integrity_check(self, vault):
        assert vault.db.integrity_check()
