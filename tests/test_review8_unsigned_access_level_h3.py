"""Review main@a159e97 H3, desktop: the unsigned access_level outlived a lying server.

An envelope's access_level is not part of its signature. A server that
turned Carol's 'read' into 'write' had the desktop store 'write' on the next
pull, and the next re-key copied it into the envelope the admin sealed and
pushed: the escalation stayed after the server stopped lying. A missing
level counted as 'write' as well. Now an envelope made on this device keeps
the level it was made with, a missing one is 'read', and a new envelope
carries 'write' over only from an envelope made here.
"""

from __future__ import annotations

from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    _client,
    server,
)
from tests.test_rekey_rebase_review8 import _folder_shared_with_member
from tests.test_review6_abandon_rekey_keeps_grants import _pinned_member


def _server_envelopes(db, user_id):
    return [
        o for o in db._storage["vault_objects"]
        if o["object_type"] == "envelope" and o.get("target_user_id") == user_id
        and not o["is_deleted"]
    ]


def _lie_write(db, user_id):
    for obj in _server_envelopes(db, user_id):
        obj["access_level"] = "write"


def _carol_read(url, tmp_path, db):
    laptop, phone, folder, _entry, old_dek, bob = _folder_shared_with_member(url, tmp_path, db)
    carol_id, carol = _pinned_member(db, laptop)
    laptop.grant_folder_access(folder, carol_id, carol.encryption_pk, "read")
    assert _client(laptop, url).push()["conflicts"] == []
    assert {o["access_level"] for o in _server_envelopes(db, carol_id)} == {"read"}
    return laptop, phone, folder, old_dek, bob, carol_id


def _local_level(vault, user_id, dek_id):
    return vault.db.fetchone(
        "SELECT access_level FROM access_envelopes WHERE user_id = ? AND dek_id = ?",
        (user_id, dek_id),
    )["access_level"]


def test_a_servers_write_does_not_replace_the_level_this_device_granted(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, old_dek, bob, carol = _carol_read(url, tmp_path, db)
    _lie_write(db, carol)
    _client(laptop, url).pull()
    assert _local_level(laptop, carol, old_dek) == "read"

    assert laptop.rekey_after_revocation(bob) == 1
    assert _client(laptop, url).push()["conflicts"] == []
    new_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert new_dek != old_dek
    assert _local_level(laptop, carol, new_dek) == "read"
    assert {o["access_level"] for o in _server_envelopes(db, carol)} == {"read"}, (
        "the re-key sealed the server's 'write' into the admin's envelope"
    )
    laptop.lock()
    phone.lock()


def test_another_device_does_not_carry_a_pulled_write_into_its_re_key(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, old_dek, bob, carol = _carol_read(url, tmp_path, db)
    _lie_write(db, carol)
    _client(phone, url).pull()
    for row in laptop.db.fetchall("SELECT * FROM known_keys"):
        phone.db.execute(
            "INSERT OR IGNORE INTO known_keys (user_id, signing_pk, encryption_pk, fingerprint, "
            "first_seen, last_verified) VALUES (?, ?, ?, ?, ?, ?)",
            (row["user_id"], row["signing_pk"], row["encryption_pk"], row["fingerprint"],
             row["first_seen"], row["last_verified"]),
        )

    assert phone.rekey_after_revocation(bob) == 1
    assert _client(phone, url).push()["conflicts"] == []
    new_dek = phone.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert _local_level(phone, carol, new_dek) == "read"
    assert {o["access_level"] for o in _server_envelopes(db, carol)} == {"read"}
    laptop.lock()
    phone.lock()


def test_a_missing_level_is_read(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, old_dek, bob, carol = _carol_read(url, tmp_path, db)
    for obj in _server_envelopes(db, carol):
        obj.pop("access_level", None)
    _client(phone, url).pull()
    assert _local_level(phone, carol, old_dek) == "read"
    laptop.lock()
    phone.lock()
