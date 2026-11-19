"""Review 7c10379 H2: a re-key gave the folder's new key to an envelope the server made up.

The re-key after a member's removal sealed the new DEK to every holder of an
envelope under the old one. It never asked who made the envelope or whether
the holder's fingerprint was confirmed: an account 'Eve' the server created,
holding an envelope she signed herself, got the new folder key. Now only a
grant this account made, or a member whose fingerprint this admin confirmed,
gets an envelope on the new key.
"""

from __future__ import annotations

from nacl.public import PrivateKey

from sezam.models import new_ulid
from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META
from tests.test_integration_client_server import server  # noqa: F401
from tests.test_rekey_rebase_review8 import _folder_shared_with_member


def _pin(vault, user_id):
    sk = PrivateKey.generate()
    vault.db.execute(
        "INSERT INTO known_keys (user_id, signing_pk, encryption_pk, fingerprint, "
        "first_seen, last_verified) VALUES (?, ?, ?, ?, 0, 0)",
        (user_id, bytes(32), bytes(sk.public_key), f"fp-{user_id}"),
    )
    return sk


def _grant(vault, dek_id, user_id, created_by):
    vault.db.execute(
        "INSERT INTO access_envelopes "
        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, 'read', ?)",
        (new_ulid(), dek_id, user_id, created_by, b"\x00" * 72),
    )


def test_rekey_seals_the_new_key_only_to_trusted_holders(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, _entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    own = laptop.db.get_meta("user_id")
    eve, bob, carol, other_admin = new_ulid(), new_ulid(), new_ulid(), new_ulid()
    for user_id in (eve, bob, carol):
        _pin(laptop, user_id)
    _grant(laptop, old_dek, eve, eve)            # made up by the server, signed by Eve
    _grant(laptop, old_dek, bob, own)            # this account's grant
    _grant(laptop, old_dek, carol, other_admin)  # another admin's, fingerprint confirmed
    laptop.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {carol: f"fp-{carol}"})

    assert laptop.rekey_after_revocation(member_id) == 1
    new_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert new_dek != old_dek
    holders = {
        row["user_id"] for row in laptop.db.fetchall(
            "SELECT user_id FROM access_envelopes WHERE dek_id = ?", (new_dek,)
        )
    }
    assert bob in holders and carol in holders
    assert eve not in holders and member_id not in holders
    laptop.lock()
    phone.lock()
