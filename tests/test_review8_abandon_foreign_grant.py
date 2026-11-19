"""Review main@a159e97 H1: 'sezam abandon-rekey' sealed the folder key to 'Eve'.

Dropping a pending removal re-key seals again every grant made on the batch's
new key while it waited. It took every envelope on that key, whoever made it:
an account the server created, holding an envelope it signed itself, got the
key the folder goes back to (and the next re-key carried it on). Only a grant
this account made, or a member whose fingerprint it confirmed, is sealed again.
"""

from __future__ import annotations

import time

from sezam.crypto.envelope_crypto import create_envelope
from sezam.crypto.keys import generate_keypair
from sezam.models import new_ulid
from sezam.vault import pending_states
from sezam.vault.rekey_abandon import abandon_pending_rekey
from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    _client,
    _server_member,
    server,
)
from tests.test_rekey_rebase_review8 import _folder_shared_with_member


def _foreign_grant_on_new_key(laptop, db, folder):
    """An envelope on the batch's new key that 'Eve' signed for herself."""
    eve_id = _server_member(db)
    eve = generate_keypair()
    now = int(time.time() * 1000)
    laptop.db.execute(
        "INSERT INTO known_keys (user_id, signing_pk, encryption_pk, fingerprint, "
        "first_seen, last_verified) VALUES (?, ?, ?, ?, ?, ?)",
        (eve_id, eve.signing_pk, eve.encryption_pk, eve.fingerprint, now, now),
    )
    new_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert new_dek in pending_states.rekey_batch(laptop.db)["dek_map"].values()
    laptop.db.execute(
        "INSERT INTO access_envelopes "
        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) VALUES (?, ?, ?, ?, ?, ?)",
        (
            new_ulid(), new_dek, eve_id, eve_id, "write",
            create_envelope(
                laptop.dek_mgr.unlock_dek(new_dek), bytes(eve.encryption_sk), eve.encryption_pk,
            ),
        ),
    )
    return eve_id, eve


def test_abandon_does_not_seal_the_key_to_a_grant_another_account_made(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, _entry, old_dek, bob = _folder_shared_with_member(url, tmp_path, db)
    assert laptop.rekey_after_revocation(bob) == 1
    eve_id, _eve = _foreign_grant_on_new_key(laptop, db, folder)

    abandon_pending_rekey(_client(laptop, url))

    assert laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"] == old_dek
    assert laptop.db.fetchone(
        "SELECT 1 FROM access_envelopes WHERE user_id = ?", (eve_id,)
    ) is None, "abandon-rekey sealed the folder key to an envelope the server made up"
    laptop.lock()
    phone.lock()


def test_abandon_keeps_a_member_whose_key_this_admin_confirmed(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, _entry, old_dek, bob = _folder_shared_with_member(url, tmp_path, db)
    assert laptop.rekey_after_revocation(bob) == 1
    eve_id, eve = _foreign_grant_on_new_key(laptop, db, folder)
    laptop.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {eve_id: eve.fingerprint})

    abandon_pending_rekey(_client(laptop, url))

    assert laptop.db.fetchone(
        "SELECT 1 FROM access_envelopes WHERE dek_id = ? AND user_id = ?", (old_dek, eve_id)
    ) is not None
    laptop.lock()
    phone.lock()
