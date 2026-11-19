"""Review main@d615826 (desktop): 'sezam abandon-rekey' dropped grants silently.

While Bob's removal re-key waited for the server, the admin shared the
folder with Carol; her envelope sealed the batch's new folder key. Dropping
the batch deleted every envelope on its new keys, so Carol's grant vanished
without a word and she never got the folder. It is now sealed again under
the key the folder goes back to, and the re-queued re-key carries it over.
"""

from __future__ import annotations

import time

from sezam.crypto.envelope_crypto import open_envelope
from sezam.crypto.keys import generate_keypair
from sezam.vault import revocation
from sezam.vault.rekey_abandon import abandon_pending_rekey
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    _client,
    _server_member,
    server,
)
from tests.test_rekey_rebase_review8 import _assert_member_cut_off, _folder_shared_with_member


def _pinned_member(db, laptop):
    carol_id = _server_member(db)
    carol = generate_keypair()
    now = int(time.time() * 1000)
    laptop.db.execute(
        "INSERT INTO known_keys (user_id, signing_pk, encryption_pk, fingerprint, "
        "first_seen, last_verified) VALUES (?, ?, ?, ?, ?, ?)",
        (carol_id, carol.signing_pk, carol.encryption_pk, carol.fingerprint, now, now),
    )
    return carol_id, carol


def _opens_for(laptop, carol, envelope) -> bytes:
    return bytes(open_envelope(
        bytes(envelope["encrypted_dek"]), bytes(carol.encryption_sk), laptop.keypair.encryption_pk,
    ))


def test_a_grant_made_while_the_rekey_waited_survives_abandon(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, _entry, old_dek, bob = _folder_shared_with_member(url, tmp_path, db)
    carol_id, carol = _pinned_member(db, laptop)

    assert laptop.rekey_after_revocation(bob) == 1
    laptop.grant_folder_access(folder, carol_id, carol.encryption_pk, "write")

    client = _client(laptop, url)
    abandon_pending_rekey(client)

    dek_now = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert dek_now == old_dek
    envelope = laptop.db.fetchone(
        "SELECT * FROM access_envelopes WHERE dek_id = ? AND user_id = ?", (old_dek, carol_id)
    )
    assert envelope is not None, "Carol's grant was dropped with the re-key"
    assert envelope["access_level"] == "write"
    assert _opens_for(laptop, carol, envelope) == bytes(laptop.dek_mgr.unlock_dek(old_dek))

    # The re-queued removal of Bob keeps Carol on the folder's next key.
    assert client.push()["conflicts"] == []
    assert revocation.finish_queued_revocations(laptop, client) == {bob: 1}
    new_dek = _assert_member_cut_off(db, laptop, folder, old_dek, bob)
    carol_on_server = [
        o for o in db._storage["vault_objects"]
        if o["object_type"] == "envelope" and o.get("target_user_id") == carol_id
        and not o["is_deleted"]
    ]
    assert carol_on_server
    current = laptop.db.fetchone(
        "SELECT * FROM access_envelopes WHERE dek_id = ? AND user_id = ?", (new_dek, carol_id)
    )
    assert current is not None
    assert _opens_for(laptop, carol, current) == bytes(laptop.dek_mgr.unlock_dek(new_dek))
    laptop.lock()
    phone.lock()
