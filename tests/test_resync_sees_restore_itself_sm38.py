"""Stateful test finding SM38: a full resync no pull or push preceded missed the restore.

As SM24, but the laptop runs the full resync straight after the server was
restored from a backup taken before its grant: no pull or push noticed the
restore first, so only the rollback flag a pull leaves behind was checked and
the sent grant was taken for one the server dropped on purpose. The full
resync now tells the restore from its own snapshot (check token of the commit
anchor, head below it) and sends the grant again.
"""

from __future__ import annotations

import copy

from sezam.vault import revocation
from sezam.vault.sync_client import SERVER_ROLLBACK_META
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _restore, _two_devices


def test_full_resync_without_a_pull_sees_the_restore_and_sends_the_grant_again(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client = _client(laptop, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    backup = copy.deepcopy(db._storage)

    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    _restore(db, backup)
    assert not _bob_envelopes_live(db, bob_id)
    assert laptop.db.get_meta(SERVER_ROLLBACK_META) is None

    laptop_client.full_resync(confirmed=True)
    assert not laptop_client.push()["conflicts"]

    dek_id = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert [o["parent_ref"] for o in _bob_envelopes_live(db, bob_id)] == [dek_id]
    laptop.lock()
    phone.lock()
