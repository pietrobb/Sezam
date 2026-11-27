"""Review c02cc47 R17-N5: a refused takeover of rotated key material was applied
by half.

adopt_rotated_key_material committed adopt_account_kek (the server's key epoch,
the account KEK, and with them the end of this device's own unsent identity
rotation) before rebind_server_identity checked the server's keypair and
refused it (an anchor naming another team log, a keypair without this
device's anchor). The device was left with neither: its rotation was gone and
the server's keys were not taken, so it no longer logged in (401). Found by
the state machine (TeamLogMachine).

The refusal stands in here for each of rebind's checks: the takeover and the
binding are one unit, a refused one changes nothing.
"""

from __future__ import annotations

import pytest

from sezam.vault import crud, pending_states
from sezam.vault.sync_client import SyncClient
from sezam.vault.team_log_local import TeamLogMismatch
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices

STATE = ("key_epoch", "argon2_salt", "argon2_params", "kek_dek_id", "encrypted_keypair", "user_id",
         "signing_pk", "encryption_pk", "server_key_material_hash")


def _state(vault) -> dict:
    db = vault.db
    return {
        **{key: db.get_meta(key) for key in STATE},
        "key_change": pending_states.key_change_journal(db),
        "rekey_batch": pending_states.rekey_batch(db),
        "deks": [tuple(r) for r in db.fetchall("SELECT id, version, encrypted_dek FROM deks ORDER BY id")],
    }


def _unauthenticated(vault, url) -> SyncClient:
    """The server took another device's rotation: logging in raises KeyEpochStale."""
    client = SyncClient(vault.db, url, vault.keypair, vault.db.get_meta("user_id"))
    client.set_dek_manager(vault.dek_mgr)
    return client


def _refuse(*_args, **_kwargs):
    raise TeamLogMismatch("The account anchor conflicts with this device's team log.", "anchor_conflict")


def test_a_refused_rebind_leaves_the_unsent_rotation_and_the_login(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client = _client(laptop, url)
    entry = laptop.create_entry(_folder(laptop), "vpn", [{"key": "password", "value": "pw", "sensitive": True}])
    laptop_client.push()
    phone_client = _client(phone, url)
    phone_client.pull()
    # The phone's own identity rotation, not sent yet.
    phone_client.prepare_key_change()
    proof = phone.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    # The laptop's goes out first.
    laptop_client.prepare_key_change()
    proof = laptop.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    _client(laptop, url).push()

    phone_client = _unauthenticated(phone, url)
    assert phone_client.has_pending_key_change()
    before = _state(phone)
    monkeypatch.setattr(crud, "import_account_anchor", _refuse)
    with pytest.raises(TeamLogMismatch):
        phone_client.adopt_rotated_key_material(phone, PASSWORD)
    assert _state(phone) == before
    monkeypatch.undo()

    # The device is as it was: it opens with its password, keeps its
    # rotation, and takes the server's material once nothing refuses it.
    phone.lock()
    phone.unlock(PASSWORD)
    phone_client = _unauthenticated(phone, url)
    assert phone_client.has_pending_key_change()
    phone_client.adopt_rotated_key_material(phone, PASSWORD)
    phone_client.pull()
    assert "pw" in str(phone.read_entry(entry))
    phone.lock()
    laptop.lock()
