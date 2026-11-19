"""Stateful test finding SM62: a grant made under the key a re-key replaced.

The laptop removed Bob; its re-key of the shared folder was built but not
sent yet. The phone (same admin account, not pulled) shared the folder with
Carol under the old key and the server took it. The laptop's re-key then gave
envelopes on the new key only to the members it knew of, so Carol held only
the retired key: on every device she lost the folder. A pull now seals this
account's grant under a retired folder key again on the folder's current key,
for a member not removed on the server.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam import cli
from sezam.vault import revocation
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live, _status
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once


def _invite_carol(url, admin_client, tmp_path, monkeypatch) -> str:
    invitation = admin_client.create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    carol = _vault(tmp_path / "carol", "carol")
    cli._server_register_and_upload(
        url, carol, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    carol_id = carol.db.get_meta("user_id")
    carol.lock()
    admin_client.approve_user(carol_id)
    return carol_id


def test_grant_under_a_key_a_pending_rekey_replaces_reaches_the_new_key(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    carol_id = _invite_carol(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()

    undo = _fail_once(laptop_client, "POST", "/api/sync", "before")
    try:
        revocation.revoke_member(laptop, laptop_client, bob_id)
    except RuntimeError:
        pass
    finally:
        undo()
    assert _status(db, bob_id) == "revoked"
    assert (pending_states.rekey_batch(laptop.db) or None)
    revocation.grant_member(phone, phone_client, carol_id, folder, confirm_fingerprint=lambda _fp: True)
    assert _bob_envelopes_live(db, carol_id)

    for _ in range(3):
        revocation.push_with_queued_revocations(laptop, laptop_client)
        laptop_client.pull()
        phone_client.push()
        phone_client.pull()
    assert not (pending_states.rekey_batch(laptop.db) or None)
    current = laptop.db.fetchone(
        "SELECT id FROM deks WHERE node_id = ? AND scope = 'folder'", (folder,)
    )["id"]
    assert current in {o["parent_ref"] for o in _bob_envelopes_live(db, carol_id)}
    assert not _bob_envelopes_live(db, bob_id)
    laptop.lock()
    phone.lock()


def test_grant_older_than_a_rekey_that_never_saw_it_reaches_the_new_key(
    server, tmp_path, monkeypatch  # noqa: F811
):
    """Capability review run 140: SM62 in the other order. The phone granted
    Carol and pushed; the laptop, not pulled, then removed Bob and re-keyed
    from its local envelopes. Carol's grant is older than the re-key, but the
    re-key never saw it, so it is not one the re-key withdrew."""
    import time

    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    carol_id = _invite_carol(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()
    revocation.grant_member(phone, phone_client, carol_id, folder, confirm_fingerprint=lambda _fp: True)
    assert _bob_envelopes_live(db, carol_id)
    time.sleep(0.005)

    undo = _fail_once(laptop_client, "POST", "/api/sync", "before")
    try:
        revocation.revoke_member(laptop, laptop_client, bob_id)
    except RuntimeError:
        pass
    finally:
        undo()

    for _ in range(3):
        revocation.push_with_queued_revocations(laptop, laptop_client)
        laptop_client.pull()
        phone_client.push()
        phone_client.pull()
    assert not (pending_states.rekey_batch(laptop.db) or None)
    current = laptop.db.fetchone(
        "SELECT id FROM deks WHERE node_id = ? AND scope = 'folder'", (folder,)
    )["id"]
    assert current in {o["parent_ref"] for o in _bob_envelopes_live(db, carol_id)}
    assert not _bob_envelopes_live(db, bob_id)
    laptop.lock()
    phone.lock()


def test_rewrap_of_a_replaced_folder_key_stays_retired(
    server, tmp_path, monkeypatch  # noqa: F811
):
    """The phone's password change re-wrapped the folder key the laptop's
    re-key had replaced. Pulled, that wrap (its folder still named) was taken
    for a tier-2 key and bound to the folder again, out of the grant again's
    sight."""
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()
    old = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]

    phone_client.prepare_key_change()
    phone.change_password(PASSWORD, "phone-pw-sm62!")
    phone_client = _client(phone, url)
    undo = _fail_once(phone_client, "POST", "/api/sync", "before")
    try:
        phone_client.push()
    except RuntimeError:
        pass
    finally:
        undo()
    assert phone_client.has_pending_key_change()
    revocation.revoke_member(laptop, laptop_client, bob_id)
    assert not (pending_states.rekey_batch(laptop.db) or None)
    phone_client.push()
    assert not phone_client.has_pending_key_change()

    laptop_client.adopt_rotated_key_material(laptop, "phone-pw-sm62!")
    _client(laptop, url).pull()
    row = laptop.db.fetchone("SELECT node_id, scope FROM deks WHERE id = ?", (old,))
    assert (row["node_id"], row["scope"]) == (None, "folder")
    assert laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"] != old
    laptop.lock()
    phone.lock()
