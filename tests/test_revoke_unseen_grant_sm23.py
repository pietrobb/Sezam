"""Stateful test finding SM23: a member revoked from a device that never saw the grant.

The laptop shared a folder with Bob. The phone (same admin account) had not
pulled it yet and revoked Bob: the re-key finds a member's folders through
the envelopes the device holds, so it re-keyed nothing. The laptop never
learned it had to: Bob's envelope stayed live and new items went on under the
key he holds. The device that sealed the envelope now queues the re-key of
every revoked member it holds envelopes for, on its next push.
"""

from __future__ import annotations

from sezam import cli
from sezam.vault import revocation
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live, _status
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def invite_bob(url, admin_client, tmp_path, monkeypatch) -> str:
    """Bob registers with an invitation and the admin approves him."""
    invitation = admin_client.create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    bob.lock()
    admin_client.approve_user(bob_id)
    return bob_id


def test_revoke_from_a_device_that_missed_the_grant_rekeys_on_the_granting_one(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()

    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    assert _bob_envelopes_live(db, bob_id)

    assert revocation.revoke_member(phone, phone_client, bob_id) == 0
    assert _status(db, bob_id) == "revoked"

    result = revocation.push_with_queued_revocations(laptop, laptop_client)
    assert result["rekeyed"] == {bob_id: 1}, result
    assert not _bob_envelopes_live(db, bob_id)
    assert not revocation.queued_revocations(laptop)
    laptop.lock()
    phone.lock()
