"""Review main@a159e97 H7, desktop: the server now names one conflict per atomic batch.

To keep a read-only member from holding the global lock, the server stops
checking an atomic batch at its first conflict. A rotation re-sealing the
grants of two members removed elsewhere (SM29) learned only of the first
refused envelope per push and gave up after one retry; it now goes on
leaving them out until the rotation lands.
"""

from __future__ import annotations

from sezam import cli
from sezam.vault import revocation
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def _invite(url, admin_client, tmp_path, monkeypatch, name: str) -> str:
    invitation = admin_client.create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    member = _vault(tmp_path / name, name)
    cli._server_register_and_upload(
        url, member, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    member_id = member.db.get_meta("user_id")
    member.lock()
    admin_client.approve_user(member_id)
    return member_id


def test_rotation_leaves_out_the_grants_of_two_members_removed_elsewhere(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    phone.lock()
    laptop_client = _client(laptop, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    members = [_invite(url, laptop_client, tmp_path, monkeypatch, name) for name in ("bob", "carol")]
    for member_id in members:
        revocation.grant_member(laptop, laptop_client, member_id, folder, confirm_fingerprint=lambda _fp: True)
    # Another device removed both; its re-key has not reached the server yet.
    for user in db._storage["users"]:
        if user["id"] in members:
            user["status"] = "revoked"

    laptop_client.prepare_key_change()
    proof = laptop.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    laptop_client = _client(laptop, url)
    result = laptop_client.push()
    assert not laptop_client.has_pending_key_change(), result
    resealed = {
        row["id"] for row in laptop.db.fetchall(
            "SELECT id FROM access_envelopes WHERE user_id IN (?, ?)", tuple(members)
        )
    }
    queued = {
        row["object_id"]
        for row in laptop.db.fetchall(
            "SELECT object_id FROM outbox WHERE kind = 'envelope' AND state = 'queued'"
        )
    }
    assert resealed and not resealed & queued
    laptop.lock()
