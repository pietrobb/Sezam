"""Review c78fd19 R13-10: an older desktop org recovery setup replaced a newer
one set up on the web.

A desktop setup the server did not take (offline, the answer lost) waits and
is registered at the next unlock or push. When the admin set up org recovery
again on the web meanwhile, that registration replaced the web's newer key on
the server and voided the shares handed out for it. The registration now
names the key it replaces; the server stores it only while that key is still
the current one, and the desktop forgets its outdated setup instead.
"""

from __future__ import annotations

import os

import pytest

from sezam import cli
from sezam.vault import org_recovery_server, pending_states
from sezam.vault.sync_client import SyncClient
from sezam.vault.sync_common import ORG_RECOVERY_SUPERSEDED, server_error
from sezam.vault.team_log_local import queued_changes
from tests.test_integration_client_server import PASSWORD, _vault, server  # noqa: F401


def _status(laptop) -> dict:
    return org_recovery_server._client(laptop)._request("GET", "/api/org-recovery/status")


def _laptop_with_waiting_setup(url, tmp_path, monkeypatch):
    """A registered setup, then a replacement whose registration waits."""
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    first = org_recovery_server.setup_and_register(laptop, PASSWORD, 2, 3)
    assert first.registered
    first_pk = laptop.db.get_meta("org_recovery_signing_pk")

    def lost(self, body, proof):
        raise ConnectionResetError("connection reset by peer")

    monkeypatch.setattr(SyncClient, "store_org_recovery", lost)
    waiting = org_recovery_server.setup_and_register(laptop, PASSWORD, 2, 3, replace=True)
    monkeypatch.undo()
    assert waiting.registered is False
    registration = pending_states.org_recovery_registration(laptop.db)
    assert registration["expected_signing_pk"] == first_pk
    return laptop, first_pk, registration["recovery_signing_pk"]


def _web_setup(laptop) -> str:
    """What the web client stores: no expected_signing_pk, the current password."""
    web_pk = os.urandom(32).hex()
    proof = laptop.current_auth_proof(PASSWORD)
    org_recovery_server._client(laptop)._request("POST", "/api/org-recovery/store", {
        "wrapped_kek": os.urandom(72).hex(), "recovery_signing_pk": web_pk,
        "threshold": 2, "total_shares": 3,
        "key_epoch": int(laptop.db.get_meta("key_epoch") or "0"),
        "current_auth_proof": bytes(proof).hex(),
    }, auth=True)
    return web_pk


def _forgotten(laptop, desktop_pk) -> None:
    assert pending_states.org_recovery_registration(laptop.db) is None
    assert not laptop.org_recovery_configured()
    assert not any(
        kind == "org.recovery" and data.get("recovery_pk") == desktop_pk
        for kind, data in queued_changes(laptop.db)
    )


def test_unlock_keeps_the_newer_web_setup(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    laptop, _first_pk, desktop_pk = _laptop_with_waiting_setup(url, tmp_path, monkeypatch)
    web_pk = _web_setup(laptop)

    notice = org_recovery_server.register_while_password_known(laptop, PASSWORD)
    assert notice == org_recovery_server.SUPERSEDED_NOTE  # before: REGISTERED_NOTICE
    assert _status(laptop)["recovery_signing_pk"] == web_pk  # before: desktop_pk
    _forgotten(laptop, desktop_pk)
    # Said once: the next unlock has nothing left to register or report.
    assert org_recovery_server.register_while_password_known(laptop, PASSWORD) is None


def test_the_server_refuses_an_outdated_registration(server, tmp_path, monkeypatch):  # noqa: F811
    """The web setup lands between the desktop's status check and its store."""
    url, _db = server
    laptop, _first_pk, desktop_pk = _laptop_with_waiting_setup(url, tmp_path, monkeypatch)
    web_pk = _web_setup(laptop)
    monkeypatch.setattr(org_recovery_server, "superseded_by", lambda db, status: False)

    notice = org_recovery_server.register_while_password_known(laptop, PASSWORD)
    assert notice == org_recovery_server.SUPERSEDED_NOTE
    assert _status(laptop)["recovery_signing_pk"] == web_pk
    _forgotten(laptop, desktop_pk)


def test_server_compare_and_store(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    laptop, first_pk, _desktop_pk = _laptop_with_waiting_setup(url, tmp_path, monkeypatch)
    registration = pending_states.org_recovery_registration(laptop.db)
    web_pk = _web_setup(laptop)
    client = org_recovery_server._client(laptop)

    def store(body):
        proof = laptop.current_auth_proof(PASSWORD)
        client._request("POST", "/api/org-recovery/store",
                        {**body, "current_auth_proof": bytes(proof).hex()}, auth=True)

    with pytest.raises(RuntimeError) as refused:
        store(registration)  # names first_pk, the server holds web_pk
    assert server_error(refused.value, 409, ORG_RECOVERY_SUPERSEDED)
    with pytest.raises(RuntimeError):
        store({**registration, "expected_signing_pk": None})  # "none before" is outdated too
    assert _status(laptop)["recovery_signing_pk"] == web_pk

    store({**registration, "expected_signing_pk": web_pk})  # a deliberate replace
    assert _status(laptop)["recovery_signing_pk"] == registration["recovery_signing_pk"]
    store({**registration, "expected_signing_pk": first_pk})  # a retry of the stored key
    body = {k: v for k, v in registration.items() if k != "expected_signing_pk"}
    store({**body, "recovery_signing_pk": os.urandom(32).hex()})  # an older client: as before


def test_push_does_not_name_the_outdated_key(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    laptop, _first_pk, desktop_pk = _laptop_with_waiting_setup(url, tmp_path, monkeypatch)
    web_pk = _web_setup(laptop)
    client = SyncClient(laptop.db, url, laptop.keypair, laptop.db.get_meta("user_id"))
    client.set_dek_manager(laptop.dek_mgr)

    result = client.push()
    assert result.get("org_recovery_superseded") is True
    assert _status(laptop)["recovery_signing_pk"] == web_pk
    _forgotten(laptop, desktop_pk)
    assert not client.push().get("org_recovery_superseded")
