"""Review a159e97 H9: an org recovery replacement whose answer was lost.

register_org_recovery raises OSError when the connection breaks (a reset, a
timeout). setup_and_register did not catch it: the error went out with the
new setup in the vault but the shares never shown; caught like a refusal it
would roll back, and a server that had taken the new key would then hold a
recovery whose shares were wiped. The outcome is unknown, so the new setup
stays and its registration waits; the server's public blob tells when it did
take the key. Setup, registration and rollback hold the vault's sync lock.
"""

from __future__ import annotations

import http.client
import json
import threading

import pytest

from sezam import cli
from sezam.vault import oplock, org_recovery_server, pending_states
from sezam.vault.sync_client import SyncClient
from sezam.vault.sync_common import ServerError
from tests.test_integration_client_server import PASSWORD, _vault, server  # noqa: F401


def _connected(url, tmp_path):
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    first = org_recovery_server.setup_and_register(laptop, PASSWORD, 2, 3)
    assert first.registered
    return laptop


def _server_blob(laptop) -> str:
    return org_recovery_server._client(laptop)._request("GET", "/api/org-recovery/blob")["wrapped_kek"]


def _lose_answer(monkeypatch, *, after_send: bool, seen: list):
    real = SyncClient.store_org_recovery

    def store(self, body, proof):
        busy = []
        probe = threading.Thread(target=lambda: busy.append(_other_process_waits(self._db.path)))
        probe.start()
        probe.join()
        seen.append(busy[0])
        if after_send:
            real(self, body, proof)
        raise ConnectionResetError("connection reset by peer")

    monkeypatch.setattr(SyncClient, "store_org_recovery", store)


def _other_process_waits(path) -> bool:
    try:
        with oplock.exclusive(path, timeout=0.2):
            return False
    except oplock.VaultBusy:
        return True


def test_the_server_took_the_key_but_the_answer_was_lost(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    laptop = _connected(url, tmp_path)
    seen: list = []
    _lose_answer(monkeypatch, after_send=True, seen=seen)

    setup = org_recovery_server.setup_and_register(laptop, PASSWORD, 2, 3, replace=True)
    assert setup.registered is True  # before: ConnectionResetError, shares never shown
    assert seen == [True]  # the sync lock was held during the registration
    assert any(any(share) for _i, share in setup.shares)
    assert pending_states.org_recovery_registration(laptop.db) is None

    laptop.lock()
    laptop.org_recovery(setup.shares[:2], "after-lost-answer!")  # the new shares work


def test_the_answer_was_lost_before_the_server_got_it(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    laptop = _connected(url, tmp_path)
    old_pk = laptop.db.get_meta("org_recovery_pk")
    old_blob = _server_blob(laptop)
    _lose_answer(monkeypatch, after_send=False, seen=[])

    setup = org_recovery_server.setup_and_register(laptop, PASSWORD, 2, 3, replace=True)
    assert setup.registered is False and "answer was lost" in setup.error
    assert laptop.db.get_meta("org_recovery_pk") != old_pk  # not rolled back
    assert pending_states.org_recovery_registration(laptop.db) is not None
    assert _server_blob(laptop) == old_blob

    monkeypatch.undo()
    notice = org_recovery_server.register_while_password_known(laptop, PASSWORD)
    assert notice == org_recovery_server.REGISTERED_NOTICE
    assert _server_blob(laptop) != old_blob
    laptop.lock()
    laptop.org_recovery(setup.shares[:2], "after-lost-answer!")


def _commit_then(monkeypatch, error: Exception) -> None:
    real = SyncClient.store_org_recovery

    def store(self, body, proof):
        real(self, body, proof)
        raise error

    monkeypatch.setattr(SyncClient, "store_org_recovery", store)


_UNCLEAR_ANSWERS = {
    "proxy_504": lambda: ServerError(504, "Gateway Timeout"),
    "proxy_502": lambda: ServerError(502, "<html>Bad Gateway</html>"),
    "garbled_200": lambda: json.JSONDecodeError("Expecting value", "<html>", 0),
    "truncated_200": lambda: http.client.IncompleteRead(b"{\"ok\":"),
}


@pytest.mark.parametrize("answer", sorted(_UNCLEAR_ANSWERS))
def test_an_unclear_answer_after_the_server_took_the_key(server, tmp_path, monkeypatch, answer):  # noqa: F811
    """Capability review run 201: a proxy's 5xx or a broken body after the
    server stored the new key went down the refusal branch - new shares
    wiped, old setup restored, the server holding a key nobody can rebuild."""
    url, _db = server
    laptop = _connected(url, tmp_path)
    old_pk = laptop.db.get_meta("org_recovery_pk")
    _commit_then(monkeypatch, _UNCLEAR_ANSWERS[answer]())

    setup = org_recovery_server.setup_and_register(laptop, PASSWORD, 2, 3, replace=True)
    assert setup.registered is True  # before: OrgRecoveryNotReplaced, shares wiped
    assert laptop.db.get_meta("org_recovery_pk") != old_pk
    assert pending_states.org_recovery_registration(laptop.db) is None
    laptop.lock()
    laptop.org_recovery(setup.shares[:2], "after-unclear-answer!")  # the new shares work


@pytest.mark.parametrize("answer", ["proxy_504", "garbled_200"])
def test_an_unclear_answer_before_the_server_got_it(server, tmp_path, monkeypatch, answer):  # noqa: F811
    url, _db = server
    laptop = _connected(url, tmp_path)
    old_pk = laptop.db.get_meta("org_recovery_pk")
    old_blob = _server_blob(laptop)
    error = _UNCLEAR_ANSWERS[answer]()

    def store(self, body, proof):
        raise error

    monkeypatch.setattr(SyncClient, "store_org_recovery", store)
    setup = org_recovery_server.setup_and_register(laptop, PASSWORD, 2, 3, replace=True)
    assert setup.registered is False and "answer was lost" in setup.error
    assert laptop.db.get_meta("org_recovery_pk") != old_pk  # kept, registration waits
    assert pending_states.org_recovery_registration(laptop.db) is not None
    assert _server_blob(laptop) == old_blob


def test_a_refusal_still_keeps_the_old_setup(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    laptop = _connected(url, tmp_path)
    old_pk = laptop.db.get_meta("org_recovery_pk")

    def refuse(self, body, proof):
        raise RuntimeError("Server error 403: refused")

    monkeypatch.setattr(SyncClient, "store_org_recovery", refuse)
    with pytest.raises(org_recovery_server.OrgRecoveryNotReplaced):
        org_recovery_server.setup_and_register(laptop, PASSWORD, 2, 3, replace=True)
    assert laptop.db.get_meta("org_recovery_pk") == old_pk
    laptop.lock()
