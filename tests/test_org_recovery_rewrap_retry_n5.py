"""Review 526419e N5: a failed server blob re-wrap after an org recovery was only logged.

Once the recovery's password change landed, the journal holding the recovery
secret was dropped, so a re-wrap the server did not take (a network blip) was
lost for good: the server kept the blob of the old KEK and the shares stopped
working there (web recovery) with no way to send it again. The body is kept,
'sezam status' lists it and every push retries it.
"""

from __future__ import annotations

from sezam.vault import pending_states as pending_store
from sezam.vault.crud import Vault
from sezam.vault.pending_states import pending_states
from sezam.vault.sync_client import SyncClient
from tests.test_grant_folder_access import team  # noqa: F401  (fixture)
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    server,
)

RECOVERED = "recovered-password!"


def _recover_with_failing_rewrap(team, tmp_path, monkeypatch):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    shares = admin.setup_org_recovery(threshold=2, shares=3)
    admin_client.store_org_recovery(
        pending_store.org_recovery_registration(admin.db), admin.current_auth_proof(PASSWORD)
    )
    admin.lock()
    recovered = Vault(tmp_path / "admin")
    recovered.org_recovery(shares[:2], RECOVERED)
    recovered.lock()
    recovered.unlock(RECOVERED)

    real = SyncClient._request
    failing = {"on": True}

    def flaky(self, method, path, *args, **kwargs):
        if failing["on"] and path == "/api/org-recovery/store":
            raise RuntimeError("Server error 503: unavailable")
        return real(self, method, path, *args, **kwargs)

    monkeypatch.setattr(SyncClient, "_request", flaky)
    client = _client(recovered, url)
    result = client.push()
    assert result["conflicts"] == []
    assert (pending_store.key_change_journal(recovered.db) or None) is None  # the journal is gone
    return recovered, client, failing, result


def test_a_failed_rewrap_is_retried_by_the_next_push(team, tmp_path, monkeypatch):  # noqa: F811
    recovered, client, failing, result = _recover_with_failing_rewrap(team, tmp_path, monkeypatch)
    try:
        assert result.get("org_recovery_rewrap_pending") is True
        assert client._request("GET", "/api/org-recovery/status")["stale"] is True
        assert "org_recovery_rewrap" in {s.key for s in pending_states(recovered)}

        failing["on"] = False
        assert not client.push().get("org_recovery_rewrap_pending")
        assert client._request("GET", "/api/org-recovery/status")["stale"] is False
        assert "org_recovery_rewrap" not in {s.key for s in pending_states(recovered)}
    finally:
        recovered.lock()


def test_a_new_password_drops_the_old_rewrap(team, tmp_path, monkeypatch):  # noqa: F811
    recovered, client, failing, _ = _recover_with_failing_rewrap(team, tmp_path, monkeypatch)
    try:
        assert pending_store.org_recovery_rewrap(recovered.db) is not None
        proof = recovered.change_password(RECOVERED, "another-password!")
        proof[:] = b"\x00" * len(proof)
        # It wraps the KEK the vault no longer has.
        assert pending_store.org_recovery_rewrap(recovered.db) is None
    finally:
        recovered.lock()
