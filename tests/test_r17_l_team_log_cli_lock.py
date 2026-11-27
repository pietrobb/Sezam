"""Review c02cc47 R17-L, desktop: 'sezam team-log status', 'confirm-founder'
and 'forget-pin' synced the team log without the sync lock.

They call SyncClient._refresh_team_log (status, confirm-founder) and
team_log_refusal (forget-pin), outside a pull or push. The team log sync
posts a restore of what the server lost, sends this account's lost changes
again and withdraws records: account sync state another process (a GUI
push) reads and rewrites at the same time (INV-6). The lock is taken where
the log is synced, so no caller can forget it.
"""

from __future__ import annotations

from sezam.vault import oplock, team_log_local
from sezam.vault.sync_client import SyncClient
from tests.test_integration_client_server import _vault


def _client(vault, seen: list) -> SyncClient:
    client = SyncClient(vault.db, "http://127.0.0.1:9", vault.keypair, "01JM0000000000000000000001")
    client._token = "token"

    def request(method, path, body=None, auth=False):
        seen.append((path, oplock.holds_sync(vault.db.path)))
        return {"head": None, "records": []}

    client._request = request
    return client


def test_the_team_log_sync_outside_a_pull_holds_the_sync_lock(tmp_path, monkeypatch):
    vault = _vault(tmp_path / "laptop", "admin")
    try:
        seen: list = []
        real = team_log_local.forgotten_genesis

        def spy(db):
            seen.append(("sync", oplock.holds_sync(vault.db.path)))
            return real(db)

        monkeypatch.setattr(team_log_local, "forgotten_genesis", spy)
        client = _client(vault, seen)
        client._refresh_team_log()  # status, confirm-founder
        client.team_log_refusal()  # forget-pin
        assert seen and all(held for _, held in seen), seen
        assert not oplock.holds_sync(vault.db.path)
    finally:
        vault.lock()
