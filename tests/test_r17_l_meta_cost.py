"""Review c02cc47 R17-L: every /api/meta with a name read every account's KDF
params (R16-L5), so its cost and time grew with the accounts on the server.
The spread of params in use is read at most once a minute per server."""

from __future__ import annotations

import pytest

import tests.test_server_spec as spec
from tests.test_server_spec import _create_admin_user, app_client, mock_db  # noqa: F401  (fixtures)


@pytest.mark.asyncio
async def test_meta_reads_the_accounts_once_not_per_request(app_client, mock_db, monkeypatch):  # noqa: F811
    _create_admin_user(mock_db._storage)
    scans = []
    execute = spec.MockCursor.execute

    async def counting(self, query, args=()):
        if query.strip().upper() == "SELECT ARGON2_PARAMS FROM USERS":
            scans.append(query)
        return await execute(self, query, args)

    monkeypatch.setattr(spec.MockCursor, "execute", counting)
    for name in ["admin"] + [f"nobody{i}" for i in range(20)]:
        assert (await app_client.get(f"/api/meta?username={name}")).status_code == 200
    assert len(scans) == 1
