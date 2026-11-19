"""Review 7c10379 (server, medium): the commit token lookup read the whole log tail.

Every push carrying a check_token looks up the token of the commit its device
saw, under the global push lock. ``first_seq <= seq AND last_seq >= seq``
cannot stop at the first row: on the last_seq primary key it reads the row of
every later push (one per push, kept forever), so a device anchored far back
held every other push for as long. It is now one primary-key seek.
"""

from __future__ import annotations

import pytest

from server.app.routers.sync import _commit_token
from tests.test_server_spec import MockCursor


class _RecordingCursor(MockCursor):
    def __init__(self, storage):
        super().__init__(storage)
        self.queries: list[str] = []

    async def execute(self, query, args=()):
        self.queries.append(" ".join(query.split()))
        return await super().execute(query, args)


@pytest.fixture
def log():
    rows = [(5, 1, "a" * 32), (6, 6, "b" * 32), (12, 9, "c" * 32)]  # seqs 7-8 lost
    return {"commit_log": [{"last_seq": last, "first_seq": first, "token": tok} for last, first, tok in rows]}


@pytest.mark.asyncio
@pytest.mark.parametrize("seq, token", [
    (0, None), (1, "a" * 32), (5, "a" * 32), (6, "b" * 32), (7, None), (8, None),
    (9, "c" * 32), (12, "c" * 32), (13, None),
])
async def test_the_token_of_the_push_that_committed_seq(log, seq, token):
    assert await _commit_token(_RecordingCursor(log), seq) == token


@pytest.mark.asyncio
async def test_the_lookup_is_one_primary_key_seek(log):
    cur = _RecordingCursor(log)
    await _commit_token(cur, 3)
    assert len(cur.queries) == 1
    query = cur.queries[0].upper()
    assert "WHERE LAST_SEQ > %S ORDER BY LAST_SEQ LIMIT 1" in query, query
    assert "FIRST_SEQ <=" not in query, query
