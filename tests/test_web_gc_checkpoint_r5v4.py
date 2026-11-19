"""Review d150605 #4: the web logs in again after tombstone GC on a quiet vault.

After every page load the web pulls everything and checks it against its
stored checkpoint. When GC collected a tombstone the checkpoint covered and
nothing else changed, the check failed with STATE MISMATCH (or ROLLBACK
DETECTED when the tombstone held the highest seq) on every login, so a
web-only user who deleted something and then only read for three months was
locked out. The server now reports its GC floor and head, and the web accepts
a pull where only collected tombstones are missing (the live objects still
match exactly) and resumes deltas from the floor.
"""

from __future__ import annotations

import pytest

from tests.test_review_web import _run, pytestmark  # noqa: F401
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    app_client,
    mock_db,
)

FUNCTIONS = [
    "liveSyncObjects", "checkPulledStateAgainstCheckpoint", "syncPositionAfter",
    "computeWebStateHash",
]

SCRIPT = """
(async () => {
    const _sodium = sodium;
    const obj = (id, version, deleted, payload) => ({
        id: id.padEnd(26, '0'), version, is_deleted: deleted ? 1 : 0,
        payload: Buffer.from(payload).toString('base64'),
    });
    const map = (...objs) => Object.fromEntries(objs.map(o => [o.id, o]));
    async function checkpointOf(objects, seq) {
        return {
            last_sync_seq: seq,
            state_hash: await computeWebStateHash(objects, _sodium),
            live_state_hash: await computeWebStateHash(liveSyncObjects(objects), _sodium),
        };
    }
    async function attempt(checkpoint, objects, seqs) {
        const pulled = {
            ...seqs,
            stateHash: await computeWebStateHash(objects, _sodium),
            liveStateHash: await computeWebStateHash(liveSyncObjects(objects), _sodium),
        };
        try {
            checkPulledStateAgainstCheckpoint(checkpoint, pulled);
            return syncPositionAfter(0, pulled);
        } catch (err) {
            return err.message.split(':')[0];
        }
    }
    const A = obj('A', 1, false, 'a');
    const B = obj('B', 1, false, 'b');
    const T = obj('T', 2, true, 't');

    // The deleted item's tombstone held the highest seq; GC took it.
    const lastIsTomb = await checkpointOf(map(A, T), 2);
    const gcLast = await attempt(lastIsTomb, map(A), { responseSeq: 1, headSeq: 2, gcFloor: 2 });
    // A tombstone below the head; GC took it.
    const midTomb = await checkpointOf(map(T, B), 2);
    const gcMid = await attempt(midTomb, map(B), { responseSeq: 2, headSeq: 2, gcFloor: 1 });
    // The server hides a live object and claims GC: still refused.
    const live = await checkpointOf(map(A, B), 2);
    const hidden = await attempt(live, map(A), { responseSeq: 1, headSeq: 2, gcFloor: 2 });
    // No GC on the server and the state differs.
    const changed = await attempt(live, map(A, obj('B', 1, false, 'x')),
        { responseSeq: 2, headSeq: 2, gcFloor: 0 });
    // The server's head went back behind the checkpoint.
    const back = await attempt(live, map(A), { responseSeq: 1, headSeq: 1, gcFloor: 2 });
    // Unchanged vault, no GC.
    const same = await attempt(live, map(A, B), { responseSeq: 2, headSeq: 2, gcFloor: 0 });
    return { gcLast, gcMid, hidden, changed, back, same };
})()
"""


def test_a_pull_missing_only_collected_tombstones_passes_the_checkpoint():
    result = _run(FUNCTIONS, SCRIPT)
    assert result["gcLast"] == 2  # deltas resume at the floor, not a 410
    assert result["gcMid"] == 2
    assert result["same"] == 2
    assert result["hidden"] == "ROLLBACK DETECTED"
    assert result["changed"] == "STATE MISMATCH at seq 2"
    assert result["back"] == "ROLLBACK DETECTED"


def test_the_checkpoint_keeps_the_live_hash_and_the_pull_uses_the_server_floor():
    from tests.test_review_web import APP

    assert "live_state_hash: liveStateHash" in APP
    assert "gcFloor: Number(data.gc_floor_seq)" in APP
    assert "last_sync_seq: syncPosition" in APP


@pytest.mark.asyncio
async def test_pull_reports_the_gc_floor(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    token = _create_jwt("ADMIN000000000000000000001", "admin", True)
    mock_db._storage["commit_counter"][0]["gc_floor_seq"] = 7
    resp = await app_client.get(
        "/api/sync?since_commit_seq=0", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    assert resp.json()["gc_floor_seq"] == 7
