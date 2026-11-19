"""Review 526419e #2 (web): an edit saved while a push was out left the queue.

pushEncryptedVaultObject deleted ``state.outbox[id]`` once the server
accepted the version it sent. A newer version queued meanwhile (a Retry
racing a new save) went with it: if its own request then failed, the edit
was neither on the server nor queued for retry.
"""

from __future__ import annotations

from tests.test_web_push_limits import STUBS, _run
from tests.test_review_web import pytestmark  # noqa: F401

FUNCTIONS = [
    "assertNotStackedOnConflict", "assertTeamLogAllowsWrite", "syncPayloadBytes", "assertSyncObjectFits",
    "pushEncryptedVaultObject", "pushEncryptedVaultObjectLocked", "webBase", "withWebBase", "isSameSyncVersion",
]


def test_a_newer_version_queued_during_the_push_stays_queued():
    result = _run(FUNCTIONS, STUBS + """
        let release;
        const gate = new Promise(resolve => { release = resolve; });
        let v2out;
        const v2sent = new Promise(resolve => { v2out = resolve; });
        apiFetch = async (path, opts) => {
            const [o] = opts.body.objects;
            if (o.version === 2) { v2out(); await gate; }   // v2 is out ...
            if (o.version === 3) throw new Error('offline'); // ... v3 fails to send
            return { accepted: [{ id: o.id }], conflicts: [] };
        };
        const v2 = pushEncryptedVaultObject({ ...obj('E', 10), version: 2, is_deleted: false });
        await v2sent;
        const v3err = await attempt(() => pushEncryptedVaultObject(
            { ...obj('E', 11), version: 3, is_deleted: false }));
        release();
        await v2;
        const left = state.outbox.E;
        return { v3err, version: left ? left.version : null };
    """)
    assert result["v3err"] == "offline"
    assert result["version"] == 3


def test_the_sent_version_leaves_the_queue():
    result = _run(FUNCTIONS, STUBS + """
        await pushEncryptedVaultObject({ ...obj('E', 10), version: 2, is_deleted: false });
        return { left: Object.keys(state.outbox) };
    """)
    assert result["left"] == []
