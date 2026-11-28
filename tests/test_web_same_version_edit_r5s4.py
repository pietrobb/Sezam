"""Review d150605 S4 (web): an edit with the same version as the push out.

A save made while a push of the same object is out gets the same version
(the tree still shows the old one). isSameSyncVersion compared version and
the delete flag only, so when the first push was accepted the edit left the
queue - and its conflict entry was cleared too (version <= sent) - and was
lost. It now compares the content as well.
"""

from __future__ import annotations

from tests.test_review_web import pytestmark  # noqa: F401
from tests.test_web_push_limits import STUBS, _run

FUNCTIONS = [
    "assertNotStackedOnConflict", "assertTeamLogAllowsWrite", "webWriteState", "syncPayloadBytes", "assertSyncObjectFits",
    "pushEncryptedVaultObject", "pushEncryptedVaultObjectLocked", "renumberedAboveBase", "webBase", "withWebBase", "isSameSyncVersion",
]

RACE = STUBS + """
let release;
const gate = new Promise(resolve => { release = resolve; });
let firstOut;
const firstSent = new Promise(resolve => { firstOut = resolve; });
const first = { ...obj('E', 10), version: 2, is_deleted: false };
const edit = { ...obj('E', 12), version: 2, is_deleted: false };  // same version, new content
"""


def test_an_edit_with_the_same_version_stays_queued():
    result = _run(FUNCTIONS, RACE + """
        apiFetch = async (path, opts) => {
            const [o] = opts.body.objects;
            if (o.payload === first.payload) { firstOut(); await gate; }
            else throw new Error('offline');
            return { accepted: [{ id: o.id }], conflicts: [] };
        };
        const pushing = pushEncryptedVaultObject(first);
        await firstSent;
        const err = await attempt(() => pushEncryptedVaultObject(edit));
        release();
        await pushing;
        const left = state.outbox.E;
        return { err, kept: Boolean(left) && left.payload === edit.payload };
    """)
    assert result["err"] == "offline"
    assert result["kept"] is True


def test_its_conflict_is_not_cleared_by_the_accepted_push():
    result = _run(FUNCTIONS, RACE + """
        apiFetch = async (path, opts) => {
            const [o] = opts.body.objects;
            if (o.payload === first.payload) { firstOut(); await gate;
                return { accepted: [{ id: o.id }], conflicts: [] }; }
            return { accepted: [], conflicts: [{ id: o.id, server_version: 2 }] };
        };
        const pushing = pushEncryptedVaultObject(first);
        await firstSent;
        const err = await attempt(() => pushEncryptedVaultObject(edit));
        release();
        await pushing;
        const conflict = state.syncConflicts.E;
        return {
            conflict: Boolean(err) && Boolean(conflict) &&
                conflict.local_object.payload === edit.payload,
            queued: Boolean(state.outbox.E),
        };
    """)
    assert result == {"conflict": True, "queued": True}
