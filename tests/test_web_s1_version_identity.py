"""Sync redesign S1 (docs/SYNC_SINGLE_SOURCE.md point 1), web client.

A folder or entry change names the server copy it was made on by version AND
payload hash; the server refuses a change naming none. The same number with
other content is a conflict, the very copy a change was made on is not.
"""

from __future__ import annotations

from tests.test_web_push_limits import STUBS, _run
from tests.test_review_web import _function, _run_source, pytestmark  # noqa: F401

FUNCTIONS = [
    "assertNotStackedOnConflict", "assertTeamLogAllowsWrite", "webWriteState", "syncPayloadBytes", "assertSyncObjectFits",
    "pushEncryptedVaultObject", "pushEncryptedVaultObjectLocked", "renumberedAboveBase", "isSameSyncVersion",
    "webBase", "withWebBase",
]

ENTRY = """
globalThis.bodies = [];
apiFetch = async (path, opts) => {
    bodies.push(opts.body.objects[0]);
    return { accepted: [{ id: opts.body.objects[0].id }], conflicts: [] };
};
const edit = (version, hash) => ({
    ...obj('E', 10), object_type: 'entry', version, is_deleted: 0, payload_hash: hash,
});
const based = o => [o.base_version ?? null, o.base_payload_hash ?? null];
"""


def test_each_edit_names_the_copy_it_was_made_on():
    result = _run(FUNCTIONS, STUBS + ENTRY + """
        state.syncObjects = { E: { id: 'E', version: 1, payload_hash: 'h1' } };
        await pushEncryptedVaultObject(edit(2, 'h2'));
        // Accepted, not pulled yet: the next edit builds on what the server took.
        await pushEncryptedVaultObject(edit(3, 'h3'));
        await pushEncryptedVaultObject({ ...edit(1, 'n1'), id: 'NEW' });
        return bodies.map(based);
    """)
    assert result == [[1, "h1"], [2, "h2"], [None, None]]


def test_a_queued_change_keeps_its_base_when_edited_again():
    result = _run(FUNCTIONS, STUBS + ENTRY + """
        state.syncObjects = { E: { id: 'E', version: 1, payload_hash: 'h1' } };
        apiFetch = async () => { throw new Error('offline'); };
        await attempt(() => pushEncryptedVaultObject(edit(2, 'h2')));
        await attempt(() => pushEncryptedVaultObject(edit(3, 'h3')));
        return based(state.outbox.E);
    """)
    assert result == [1, "h1"]


def test_a_pull_compares_the_pair():
    source = _function("syncCoreVersion") + _function("reconcileWebDirtyState")
    result = _run_source(source, """(() => {
        const queued = { id: 'E', version: 2, payload_hash: 'h2', base_version: 1, base_payload_hash: 'h1' };
        const same = reconcileWebDirtyState([{ id: 'E', version: 1, payload_hash: 'h1' }], { E: queued }, {});
        const other = reconcileWebDirtyState([{ id: 'E', version: 1, payload_hash: 'x1' }], { E: queued }, {});
        return { same: Object.keys(same.conflicts), sameQueued: Object.keys(same.outbox),
                 other: Object.keys(other.conflicts) };
    })()""")
    assert result == {"same": [], "sameQueued": ["E"], "other": ["E"]}
