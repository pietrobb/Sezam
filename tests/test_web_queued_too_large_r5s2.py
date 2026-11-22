"""Review d150605 S2 (web): an old queued object over 1 MiB blocked everything.

An older web version queued an item over the server's 1 MiB limit. Retry
pushed the queue in order and stopped at it (assertSyncObjectFits threw), so
no change queued after it was ever sent, and nothing offered to drop it.
Deleting the entry did not help either: its tombstone carried the same
content and was refused too. Now Retry sends the rest and names the oversized
change, the conflict bar offers to drop it, and its tombstone keeps only the
name and tags.
"""

from __future__ import annotations

from tests.test_review_web import APP, VENDOR, _function, pytestmark  # noqa: F401
from tests.test_web_push_limits import STUBS, _run

PUSH = [
    "assertNotStackedOnConflict", "assertTeamLogAllowsWrite", "syncPayloadBytes", "assertSyncObjectFits",
    "pushEncryptedVaultObject", "pushEncryptedVaultObjectLocked", "renumberedAboveBase", "webBase", "withWebBase", "isSameSyncVersion",
]


def test_retry_sends_the_rest_and_names_the_oversized_change():
    result = _run(
        PUSH + ["retryAllWebDirtyObjects"] + (
            ["oversizedQueuedObjects"] if "function oversizedQueuedObjects" in APP else []
        ),
        STUBS + """
        globalThis.pendingWebRevocations = async () => [];
        globalThis.pullAndBuildTree = async () => {};
        globalThis.resealUnderFolderSuccessor = async (o) => o;
        const big = obj('BIG', 1100 * 1024);
        const small = { ...obj('SMALL', 10), version: 2 };
        state.outbox = { BIG: big, SMALL: small };
        const err = await attempt(() => retryAllWebDirtyObjects());
        return { err, sent, left: Object.keys(state.outbox) };
        """,
    )
    assert result["err"] == "sync.queued_too_large"
    assert result["sent"] == [1]  # SMALL went out
    assert result["left"] == ["BIG"]  # stays until dropped, shortened or deleted


def test_the_bar_offers_to_drop_it_and_the_tombstone_fits():
    banner = _function("renderWebSyncConflicts")
    assert "oversizedQueuedObjects()" in banner
    assert "discardWebConflictedChanges(oversized.map(" in banner
    delete = _function("handleDeleteConfirm")
    assert "entryPayload.length > MAX_OBJECT_PAYLOAD_BYTES" in delete
    assert "{ ...entryData, fields: [] }" in delete
    i18n = (VENDOR.parent / "i18n.js").read_text(encoding="utf-8")
    for key in ("sync.queued_too_large", "sync.queued_object_too_large",
                "sync.drop_too_large", "sync.drop_too_large_confirm"):
        assert i18n.count(f"'{key}':") == 2, key


def test_deleting_an_oversized_entry_sends_a_tombstone_that_fits():
    result = _run(
        ["handleDeleteConfirm"],
        """
        globalThis.t = (key) => key;
        const el = () => ({ classList: { add() {}, remove() {} }, dataset: { entryId: 'E' } });
        const els = {};
        globalThis.document.getElementById = (id) => (els[id] = els[id] || el());
        globalThis.ensureSodium = async () => ({});
        globalThis.canEditObject = () => true;
        globalThis.resolveWriteDekId = () => 'D';
        globalThis.state.deks = { D: new Uint8Array(32) };
        globalThis.state.entries = { E: { id: 'E', name: 'big', version: 3,
            fields: [{ key: 'note', value: 'x'.repeat(1100 * 1024) }] } };
        globalThis.encryptEntryPayload = (data) =>
            new Uint8Array(100 + JSON.stringify(data.fields).length);
        globalThis.bytesToBase64 = (b) => Buffer.from(b).toString('base64');
        globalThis.base64ToBytes = (s) => Buffer.from(s, 'base64');
        globalThis.sha256hexBytes = async () => '00';
        globalThis.signSyncObject = () => new Uint8Array(64);
        globalThis.hexToBytes = () => new Uint8Array(1);
        globalThis.bytesToHex = () => 'ff';
        globalThis.closeDeleteModal = () => {};
        globalThis.logFieldAccess = () => {};
        globalThis.pullAndBuildTree = async () => {};
        const alerts = [];
        globalThis.alert = (m) => alerts.push(m);
        const pushed = [];
        globalThis.pushEncryptedVaultObject = async (o) => {
            if (Buffer.from(o.payload, 'base64').length > 1024 * 1024) {
                throw new Error('sync.object_too_large');
            }
            pushed.push(o.is_deleted);
        };
        await handleDeleteConfirm();
        return { alerts, pushed };
        """,
    )
    assert result["alerts"] == []
    assert result["pushed"] == [1]
