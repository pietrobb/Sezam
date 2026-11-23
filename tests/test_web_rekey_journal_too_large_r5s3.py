"""Review d150605 S3 (web): a re-key journal too large to send had no way out.

A member re-key journalled by an older version (before the size check) with
an object over 1 MiB, or with more than the server takes in one batch, was
refused by postAtomicSyncBatch on every Retry. finishWebRevocation rethrew
it, so the journal stayed for good, Retry sent nothing else, and every other
revocation was refused ('A different user revocation is still pending').
Now the journal is rebuilt once from the server's state; if that still does
not fit, it is dropped (nothing of it reached the server) and the admin is
told that the member was NOT removed. Retry goes on with the rest.
"""

from __future__ import annotations

from tests.test_review_web import pytestmark  # noqa: F401
from tests.test_web_push_limits import STUBS, _run

FUNCTIONS = [
    "syncPayloadBytes", "assertSyncObjectFits", "assertSyncUnitFits", "splitForPush",
    "postAtomicSyncBatch", "pushWebRekeyBatch", "sendWebTeamRecords", "noteWebTeamRecordsSent", "noteWebTeamRecordsTaken", "prepareWebRekeyJournal",
    "finishWebRevocation", "retryAllWebDirtyObjects", "oversizedQueuedObjects",
    "assertNotStackedOnConflict", "assertTeamLogAllowsWrite", "pushEncryptedVaultObject", "pushEncryptedVaultObjectLocked", "renumberedAboveBase", "webBase", "withWebBase", "isSameSyncVersion",
]

SETUP = STUBS + """
const calls = [];
let journal = { revoked_user_id: 'BOB', phase: 'prepared',
                objects: [obj('OLD', 1100 * 1024)] };
globalThis.state.userId = 'ME';
globalThis.pendingWebRevocations = async () => (journal ? ['BOB'] : []);
globalThis.loadWebRekeyJournal = async () => (journal ? JSON.parse(JSON.stringify(journal)) : null);
globalThis.saveWebRekeyJournal = async (value) => { journal = JSON.parse(JSON.stringify(value)); };
globalThis.clearWebRekeyJournal = async () => { calls.push('clear'); journal = null; };
globalThis.pullAndBuildTree = async () => {};
globalThis.resealUnderFolderSuccessor = async (o) => o;
globalThis.generateULID = () => 'B1';
globalThis.apiFetch = async (path, opts) => {
    if (opts.method === 'DELETE') { calls.push('DELETE ' + path); return {}; }
    calls.push('sync ' + opts.body.objects.map(o => o.id).join(','));
    return { accepted: opts.body.objects.map(o => ({ id: o.id })), conflicts: [] };
};
"""


def test_a_journal_that_never_fits_is_dropped_and_the_retry_goes_on():
    result = _run(
        FUNCTIONS,
        SETUP + """
        globalThis.buildWebRekeyBatch = async () => ({ objects: [obj('NEW', 1100 * 1024)],
                                                      folders_rekeyed: 1 });
        state.outbox = { U1: { ...obj('U1', 10), version: 2 } };
        const err = await attempt(() => retryAllWebDirtyObjects());
        return { err, calls, journal, left: Object.keys(state.outbox) };
        """,
    )
    assert result["err"] == "admin.rekey_too_large"
    assert result["calls"] == ["clear", "sync U1"]  # no DELETE: the member stays
    assert result["journal"] is None
    assert result["left"] == []


def test_a_journal_from_an_older_version_is_rebuilt_when_it_fits_now():
    result = _run(
        FUNCTIONS,
        SETUP + """
        globalThis.buildWebRekeyBatch = async () => ({ objects: [obj('NEW', 10)],
                                                      folders_rekeyed: 1 });
        const err = await attempt(() => finishWebRevocation('BOB', {}));
        return { err, calls, journal };
        """,
    )
    assert result["err"] is None
    assert result["calls"] == ["sync NEW", "DELETE /api/users/BOB", "clear"]
