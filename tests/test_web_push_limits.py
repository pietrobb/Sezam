"""Review 526419e #1 (web): what the server can never take is refused up front.

The web pushes one object per request, but an item over the server's 1 MiB
was queued and resent on every retry, and the all-or-nothing batches (member
re-key, org-recovery password change) went out whatever their size and were
refused as a whole for good. Both are now refused before they are queued or
journalled, with the reason.
"""

from __future__ import annotations


from tests.test_review_web import APP, VENDOR, _function, _run_source, pytestmark  # noqa: F401

LIMITS = APP[APP.index("const MAX_PUSH_OBJECTS"):APP.index("function syncPayloadBytes")]


def _run(functions: list[str], script: str):
    helpers = LIMITS + "\n".join(_function(name) for name in functions)
    return _run_source(helpers, f"(async () => {{ {script} }})()")


STUBS = """
globalThis.sent = [];
globalThis.queued = 0;
globalThis.t = (key) => key;
globalThis.apiFetch = async (path, opts) => {
    sent.push(opts.body.objects.length);
    return { accepted: opts.body.objects.map(o => ({ id: o.id })), conflicts: [] };
};
globalThis.ensureSodium = async () => ({});
globalThis.saveWebDirtyState = async () => { queued += 1; };
globalThis.renderWebSyncConflicts = () => {};
globalThis.state.outbox = {};
globalThis.state.syncConflicts = {};
const obj = (id, bytes) => ({ id, payload: Buffer.alloc(bytes).toString('base64') });
async function attempt(fn) {
    try { await fn(); return null; } catch (err) { return err.message; }
}
"""


def test_an_item_over_1_mib_is_never_queued():
    result = _run(
        ["assertNotStackedOnConflict", "assertTeamLogAllowsWrite", "webWriteState", "syncPayloadBytes", "assertSyncObjectFits",
         "pushEncryptedVaultObject", "pushEncryptedVaultObjectLocked", "renumberedAboveBase", "webBase", "withWebBase", "isSameSyncVersion"],
        STUBS + """
        const big = await attempt(() => pushEncryptedVaultObject(obj('B', 1100 * 1024)));
        const bigQueued = Object.keys(state.outbox).length;
        const fits = await attempt(() => pushEncryptedVaultObject(obj('S', 1024 * 1024)));
        return { big, bigQueued, fits, sent };
        """,
    )
    assert result["big"] == "sync.object_too_large"
    assert result["bigQueued"] == 0
    assert result["fits"] is None and result["sent"] == [1]


ATOMIC = [
    "syncPayloadBytes", "assertSyncObjectFits", "assertSyncUnitFits", "splitForPush",
    "postAtomicSyncBatch", "pushWebRekeyBatch", "sendWebTeamRecords", "noteWebTeamRecordsSent", "noteWebTeamRecordsTaken", "generateULID",
]


def test_an_atomic_batch_over_the_server_limits_is_refused_before_sending():
    result = _run(
        ATOMIC,
        STUBS + """
        const many = Array.from({ length: 100001 }, (_, i) => obj('M' + i, 1));
        const tooMany = await attempt(() => pushWebRekeyBatch({ objects: many }));
        const ok = await attempt(() => pushWebRekeyBatch({ objects: many.slice(0, 1000) }));
        return { tooMany, ok, sent };
        """,
    )
    assert result["tooMany"] == "sync.unit_too_large"
    assert result["ok"] is None and result["sent"] == [1000]


def test_an_atomic_batch_over_one_request_is_staged_and_applied_at_once():
    """Review d150605 #3: over 1000 objects (or 15 MiB) a member re-key or the
    org-recovery DEK re-wrap was refused for good; it is staged in parts and
    the last request names the staged batch."""
    result = _run(
        ATOMIC,
        STUBS + """
        const calls = [];
        globalThis.apiFetch = async (path, opts) => {
            const b = opts.body;
            calls.push({ path, n: b.objects.length, start: b.start,
                         batch: b.batch_id || b.staged_batch_id, count: b.staged_count,
                         atomic: b.atomic_batch, epoch: b.key_epoch });
            return path === '/api/sync/stage' ? { staged: b.start + b.objects.length }
                : { accepted: [], conflicts: [] };
        };
        const many = Array.from({ length: 2500 }, (_, i) => obj('M' + i, 10));
        const err = await attempt(() => postAtomicSyncBatch(many, { key_epoch: 4 }));
        const heavy = Array.from({ length: 20 }, (_, i) => obj('H' + i, 900 * 1024));
        const heavyErr = await attempt(() => postAtomicSyncBatch(heavy, { key_epoch: 4 }));
        return { err, heavyErr, calls };
        """,
    )
    assert result["err"] is None and result["heavyErr"] is None
    calls = result["calls"]
    first = calls[:3]
    assert [c["path"] for c in first] == ["/api/sync/stage", "/api/sync/stage", "/api/sync"]
    assert [(c["n"], c["start"]) for c in first[:2]] == [(1000, 0), (1000, 1000)]
    assert first[0]["batch"] == first[1]["batch"] == first[2]["batch"]
    assert first[2]["n"] == 500 and first[2]["count"] == 2000
    assert first[2]["atomic"] is True and first[2]["epoch"] == 4
    heavy = calls[3:]
    assert heavy[-1]["path"] == "/api/sync" and len(heavy) == 2
    assert heavy[-1]["count"] == heavy[0]["n"] and heavy[0]["n"] + heavy[-1]["n"] == 20


def test_journals_are_checked_before_they_are_written():
    prepare = _function("prepareWebRekeyJournal")
    assert prepare.index("assertSyncUnitFits(batch.objects)") < prepare.index("saveWebRekeyJournal")
    assert APP.index("assertSyncUnitFits(rewrappedDeks)") < APP.index(
        "await saveKekRotationJournal(rotationJournal)"
    )
    i18n = (VENDOR.parent / "i18n.js").read_text(encoding="utf-8")
    assert i18n.count("'sync.object_too_large':") == 2
    assert i18n.count("'sync.unit_too_large':") == 2
