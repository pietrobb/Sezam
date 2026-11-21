"""Review e443cbc H2 (INV-7): the open vault's way out of a lost team log.

Since INV-7 a sign-in on a lost log opens the vault (team refused), so the
sign-in screen's forget, the only one that exported and dropped the queue,
is never reached. The Team trust forget (handleForgetTeamPin) refused with
anything queued ("send or resolve the unsent changes first"), and nothing
queued could be sent to a lost log: the browser stayed refused for good.

Every case of tests/vectors/team_log_mismatch.json runs through the Team trust
form with a queued edit, a queued operation and a conflict. Where the log is
lost (the vectors' ``forget``), the forget asks, exports the queued objects,
drops the queue and leaves the log; everywhere else nothing is dropped,
nothing exported and the pin stays (INV-8). Red on e443cbc:
``python -m pytest -q tests/test_r15_web_forget_with_queue.py``.
"""

from __future__ import annotations

import json

import pytest

from tests.node_support import node_problem
from tests.test_inv7_forget_offer import CASES
from tests.test_inv8_forget_acts_only_on_lost import _forgets
from tests.test_review_web import _function, _run_source
from tests.test_team_log_web_rekey import FUNCTIONS, TEAMLOG_JS, _secrets
from tests.test_web_old_kek_records import FAKE_IDB
from tests.team_log_vectors import B

SCRIPT = """
    const cases = %s;
    const out = {};
    const me = %s;
    restoreWebTeamLog = async () => false;
    t = (key, args) => key + (args ? ' ' + JSON.stringify(args) : '');
    const elements = {};
    document = { getElementById: id => (elements[id] ||= {
        value: '', textContent: '', classList: { add() {}, remove() {} } }) };
    let asked = [], exported = [], saved = null;
    window = { confirm: message => { asked.push(message); return true; } };
    ensureSodium = async () => sodium;
    withWebSyncLock = async fn => fn();
    pullAndBuildTreeLocked = async () => {};
    openTeamTrustModal = async () => {};
    exportWebDirtyObjects = objects => { exported.push(...objects); };
    saveWebDirtyState = async (outbox, conflicts, _s, ops) => { saved = { outbox, conflicts, ops }; };
    for (const c of cases) {
        asked = []; exported = []; saved = null;
        state.userId = %s;
        state.kek = newKek;
        state.sessionSerial = 1;
        state.keypair = { signingSk: hexToBytes(me.signingSk), signingPk: hexToBytes(me.signingPk),
                          encryptionSk: hexToBytes(me.encryptionSk) };
        state.confirmedTeamGenesis = c.device.confirmed_genesis;
        state.forgottenTeamGenesis = c.device.forgotten_genesis;
        const local = c.device.records ? { records: c.device.records, team: TL.replay(c.device.records, sodium) } : null;
        state.teamLog = local;
        state.syncCheckpoint = { last_sync_seq: 1, state_hash: 'a'.repeat(64),
                                 team_log: local ? teamLogPin(local.team) : null, timestamp: 1 };
        state.syncCheckpointLoaded = true;
        state.outboxLoaded = true;
        state.outbox = { e1: { id: 'e1', type: 'entry' } };
        state.syncConflicts = { e2: { local_object: { id: 'e2', type: 'entry' } } };
        state.outboxOps = [{ op: 'revoke' }];
        apiFetch = async url => {
            const since = Number(url.split('since=')[1]);
            return { head: c.server.head, records: c.server.records.filter(r => JSON.parse(r.body).seq > since) };
        };
        const pins = webPinnedTeamGenesis();
        let typed = pins.length ? pins[0] : '0'.repeat(16);
        for (const pin of pins) while (!pin.startsWith(typed)) typed = typed.slice(0, -1);
        elements['team-forget-genesis'] = { value: typed, textContent: '', classList: { add() {}, remove() {} } };
        await handleForgetTeamPin({ preventDefault() {} });
        out[c.name] = {
            left: pins.length > 0 && webPinnedTeamGenesis().length === 0,
            dropped: !!saved && !Object.keys(state.outbox).length && !Object.keys(state.syncConflicts).length
                && !state.outboxOps.length,
            exported: exported.map(o => o.id).sort(),
            asked_to_drop: asked.some(m => m.startsWith('team.forget_discard_unsent')),
        };
    }
    return out;
"""


def _expected(case: dict) -> dict:
    lost = _forgets(case)
    return {"left": lost, "dropped": lost, "exported": ["e1", "e2"] if lost else [], "asked_to_drop": lost}


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for app.js")
def test_the_team_trust_forget_leaves_a_lost_log_with_anything_queued():
    names = FUNCTIONS + ["webPinnedTeamGenesis", "forgetWebTeamLogPinLocked", "loadWebLocalStateLocked",
                         "loadSyncCheckpoint", "saveSyncCheckpoint", "syncCheckpointRecordId",
                         "syncCheckpointAAD", "webTeamLogRefusal", "handleForgetTeamPin"]
    helpers = (TEAMLOG_JS + "\nvar ENVELOPE_ALG = 1, SCHEMA_VERSION = 1, TEAM_LOG_PAGES = 1000, "
               "FORGET_PIN_MIN_CHARS = 16, BLOB_KIND = { NODE_META: 1 };\n"
               + "\n".join(_function(n) for n in names))
    script = FAKE_IDB + "\nconst TL = globalThis.SezamTeamLog;\n" + SCRIPT % (
        json.dumps(CASES), json.dumps(_secrets(B)), json.dumps(B.uid))
    got = _run_source(helpers, "(async () => {" + script + "\n})()")
    assert got == {case["name"]: _expected(case) for case in CASES}
