"""Review c02cc47 R17-L (web): the Team trust forget dropped every queued
write, also the personal ones INV-7 rule 1 sends under the refused log. Only
the team's are exported and dropped now; a personal write and a conflict over
one stay queued."""

from __future__ import annotations

import json

import pytest

from tests.node_support import node_problem
from tests.test_inv7_forget_offer import CASES
from tests.test_inv8_forget_acts_only_on_lost import _forgets
from tests.test_r15_web_forget_with_queue import SCRIPT as QUEUE_SCRIPT
from tests.test_review_web import _function, _run_source
from tests.test_team_log_web_rekey import FUNCTIONS, TEAMLOG_JS, _secrets
from tests.test_web_old_kek_records import FAKE_IDB
from tests.team_log_vectors import B

PERSONAL_DEK = "01JD0000000000000000000P01"
TEAM_DEK = "01JD0000000000000000000T01"

# The queue of the R15 test, with one personal and one team write in place of
# its untyped ones; the personal folder P is this account's, signed by it and
# sealed under its own key (a personal root has one: core authority::personal_tree).
QUEUE = """
        btoa = value => Buffer.from(value, 'binary').toString('base64');
        atob = value => Buffer.from(value, 'base64').toString('binary');
        const sealed = dek => {
            const env = new Uint8Array(60); env[0] = ENVELOPE_ALG; env[1] = SCHEMA_VERSION;
            env.set(new TextEncoder().encode(dek), 3);
            const out = new Uint8Array(64); out.set(env, 4); return bytesToBase64(out);
        };
        state.deks = { '%(p)s': new Uint8Array(32) };
        state.nodes = { P: { id: 'P', personal: true, parent_ref: null, dekId: '%(p)s' },
                        T: { id: 'T', parent_ref: null, dekId: '%(t)s' } };
        state.syncObjects = { P: { id: 'P', signer: state.userId }, T: { id: 'T', signer: state.userId } };
        const personalEntry = id => ({ id, object_type: 'entry', parent_ref: 'P', is_deleted: 0, payload: sealed('%(p)s') });
        state.outbox = { e1: personalEntry('e1'),
                         e3: { id: 'e3', object_type: 'entry', parent_ref: 'T', is_deleted: 0, payload: sealed('%(t)s') } };
        state.syncConflicts = { e2: { local_object: personalEntry('e2') } };
""" % {"p": PERSONAL_DEK, "t": TEAM_DEK}

OLD_QUEUE = """
        state.outbox = { e1: { id: 'e1', type: 'entry' } };
        state.syncConflicts = { e2: { local_object: { id: 'e2', type: 'entry' } } };
"""

RESULT = "            exported: exported.map(o => o.id).sort(),\n"


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for app.js")
def test_the_forget_keeps_the_personal_writes_rule_1_sends():
    assert OLD_QUEUE in QUEUE_SCRIPT and RESULT in QUEUE_SCRIPT
    script = QUEUE_SCRIPT.replace(OLD_QUEUE, QUEUE).replace(
        RESULT, RESULT + "            kept: [...Object.keys(state.outbox), ...Object.keys(state.syncConflicts)].sort(),\n")
    names = FUNCTIONS + ["webPinnedTeamGenesis", "forgetWebTeamLogPinLocked", "loadWebLocalStateLocked",
                         "loadSyncCheckpoint", "saveSyncCheckpoint", "syncCheckpointRecordId",
                         "syncCheckpointAAD", "webTeamLogRefusal", "handleForgetTeamPin",
                         "bytesToBase64", "base64ToBytes"]
    helpers = (TEAMLOG_JS + "\nvar ENVELOPE_ALG = 1, SCHEMA_VERSION = 1, TEAM_LOG_PAGES = 1000, "
               "FORGET_PIN_MIN_CHARS = 16, BLOB_KIND = { NODE_META: 1 };\n"
               + "\n".join(_function(n) for n in names))
    lost = [case for case in CASES if _forgets(case)]
    assert lost
    full = FAKE_IDB + "\nconst TL = globalThis.SezamTeamLog;\n" + script % (
        json.dumps(lost), json.dumps(_secrets(B)), json.dumps(B.uid))
    got = _run_source(helpers, "(async () => {" + full + "\n})()")
    for case in lost:
        result = got[case["name"]]
        assert result["left"] and result["asked_to_drop"], (case["name"], result)
        assert result["exported"] == ["e3"], (case["name"], result)
        assert result["kept"] == ["e1", "e2"], (case["name"], result)
