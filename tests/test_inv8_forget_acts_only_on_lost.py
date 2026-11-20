"""INV-8 (docs/ROOT_CAUSE_PLAN.md, review 8bc70f7 H4): "forget the pinned team
log" acts exactly where the device, following the server's log now, refuses it
as lost for good (tests/vectors/team_log_mismatch.json: the server has none
while the device holds, pins or confirmed one, or it starts with another
genesis). It never leaves a log for a server that lies (behind, a fork, a log
that does not replay, short of its head, TL7) or that the device follows.

INV-7 (tests/test_inv7_forget_offer.py) decides where it is offered; this is
the action itself, whichever screen reaches it (CLI, Team trust, the sign-in
screen, the phone's settings). Before, each client's forget checked only the
typed genesis and unsent changes: offered or not, it left any pinned log,
a forked one included.

Every case of the vectors runs through each client's own forget, with the
genesis typed right: the desktop (forget_team_log_pin) and the page
(forgetWebTeamLogPinLocked) here, the phone (SyncService.forgetTeamLogPin) in
mobile/test/team_log_forget_acts_vectors_test.dart. The same files run on the
code before (a forget without the server's judgment is called as it was).
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sezam import teamlog as tl
from sezam.vault.db import VaultDB
from sezam.vault.team_log_forget import forget_team_log_pin, pinned_genesis
from sezam.vault.team_log_local import CONFIRMED_GENESIS_META, FORGOTTEN_GENESIS_META, GENESIS_META
from tests.node_support import node_problem
from tests.test_inv7_forget_offer import CASES, _Device
from tests.test_review_web import APP, _function, _run_source
from tests.test_team_log_web_rekey import FUNCTIONS, TEAMLOG_JS, _secrets
from tests.test_web_old_kek_records import FAKE_IDB
from tests.team_log_vectors import B


def _seq(record: dict) -> int:
    return tl.parse_body(record["body"])["seq"]


def _forgets(case: dict) -> bool:
    return case["expect"].get("forget") is True


def _typed(pins) -> str:
    """The pinned genesis typed right: the common start of every pin."""
    pins = sorted(pins)
    if not pins:
        return "0" * 16
    common = pins[0]
    for pin in pins[1:]:
        while not pin.startswith(common):
            common = common[:-1]
    return common


class _Served(_Device):
    """The desktop follower; the server serves the case's records and head."""

    _token = "token"

    def __init__(self, db, served, head):
        super().__init__(db, served)
        self._head = head

    def _request(self, method, path, body=None, auth=False):
        assert method == "GET" and path.startswith("/api/team-log?since="), path
        since = int(path.split("since=", 1)[1])
        return {"head": self._head, "records": [r for r in self._served if _seq(r) > since]}


def _desktop(tmp_path: Path, case: dict) -> bool:
    db = VaultDB(tmp_path / (case["name"].replace("/", "-") + ".db"))
    db.open()
    db.create_schema()
    try:
        held = case["device"]
        device = _Served(db, case["server"]["records"], case["server"]["head"])
        if held["records"]:
            device._store_team_log(held["records"], tl.replay(held["records"]))
            db.set_meta(GENESIS_META, tl.replay(held["records"]).genesis_hash)
        if held["confirmed_genesis"]:
            db.set_meta(CONFIRMED_GENESIS_META, held["confirmed_genesis"])
        if held["forgotten_genesis"]:
            db.set_meta_json(FORGOTTEN_GENESIS_META, held["forgotten_genesis"])
        vault = SimpleNamespace(db=db, keypair=SimpleNamespace(confirmed_genesis=None))
        typed = _typed(pinned_genesis(vault))
        asks_server = "client" in inspect.signature(forget_team_log_pin).parameters
        try:
            forget_team_log_pin(vault, typed, device) if asks_server else forget_team_log_pin(vault, typed)
        except (ValueError, RuntimeError):
            return False
        assert not pinned_genesis(vault), case["name"]
        return True
    finally:
        db.close()


def test_the_desktop_forgets_exactly_where_the_log_is_lost(tmp_path):
    got = {case["name"]: _desktop(tmp_path, case) for case in CASES}
    assert got == {case["name"]: _forgets(case) for case in CASES}


WEB_SCRIPT = """
    const cases = %s;
    const out = {};
    const me = %s;
    restoreWebTeamLog = async () => false;  // a restore that lands is INV-2
    t = (key, args) => key + (args ? ' ' + JSON.stringify(args) : '');
    for (const c of cases) {
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
        state.outbox = {}; state.outboxOps = []; state.syncConflicts = {};
        apiFetch = async url => {
            const since = Number(url.split('since=')[1]);
            return { head: c.server.head, records: c.server.records.filter(r => JSON.parse(r.body).seq > since) };
        };
        const pins = webPinnedTeamGenesis();
        let typed = pins.length ? pins[0] : '0'.repeat(16);
        for (const pin of pins) while (!pin.startsWith(typed)) typed = typed.slice(0, -1);
        try {
            await forgetWebTeamLogPinLocked(typed, 1, sodium);
            out[c.name] = webPinnedTeamGenesis().length === 0;
        } catch (err) {
            out[c.name] = false;
        }
    }
    return out;
"""


def _web() -> dict:
    extra = ["webPinnedTeamGenesis", "forgetWebTeamLogPinLocked", "loadWebLocalStateLocked",
             "loadSyncCheckpoint", "saveSyncCheckpoint", "syncCheckpointRecordId", "syncCheckpointAAD"]
    if "function webTeamLogRefusal(" in APP:
        extra.append("webTeamLogRefusal")
    helpers = (TEAMLOG_JS + "\nvar ENVELOPE_ALG = 1, SCHEMA_VERSION = 1, TEAM_LOG_PAGES = 1000, "
               "FORGET_PIN_MIN_CHARS = 16, BLOB_KIND = { NODE_META: 1 };\n"
               + "\n".join(_function(n) for n in FUNCTIONS + extra))
    script = FAKE_IDB + "\nconst TL = globalThis.SezamTeamLog;\n" + WEB_SCRIPT % (
        json.dumps(CASES), json.dumps(_secrets(B)), json.dumps(B.uid))
    return _run_source(helpers, "(async () => {" + script + "\n})()")


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for app.js")
def test_the_page_forgets_exactly_where_the_log_is_lost():
    got = _web()
    assert got == {case["name"]: _forgets(case) for case in CASES}
