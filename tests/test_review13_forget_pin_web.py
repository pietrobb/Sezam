"""Review c78fd19 (medium), web: a browser pinned to a team log the server lost
for good leaves it ("Team trust -> Forget the pinned team log") after typing
the pinned genesis, and then follows the server's log as a new one.
"""

from __future__ import annotations

import json

from tests.team_log_vectors import B, D, Log
from tests.test_review_web import _function, _run_source, pytestmark  # noqa: F401
from tests.test_team_log_web_rekey import FUNCTIONS, TEAMLOG_JS, _secrets
from tests.test_web_old_kek_records import FAKE_IDB

EXTRA = [
    "webPinnedTeamGenesis", "forgetWebTeamLogPinLocked", "loadWebLocalStateLocked",
    "loadSyncCheckpoint", "saveSyncCheckpoint", "syncCheckpointRecordId", "syncCheckpointAAD",
]
OLD = Log().genesis().member(B)
NEW = Log().genesis(D)


def _run(script: str):
    prelude = FAKE_IDB + f"""
      const TL = globalThis.SezamTeamLog;
      const OLD = {json.dumps(OLD.records)};
      const NEW = {json.dumps(NEW.records)};
      const me = {json.dumps(_secrets(B))};
      state.userId = {json.dumps(B.uid)};
      state.kek = newKek;
      state.sessionSerial = 1;
      state.keypair = {{ signingSk: hexToBytes(me.signingSk), signingPk: hexToBytes(me.signingPk),
                        encryptionSk: hexToBytes(me.encryptionSk) }};
      t = (key, args) => key + (args ? ' ' + JSON.stringify(args) : '');
      const old = {{ records: OLD, team: TL.replay(OLD, sodium) }};
      const fresh = TL.replay(NEW, sodium);
      const want = old.team.genesisHash;
      const pull = async () => {{
        apiFetch = async () => ({{ records: NEW }});
        try {{
          const got = await syncWebTeamLog(teamLogPin(fresh), state.teamLog, state.syncCheckpoint?.team_log, sodium);
          return got.team.genesisHash === fresh.genesisHash;
        }} catch (err) {{ return err.message; }}
      }};
      const forget = async typed => {{
        try {{ return await forgetWebTeamLogPinLocked(typed, 1, sodium); }} catch (err) {{ return err.message; }}
      }};
      // This browser followed and confirmed the old log.
      state.teamLog = old;
      await saveConfirmedTeamGenesis(want, sodium);
      state.syncCheckpoint = {{ last_sync_seq: 3, state_hash: 'a'.repeat(64), team_log: teamLogPin(old.team),
                               timestamp: 1 }};
      await saveSyncCheckpoint(state.syncCheckpoint, sodium);
      state.syncCheckpointLoaded = true;
    """
    helpers = (TEAMLOG_JS + "\nvar ENVELOPE_ALG = 1, SCHEMA_VERSION = 1, TEAM_LOG_PAGES = 1000, "
               "FORGET_PIN_MIN_CHARS = 16, BLOB_KIND = { NODE_META: 1 };\n"
               + "\n".join(_function(n) for n in FUNCTIONS + EXTRA))
    return _run_source(helpers, "(async () => {" + prelude + script + "\n})()")


def test_a_browser_leaves_a_lost_log_and_follows_the_new_one():
    result = _run("""
        const before = await pull();
        const refused = [];
        for (const typed of ['', want.slice(0, 15), fresh.genesisHash.slice(0, 16), 'f'.repeat(64)]) {
            refused.push(await forget(typed));
        }
        state.outboxOps = [{ op: 'x' }];
        const unsent = await forget(want.slice(0, 16));
        state.outboxOps = [];
        const stillPinned = webPinnedTeamGenesis();
        const left = await forget(want.slice(0, 16).toUpperCase());
        const reloaded = await loadSyncCheckpoint(sodium);
        return { before, refused, unsent, stillPinned, left, after: await pull(),
                 confirmed: await loadConfirmedTeamGenesis(sodium),
                 forgotten: await loadForgottenTeamGenesis(sodium),
                 checkpointLog: reloaded.team_log, pins: webPinnedTeamGenesis() };
    """)
    assert result["before"].startswith("TEAM LOG MISMATCH") and "Forget the pinned team log" in result["before"]
    assert all(r.startswith("team.forget_typed") for r in result["refused"]), result["refused"]
    assert result["unsent"] == "team.forget_unsent"
    want = OLD.state.genesis_hash
    assert result["stillPinned"] == [want]
    assert result["left"] == [want]
    assert result["after"] is True
    assert result["confirmed"] is None and result["checkpointLog"] is None
    assert result["forgotten"] == [want] and result["pins"] == []


def test_the_account_bundle_does_not_pin_a_forgotten_log_again_until_confirmed():
    result = _run("""
        await forget(want);
        state.keypair.confirmedGenesis = want;  // the server's account bundle still names it
        await importAccountTeamAnchor(sodium);
        const afterImport = { confirmed: await loadConfirmedTeamGenesis(sodium),
                              keypair: state.keypair.confirmedGenesis };
        await saveConfirmedTeamGenesis(want, sodium);  // the user confirms it again (invitation, founder)
        return { afterImport, confirmed: await loadConfirmedTeamGenesis(sodium),
                 forgotten: await loadForgottenTeamGenesis(sodium) };
    """)
    want = OLD.state.genesis_hash
    assert result["afterImport"] == {"confirmed": None, "keypair": None}
    assert result["confirmed"] == want and result["forgotten"] == []
