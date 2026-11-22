"""The web client follows the signed team log (TL5; docs/DESIGN_TEAM_LOG.md §4.3, §6).

A lying server: serves another log than the browser saw, or objects the log
gives their author no right to. In a team folder the log alone decides what
the browser shows and what it seals; write envelopes and accounts the server
takes for admins decide nothing there.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.team_log_vectors import A, B, C, D, F1, ITEM, K, Log
from tests.test_review_web import _function, _run_source, pytestmark  # noqa: F401

TEAMLOG_JS = (Path(__file__).parents[1] / "web" / "static" / "js" / "teamlog.js").read_text(encoding="utf-8")
FUNCTIONS = [
    "syncWebTeamLog", "catchUpWebTeamLog", "followOwnAccountFork", "ownTeamChange", "teamLogPin", "webTeamFolderAbove", "unauthorizedWrites", "sealingDekId",
    "isEncryptedEnvelope", "teamLogRefusedError", "assertTeamLogAllowsWrite", "payloadDekId",
    "nearestFolderDekId", "keyAuthors", "folderTreeOwner", "provenDekSuccessors", "ulidTimeMs", "webTeamLogTrusted", "webFounderLineage",
    "webLogAdmins", "restoreWebTeamLog",
]
ROOT = "01JR0000000000000000000001"
OTHER = "01JR0000000000000000000002"  # a folder outside every team folder
ITEM2 = "01JE0000000000000000000002"


def _run(script: str, log: Log, served: Log | None = None):
    prelude = f"""
      const TL = globalThis.SezamTeamLog;
      const RECORDS = {json.dumps(log.records)};
      const SERVED = {json.dumps((served or log).records)};
      const ids = {json.dumps({"A": A.uid, "B": B.uid, "C": C.uid, "D": D.uid, "F1": F1, "ITEM": ITEM,
                                "ITEM2": ITEM2, "ROOT": ROOT, "OTHER": OTHER, "K1": K[1], "K2": K[2],
                                "K9": K[9]})};
      const fetched = [];
      // GET /api/team-log?since=N, pages of 2 records
      apiFetch = async url => {{
        fetched.push(url);
        const since = Number(/since=(-?\\d+)/.exec(url)[1]);
        return {{ records: SERVED.slice(since + 1, since + 3) }};
      }};
      const teamOf = records => TL.replay(records, sodium);
      const headOf = records => TL.stateToJson(teamOf(records));
      const head = records => {{ const s = headOf(records);
        return {{ seq: s.head_seq, hash: s.head_hash, genesis_hash: s.genesis_hash }}; }};
      // A node / entry payload whose header names dekId (bytes 3..29).
      const sealed = (dekId, kind = 'node') => {{
        const bytes = new Uint8Array(60); bytes[0] = 1; bytes[1] = 1; bytes[2] = 1;
        bytes.set(new TextEncoder().encode(dekId), 3);
        const out = kind === 'entry' ? new Uint8Array([0, 0, 0, 60, ...bytes]) : bytes;
        return Buffer.from(out).toString('base64');
      }};
      const rec = (id, object_type, parent_ref, signer, dek, extra = {{}}) => ({{
        id, object_type, parent_ref, signer, owner_id: signer, version: 1, is_deleted: 0,
        payload: dek ? sealed(dek, object_type) : '', ...extra }});
    """
    if script.lstrip().startswith("(async"):
        script = "return " + script.lstrip()
    return _run_source(TEAMLOG_JS + "\nvar ENVELOPE_ALG = 1, SCHEMA_VERSION = 1, TEAM_LOG_PAGES = 1000;\n" + "\n".join(_function(n) for n in FUNCTIONS),
                       "(async () => {" + prelude + script + "\n})()")


# ── Following the server's log ────────────────────────────────────────────


def test_invitation_anchor_rejects_missing_or_other_genesis_before_fetch():
    log = Log().genesis().member(B)
    result = _run("""(async () => {
        state.confirmedTeamGenesis = teamOf(RECORDS).genesisHash;
        const refusals = [];
        for (const announced of [null, head(SERVED)]) {
            try { await syncWebTeamLog(announced, null, null, sodium); refusals.push('accepted'); }
            catch (err) { refusals.push(err.message); }
        }
        return { refusals, fetched };
    })()""", log, served=Log().genesis(D))
    assert all(message.startswith("TEAM LOG MISMATCH") for message in result["refusals"])
    # Goal #440: only the first page, whose genesis decides the cause (the
    # head is unsigned); nothing past it.
    assert result["fetched"] == ["/api/team-log?since=-1"] * 2


def test_a_fresh_browser_replays_the_whole_log_in_pages():
    log = Log().genesis().member(B).member(C).key(F1, 0, K[1], None).access(F1, B, "write")
    result = _run("""(async () => {
        const got = await syncWebTeamLog(head(RECORDS), null, null, sodium);
        return { seq: got.team.headSeq, n: got.records.length, fetched, pin: teamLogPin(got.team),
                 want: head(RECORDS) };
    })()""", log)
    assert result["seq"] == 4 and result["n"] == 5
    assert result["fetched"] == ["/api/team-log?since=-1", "/api/team-log?since=1", "/api/team-log?since=3"]
    assert result["pin"] == result["want"]


def test_records_after_the_pulls_head_wait_for_the_next_pull():
    log = Log().genesis().member(B)
    longer = Log().genesis().member(B).member(C)
    result = _run("""(async () => {
        const got = await syncWebTeamLog(head(RECORDS), null, null, sodium);
        return got.team.headSeq;
    })()""", log, served=longer)
    assert result == 1


def _mismatch(script: str, log: Log, served: Log | None = None) -> str:
    return _run(f"""(async () => {{
        try {{ {script} }} catch (err) {{ return err.message; }}
        return 'accepted';
    }})()""", log, served)


def test_a_log_forked_at_the_pinned_record_is_refused_after_a_reload():
    seen = Log().genesis().member(B).member(C)
    forked = Log().genesis().member(B).member(D).member(C)
    message = _mismatch("""
        const pin = teamLogPin(teamOf(RECORDS));  // the checkpoint of the last session
        await syncWebTeamLog(head(SERVED), null, pin, sodium);
    """, seen, served=forked)
    assert message.startswith("TEAM LOG MISMATCH") and "differs at record 2" in message


def test_a_shorter_log_than_the_pinned_one_is_refused():
    seen = Log().genesis().member(B).member(C)
    message = _mismatch("""
        const pin = teamLogPin(teamOf(RECORDS));
        await syncWebTeamLog(head(RECORDS.slice(0, 2)), null, pin, sodium);
    """, seen)
    assert "went back (head 1 < 2)" in message


def test_a_server_without_the_log_this_browser_saw_is_refused():
    seen = Log().genesis().member(B)
    assert "is gone" in _mismatch(
        "await syncWebTeamLog(null, null, teamLogPin(teamOf(RECORDS)), sodium);", seen, served=Log())
    # Goal #440: no head over the records of the same log is a lie, not a loss.
    assert "head names another genesis" in _mismatch(
        "await syncWebTeamLog(null, null, teamLogPin(teamOf(RECORDS)), sodium);", seen)
    other = Log().genesis(D)
    assert "another genesis" in _mismatch("""
        const local = { records: RECORDS, team: teamOf(RECORDS) };
        await syncWebTeamLog(head(SERVED), local, null, sodium);
    """, seen, served=other)


def test_a_head_the_served_records_do_not_reach_is_refused():
    log = Log().genesis().member(B).member(C)
    message = _mismatch("""
        const announced = head(RECORDS);
        await syncWebTeamLog(announced, null, null, sodium);
    """, log, served=Log().genesis().member(B))
    assert "does not reach the head it announced" in message


def test_a_forged_record_does_not_replay():
    honest = Log().genesis().member(B).member(C)
    forged = Log()
    forged.records = honest.records[:2] + [{**honest.records[2], "sig": "00" * 64}]
    message = _mismatch("""
        const seen = RECORDS.slice(0, 2);
        await syncWebTeamLog(head(RECORDS), { records: seen, team: teamOf(seen) }, null, sodium);
    """, honest, served=forged)
    assert "does not replay" in message


def test_a_head_with_two_admins_is_refused_but_a_handover_is_followed():
    """TL7 (review 1141a20): one admin per organisation, as the server rules,
    in every client; records may pass through two within one handover."""
    two = Log().genesis().member(B).add("member.role", A, {"user_id": B.uid, "role": "admin"})
    assert "is refused at its head: more than one admin" in _mismatch(
        "await syncWebTeamLog(head(RECORDS), null, null, sodium);", two)
    handed = Log().genesis().member(B).add("member.role", A, {"user_id": B.uid, "role": "admin"})
    handed.add("member.role", A, {"user_id": A.uid, "role": "member"})
    result = _run("""(async () => {
        const got = await syncWebTeamLog(head(RECORDS), null, null, sodium);
        return got.team.headSeq;
    })()""", handed)
    assert result == 3


# ── What the browser shows in a team folder ──────────────────────────────

TEAM = Log().genesis().member(B).member(C).key(F1, 0, K[1], None).access(F1, B, "write").access(F1, C, "read")
SNAPSHOT = """
  const team = teamOf(RECORDS);
  const objects = Object.fromEntries([
    rec(ids.ROOT, 'node', null, ids.A, ids.K9),
    rec(ids.F1, 'node', ids.ROOT, ids.A, ids.K1),
    rec(ids.OTHER, 'node', ids.ROOT, ids.A, ids.K9),
    rec(ids.K1, 'dek', ids.F1, ids.A, null),
  ].map(o => [o.id, o]));
  const put = (...recs) => { for (const r of recs) objects[r.id] = r; return objects; };
  const blocked = (objs, prev = null) => {
    const out = unauthorizedWrites(objs, ids.A, team, prev);
    return { blocked: [...out].sort(), byTeamLog: [...out.byTeamLog].sort() };
  };
"""


def test_the_log_decides_who_writes_in_a_team_folder():
    result = _run(SNAPSHOT + """
      // The server says Dan is an admin (he signed an envelope) and gave Carol a write envelope.
      put(rec('ENV1', 'envelope', ids.K1, ids.D, null, { target_user_id: ids.D, access_level: 'write' }),
          rec('ENV2', 'envelope', ids.K1, ids.A, null, { target_user_id: ids.C, access_level: 'write' }),
          rec('BOB_ITEM', 'entry', ids.F1, ids.B, ids.K1),
          rec('CAROL_ITEM', 'entry', ids.F1, ids.C, ids.K1),
          rec('DAN_ITEM', 'entry', ids.F1, ids.D, ids.K1),
          rec('DAN_DIR', 'node', ids.F1, ids.D, ids.K1),
          rec('BELOW_DAN', 'entry', 'DAN_DIR', ids.B, ids.K1));
      return blocked(objects);
    """, TEAM)
    assert result["blocked"] == ["BELOW_DAN", "CAROL_ITEM", "DAN_DIR", "DAN_ITEM"]
    assert result["byTeamLog"] == result["blocked"]


def test_an_old_or_unknown_key_is_not_the_folders_key():
    rekeyed = Log().genesis().member(B).member(C).key(F1, 0, K[1], None).access(F1, B, "write") \
        .key(F1, 1, K[2], K[1])
    result = _run(SNAPSHOT + """
      objects[ids.F1].payload = sealed(ids.K2);  // the re-key sealed the folder again
      put(rec('OLD', 'entry', ids.F1, ids.B, ids.K1),
          rec('NEW', 'entry', ids.F1, ids.B, ids.K2),
          rec('ALIEN', 'entry', ids.F1, ids.B, ids.K9),        // a key someone else made
          rec(ids.K9, 'dek', null, ids.A, null),
          rec('OWN_KEY', 'dek', null, ids.B, null),
          rec('PERSONAL', 'entry', ids.F1, ids.B, 'OWN_KEY'));
      return blocked(objects);
    """, rekeyed)
    # Bob's own personal key with write access is the server's rule too (finding 204).
    assert result["blocked"] == ["ALIEN", "OLD"]


def test_a_refused_removal_or_move_out_keeps_what_was_shown():
    result = _run(SNAPSHOT + """
      put(rec('BOB_ITEM', 'entry', ids.F1, ids.B, ids.K1), rec('BOB_ITEM2', 'entry', ids.F1, ids.B, ids.K1));
      const previous = JSON.parse(JSON.stringify(objects));
      put(rec('BOB_ITEM', 'entry', ids.F1, ids.C, null, { version: 2, is_deleted: 1 }),
          rec('BOB_ITEM2', 'entry', ids.OTHER, ids.C, ids.K9, { version: 2 }));
      const byCarol = blocked(objects, previous);
      // Bob moves his item into his own tree (review 1141a20 H6: the admin's
      // unshared folder OTHER is no folder of his to write in).
      put(rec('BOB_KEY', 'dek', null, ids.B, null),
          rec('BOB_HOME', 'node', ids.ROOT, ids.B, 'BOB_KEY'),
          rec('BOB_ITEM', 'entry', ids.F1, ids.B, null, { version: 2, is_deleted: 1 }),
          rec('BOB_ITEM2', 'entry', 'BOB_HOME', ids.B, 'BOB_KEY', { version: 2 }));
      const byBob = blocked(objects, previous);
      put(rec('BOB_ITEM2', 'entry', ids.OTHER, ids.B, ids.K9, { version: 2 }));
      return { byCarol, byBob, intoAdminFolder: blocked(objects, previous) };
    """, TEAM)
    assert result["byCarol"]["byTeamLog"] == ["BOB_ITEM", "BOB_ITEM2"]
    assert result["byBob"]["blocked"] == []
    assert result["intoAdminFolder"]["blocked"] == ["BOB_ITEM2"]


def test_without_a_log_the_old_rules_still_decide():
    result = _run(SNAPSHOT + """
      put(rec('ENV2', 'envelope', ids.K1, ids.A, null, { target_user_id: ids.C, access_level: 'write' }),
          rec('CAROL_ITEM', 'entry', ids.F1, ids.C, ids.K1));
      return [...unauthorizedWrites(objects, ids.A)];
    """, TEAM)
    assert result == []


# ── What the browser seals ───────────────────────────────────────────────

WRITER = SNAPSHOT + """
  state.teamLog = { records: RECORDS, team };
  state.confirmedTeamGenesis = team.genesisHash;  // ACL tests start after external confirmation.
  state.syncObjects = put(rec('BOB_ITEM', 'entry', ids.F1, ids.B, ids.K1));
  state.nodes = {}; state.entries = {};
  const attempt = (userId, obj) => {
    state.userId = userId;
    try { assertTeamLogAllowsWrite(obj); return 'ok'; } catch (err) { return err.message; }
  };
"""


def test_the_browser_does_not_send_what_the_log_refuses():
    rekeyed = Log().genesis().member(B).member(C).key(F1, 0, K[1], None).access(F1, B, "write") \
        .access(F1, C, "read").key(F1, 1, K[2], K[1])
    result = _run(WRITER + """
      return {
        bob_current: attempt(ids.B, rec(ids.ITEM, 'entry', ids.F1, ids.B, ids.K2)),
        bob_old: attempt(ids.B, rec(ids.ITEM, 'entry', ids.F1, ids.B, ids.K1)),
        carol: attempt(ids.C, rec(ids.ITEM, 'entry', ids.F1, ids.C, ids.K2)),
        dan: attempt(ids.D, rec(ids.ITEM, 'entry', ids.F1, ids.D, ids.K2)),
        carol_delete: attempt(ids.C, rec('BOB_ITEM', 'entry', ids.F1, ids.C, null, { is_deleted: 1 })),
        carol_move_out: attempt(ids.C, rec('BOB_ITEM', 'entry', ids.OTHER, ids.C, ids.K9)),
        outside: attempt(ids.C, rec(ids.ITEM2, 'entry', ids.OTHER, ids.C, ids.K9)),
      };
    """, rekeyed)
    assert result["bob_current"] == "ok"
    assert result["outside"] == "ok"
    assert "old key generation" in result["bob_old"]
    for who in ("carol", "dan", "carol_delete", "carol_move_out"):
        assert "team log gives no write access here" in result[who], who


def test_a_folder_waiting_for_a_re_key_is_not_sealed_to():
    removed = Log().genesis().member(B).member(C).key(F1, 0, K[1], None).access(F1, B, "write") \
        .access(F1, C, "read").remove(C)
    result = _run(WRITER + "return attempt(ids.B, rec(ids.ITEM, 'entry', ids.F1, ids.B, ids.K1));", removed)
    assert "waits for a re-key" in result


def test_the_folders_key_is_the_logs_current_generation():
    rekeyed = Log().genesis().member(B).key(F1, 0, K[1], None).access(F1, B, "write").key(F1, 1, K[2], K[1])
    result = _run(WRITER + """
      // A newer-looking key the server labels the folder's: the log knows nothing of it.
      put(rec('01JZZZZZZZZZZZZZZZZZZZZZZZ', 'dek', ids.F1, ids.A, null, { scope: 'folder' }));
      state.deks = { [ids.K1]: new Uint8Array(32), [ids.K2]: new Uint8Array(32),
                     '01JZZZZZZZZZZZZZZZZZZZZZZZ': new Uint8Array(32) };
      const held = nearestFolderDekId(ids.F1);
      delete state.deks[ids.K2];
      let missing;
      try { nearestFolderDekId(ids.F1); } catch (err) { missing = err.message; }
      return { held, missing };
    """, rekeyed)
    assert result["held"] == K[2]
    assert "does not hold the folder's current key" in result["missing"]
