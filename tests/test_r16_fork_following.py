"""Review 18c300f R16-H1: a server serves the admin's own records it refused
or that the admin's device dropped; a member's device never follows a fork.

INV-2 (docs/ROOT_CAUSE_PLAN.md): a device's log holds only what its author
meant. On 18c300f every fork of this account's own records was followed
(team_log_local.py:360, the page and the phone alike): the admin sent a
hand-over to Bob, the server refused it and kept it, the admin removed Bob,
and the server served the hand-over in place of the removal. The admin's
device took it: Bob was the admin and the admin's member.remove failed with
not_admin. A dropped identity rotation served the same way named keys nobody
holds (every push bad_signature). Without a fork too: the kept hand-over
served on top of the log was a plain continuation.

INV-7: with an honest server, a member's device that had pulled the records
the server then lost stayed on 'does not replay' for good, also once the
admin's device had made them again on the server's side.

tests/vectors/team_log_fork.json says by hand what every client's
fork_refusal answers; the desktop's withdrawn records (the server refused
them, the device went on without them, the key change was dropped) are
tests/test_r16_fork_following.py's real server cases below.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sezam import teamlog as tl
from sezam.vault.db import VaultDB
from sezam.vault.sync_common import ServerError
from sezam.vault.team_log_local import GENESIS_META, TeamLogMismatch, TeamLogMixin
from sezam.vault.team_log_state import resolve_change
from sezam.vault.team_migration import hand_over_admin
from tests.team_log_fork_vectors import VECTORS_PATH, _base, build_vectors, dump
from tests.team_log_vectors import A, B, D, F1, K
from tests.node_support import node_problem
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review_web import _run_source
from tests.test_team_log_desktop import _confirm_founder, _forget_server_cache, _found_with_bob, team  # noqa: F401
from tests.test_team_log_web_pull import TEAMLOG_JS, _run as _pull_run

VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _web_run(script: str, log) -> dict:
    """test_team_log_web_pull's page, with the re-key push and hex helpers."""
    import tests.test_team_log_web_pull as pull

    extra = ["pushWebRekeyBatch", "hexToBytes", "bytesToHex", "postAtomicSyncBatch"]
    saved = list(pull.FUNCTIONS)
    pull.FUNCTIONS[:] = saved + [n for n in extra if n not in saved]
    try:
        return _pull_run("(async () => {" + script + "\n})()", log)
    finally:
        pull.FUNCTIONS[:] = saved


def test_the_vectors_are_the_builders():
    assert VECTORS_PATH.read_text(encoding="utf-8") == dump(build_vectors())


def test_the_python_core_gives_every_answer():
    for case in VECTORS["cases"]:
        got = tl.fork_refusal(case["lost"], case["theirs"], case["user_id"],
                              case["held_keys"], frozenset(case["withdrawn"]))
        assert list(got) == [case["expect"]["refusal"], case["expect"]["missing"]], case["name"]


def _remade_cases() -> list[dict]:
    return [c for c in VECTORS["cases"] if "remade" in c["expect"]]


def test_the_python_core_makes_every_lost_change_again():
    """R16-M5: each missing change as a device makes it again on the server's head."""
    got = {}
    for case in _remade_cases():
        served = tl.replay(VECTORS["prefix"] + case["theirs"])
        bodies = [tl.parse_body(r["body"]) for r in case["lost"]]
        try:
            got[case["name"]] = [[b["type"], d] for b in bodies if b["seq"] in case["expect"]["missing"]
                                 for d in [resolve_change(served, b["type"], b["data"])] if d is not None]
        except tl.TeamLogError as exc:
            got[case["name"]] = exc.code
    assert got == {c["name"]: c["expect"]["remade"] for c in _remade_cases()}


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for teamlog.js")
def test_the_page_core_makes_every_lost_change_again():
    got = _run_source(TEAMLOG_JS, """(async () => {
        const TL = globalThis.SezamTeamLog;
        const out = {};
        for (const c of %s) {
            const served = TL.replay(%s.concat(c.theirs), sodium);
            const bodies = c.lost.map(r => TL.parseBody(r.body, null)).filter(b => c.expect.missing.includes(b.seq));
            try {
                out[c.name] = bodies.map(b => [b.type, TL.resolveChange(served, b.type, b.data)])
                    .filter(([, d]) => d !== null);
            } catch (err) { out[c.name] = err.code; }
        }
        return out;
    })()""" % (json.dumps(_remade_cases()), json.dumps(VECTORS["prefix"])))
    assert got == {c["name"]: c["expect"]["remade"] for c in _remade_cases()}


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for teamlog.js")
def test_the_page_core_gives_every_answer():
    got = _run_source(TEAMLOG_JS, """(async () => {
        const TL = globalThis.SezamTeamLog;
        const out = {};
        for (const c of %s) {
            const v = TL.forkRefusal(c.lost, c.theirs, c.user_id, c.held_keys, new Set(c.withdrawn), sodium);
            out[c.name] = [v.refusal, v.missing];
        }
        return out;
    })()""" % json.dumps(VECTORS["cases"]))
    assert got == {c["name"]: [c["expect"]["refusal"], c["expect"]["missing"]] for c in VECTORS["cases"]}


# ── The page's ledger: what the server refused never enters its log ───


WEB_LEDGER = """
    const store = new Map();
    idbKeysRequest = async (mode, op) => op({
        get: id => store.get(id), put: row => { store.set(row.id, row); },
    });
    state.kek = new Uint8Array(32).fill(7);
    state.userId = ids.A;
    let serverRecords = RECORDS.slice();
    let refuse = false;
    apiFetch = async (url, opts) => {
        if (opts && opts.method === 'POST') {
            if (refuse) { const err = new Error('400 refused'); err.status = 400; throw err; }
            serverRecords = serverRecords.concat(opts.body.records);
            return {};
        }
        const since = Number(/since=(-?\\d+)/.exec(url)[1]);
        return { records: serverRecords.slice(since + 1, since + 3) };
    };
    const me = { signingSk: hexToBytes(ME_SK) };
    const local = { records: RECORDS, team: teamOf(RECORDS) };
    const sign = (kind, data) => TL.signRecord(TL.nextBody(local.team, kind, ids.A, data), me.signingSk, sodium);
    const removal = sign('member.remove', { user_id: ids.B });
    refuse = true;
    try { await pushWebRekeyBatch({ objects: [], team_log: [removal] }, sodium); } catch (err) { }
    refuse = false;
    serverRecords = serverRecords.concat([removal]);  // the server kept what it refused
    try {
        const got = await syncWebTeamLog(head(serverRecords), local, null, sodium);
        return { followed: got.team.headSeq };
    } catch (err) { return { error: err.message }; }
"""


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for app.js")
def test_the_page_never_takes_a_record_the_server_refused():
    """On 18c300f the page followed it: the removal the admin saw refused
    (and may have dropped since) was in its log after the next pull."""
    log = _base()
    script = WEB_LEDGER.replace("ME_SK", json.dumps((bytes(A.sk) + bytes(A.sk.verify_key)).hex()))
    result = _web_run(script, log)
    assert "which this browser withdrew" in result.get("error", ""), result


# R16-M5: the browser makes this account's lost changes again on the server's
# head (RECORDS is the prefix both sides hold).
WEB_REMAKE = """
    const store = new Map();
    idbKeysRequest = async (mode, op) => op({
        get: id => store.get(id), put: row => { store.set(row.id, row); },
    });
    state.kek = new Uint8Array(32).fill(7);
    state.userId = ids.A;
    state.keypair = { signingSk: hexToBytes(ME_SK) };
    const c = CASE;
    const held = RECORDS.concat(c.lost);
    let serverRecords = RECORDS.concat(c.theirs);
    const posted = [];
    apiFetch = async (url, opts) => {
        if (opts && opts.method === 'POST') {
            if (REFUSE) { const err = new Error('400 refused'); err.status = 400; throw err; }
            posted.push(...opts.body.records);
            serverRecords = serverRecords.concat(opts.body.records);
            return {};
        }
        const since = Number(/since=(-?\\d+)/.exec(url)[1]);
        return { records: serverRecords.slice(since + 1, since + 3) };
    };
    try {
        const served = serverRecords.length - 1;
        const got = await syncWebTeamLog(head(serverRecords), { records: held, team: teamOf(held) }, null, sodium);
        const ledger = await loadWebTeamLedger(sodium);
        return {
            followed: got.team.headSeq - served, server: serverRecords.length - 1 - served,
            posted: posted.map(r => { const b = TL.parseBody(r.body, null); return [b.type, b.data, b.author]; }),
            set_aside: ledger.setAside.map(x => [x.type, x.reason]),
        };
    } catch (err) { return { error: err.message }; }
"""


def _web_remake(name: str, refuse: bool = False) -> dict:
    case = next(c for c in VECTORS["cases"] if c["name"] == name)
    script = (WEB_REMAKE.replace("ME_SK", json.dumps((bytes(A.sk) + bytes(A.sk.verify_key)).hex()))
              .replace("CASE", json.dumps(case)).replace("REFUSE", json.dumps(refuse)))
    return _web_run(script, _base())


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for app.js")
def test_the_page_makes_the_changes_it_lost_again():
    """On 18c300f the page waited for them for good: 'differs' at every pull,
    the team part of the vault refused while the personal tree went on."""
    got = _web_remake("own_fork_recovery_made_here")
    remade = VECTORS["cases"][[c["name"] for c in VECTORS["cases"]].index("own_fork_recovery_made_here")]
    assert got == {"followed": 2, "server": 2, "set_aside": [],
                   "posted": [[k, d, A.uid] for k, d in remade["expect"]["remade"]]}, got


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for app.js")
def test_the_page_sets_aside_what_the_log_or_the_server_no_longer_takes():
    moved = _web_remake("own_fork_folder_keyed_elsewhere")
    assert moved["followed"] == 0 and moved["posted"] == [], moved
    assert [k for k, _ in moved["set_aside"]] == ["folder.key"] and "folder_key_moved" in moved["set_aside"][0][1]
    refused = _web_remake("own_fork_shorter", refuse=True)
    assert refused == {"followed": 0, "server": 0, "posted": [],
                       "set_aside": [["folder.key", "the server refused them"],
                                     ["access.set", "the server refused them"]]}, refused


# ── The desktop's follower over a vault database ──────────────────────


class _Keys:
    def __init__(self, actor):
        self.signing_pk = bytes.fromhex(actor.spk)
        self.encryption_pk = bytes.fromhex(actor.epk)


class _Device(TeamLogMixin):
    """The follower of ``user`` over a real vault database; the server
    serves ``served`` and refuses every restore."""

    def __init__(self, db: VaultDB, user, served: list[dict]):
        self._db, self._user_id, self._keypair, self._served = db, user.uid, _Keys(user), served

    def _request(self, method, path, body=None, auth=False):
        assert method == "GET" and path.startswith("/api/team-log?since="), path
        since = int(path.split("since=", 1)[1])
        return {"records": [r for r in self._served if tl.parse_body(r["body"])["seq"] > since]}

    def _restore_server_team_log(self, local, server_head):
        return False


def _device(tmp_path: Path, user, held: list[dict], served: list[dict]) -> _Device:
    db = VaultDB(tmp_path / f"{user.name}.db")
    db.open()
    db.create_schema()
    device = _Device(db, user, served)
    device._store_team_log(held, tl.replay(held))
    db.set_meta(GENESIS_META, tl.replay(held).genesis_hash)
    return device


def _head(records: list[dict]) -> dict:
    state = tl.replay(records)
    return {"genesis_hash": state.genesis_hash, "seq": state.head_seq, "hash": state.head_hash}


def _own() -> list[dict]:
    return _base().key(F1, 0, K[1], None).access(F1, B, "write").records


def test_a_members_device_follows_once_the_admin_made_the_lost_changes_again(tmp_path):
    """Honest server restored from a backup: Bob pulled what the admin's
    device then made again after another device of the admin's put a record
    first. Bob follows (on 18c300f: 'does not replay' for good)."""
    again = _base().member(D).key(F1, 0, K[1], None).access(F1, B, "write").records
    device = _device(tmp_path, B, _own(), again)
    try:
        assert device._sync_team_log(_head(again)).head_seq == 5
        assert [row["hash"] for row in device._db.fetchall("SELECT hash FROM team_log ORDER BY seq")] == [
            tl.record_hash(r) for r in again]
    finally:
        device._db.close()


def test_a_members_device_waits_while_a_change_it_saw_is_missing(tmp_path):
    shorter = _base().member(D).records
    device = _device(tmp_path, B, _own(), shorter)
    try:
        with pytest.raises(TeamLogMismatch, match="record 3 this device saw is not on the server's side"):
            device._sync_team_log(_head(shorter))
        assert device.team_state().head_seq == 4
    finally:
        device._db.close()


def test_the_admin_never_follows_a_fork_with_keys_nobody_holds(tmp_path):
    """Another device of the admin's dropped an identity rotation (this
    device never saw it go out): the fork names keys this device does not hold."""
    rotated = _base().rotate(A, D).records
    device = _device(tmp_path, A, _own(), rotated)
    try:
        with pytest.raises(TeamLogMismatch, match="names keys this device does not hold"):
            device._sync_team_log(_head(rotated))
        assert device.team_state().members[A.uid].signing_pk == A.spk
    finally:
        device._db.close()


# ── Real desktop clients against the real server ───────────────────────


def _refuse_and_keep(monkeypatch, client, kind: str) -> list[dict]:
    """The server answers 400 to any request with a record of ``kind`` and
    keeps the records."""
    kept: list[dict] = []
    original = client._request

    def request(method, path, body=None, auth=False, **kw):
        records = (body or {}).get("records") or (body or {}).get("team_log") or []
        if method == "POST" and any(tl.parse_body(r["body"])["type"] == kind for r in records):
            kept.extend(records)
            raise ServerError(400, json.dumps({"detail": "refused", "code": "team_log_refused"}))
        return original(method, path, body, auth=auth, **kw)

    monkeypatch.setattr(client, "_request", request)
    return kept


def _serve(db, records: list[dict], from_seq: int) -> None:
    """The server's log from ``from_seq`` on becomes ``records``."""
    rows = [row for row in db._storage["team_log"] if row["seq"] < from_seq]
    for record in records:
        body = tl.parse_body(record["body"])
        rows.append({"seq": body["seq"], "prev": body["prev"], "hash": tl.record_hash(record),
                     "body": record["body"], "sig": record["sig"], "author": body["author"], "created_at": 0})
    db._storage["team_log"] = rows
    _forget_server_cache()


def _handover_refused_and_kept(team, monkeypatch) -> tuple:
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    bob_id = bob.db.get_meta("user_id")
    kept = _refuse_and_keep(monkeypatch, admin_client, "member.role")
    with pytest.raises(RuntimeError, match="400"):
        hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    monkeypatch.undo()
    assert [tl.parse_body(r["body"])["type"] for r in kept] == ["member.role", "member.role"]
    return db, admin, admin_client, bob_id, kept


def test_the_server_serves_a_handover_it_refused_in_place_of_the_removal(team, monkeypatch):
    """The reviewer's take-over: on 18c300f Bob was the admin, the admin a member."""
    db, admin, admin_client, bob_id, kept = _handover_refused_and_kept(team, monkeypatch)
    admin_id = admin.db.get_meta("user_id")
    removal = admin_client.append_team_log([("member.remove", {"user_id": bob_id})]).head_seq
    _serve(db, kept, removal)
    with pytest.raises(TeamLogMismatch, match="withdrew"):
        admin_client._refresh_team_log()
    state = admin_client.team_state()
    assert tl.is_admin(state, admin_id) and not state.members[bob_id].active


def test_the_server_serves_a_handover_it_refused_on_top_of_the_log(team, monkeypatch):
    db, admin, admin_client, bob_id, kept = _handover_refused_and_kept(team, monkeypatch)
    _serve(db, kept, admin_client.team_state().head_seq + 1)
    with pytest.raises(TeamLogMismatch, match="withdrew"):
        admin_client._refresh_team_log()
    assert tl.is_admin(admin_client.team_state(), admin.db.get_meta("user_id"))
