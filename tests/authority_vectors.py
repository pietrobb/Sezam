"""Write tests/vectors/authority.json: which pulled writes a client does not
apply (core/src/authority.rs, docs/CORE_UNIFICATION.md U5).

The reference is the web's unauthorizedWrites and sealingDekId as they were
before the move into the core (web/static/js/app.js at REFERENCE), run in
node over seeded random snapshots: folders and items under team folders, the
organisation's tree, personal trees, folders the snapshot lacks, cycles; keys
of the log, of an account and of a folder; write grants; tombstones and moves
against a previous snapshot; with and without a team log. Every side (core,
desktop, web, phone) must give the same answers; never regenerate this file
to make a side pass. The header rule is the phone's (the strictest of the
four that had drifted apart): an envelope header (alg 1, schema 1, 53 bytes),
an ASCII id, an empty id names no key.

    python tests/authority_vectors.py   # needs node and the git history
"""

from __future__ import annotations

import base64
import json
import random
import subprocess
from pathlib import Path

import sezam_sync_core

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "vectors" / "authority.json"
REFERENCE = "6ad1d19"
FUNCTIONS = ("base64ToBytes", "isEncryptedEnvelope", "sealingDekId", "webTeamFolderAbove",
             "webLogAdmins", "unauthorizedWrites")
TEAM_SCENARIOS = ("second_admin_removes_founder", "org_recovery_wrap", "handover_on_ends_the_role_keys")
CASES = 180
OWN = "01JOWN00000000000000000001"
STRANGER = "01JSTRANGER000000000000001"


# Where the clients had drifted apart and the reference is not the web's: each
# (the web's text, the decided rule, why). The desktop's tests/r18 differential
# against these vectors found them (docs/CORE_UNIFICATION.md U5).
DECISIONS = (
    (
        """        } else if (team && !rec.parent_ref && rec.object_type === 'node' && !rec.is_deleted) {""",
        """        } else if (decided !== undefined) {
            if (decided !== null) {
                verdict = 'blocked';
                byTeamLog.add(rec.id);
            }
        } else if (team && !rec.parent_ref && rec.object_type === 'node' && !rec.is_deleted) {""",
        "the log decides first, a top-level folder too (desktop): a team folder's own meta, "
        "one sealed with a team folder's key",
    ),
    (
        """                if (owner && owner !== ownUserId && !rec.is_deleted && sealedBy !== owner) verdict = 'blocked';""",
        """                if (owner && owner !== ownUserId && sealedBy !== owner &&
                    (!rec.is_deleted || (team && author !== owner))) verdict = 'blocked';""",
        "with a log only the owner removes from a personal tree (desktop)",
    ),
    (
        """                if (team && !owner && !rec.is_deleted && author !== ownUserId && !admins.has(author)) {""",
        """                if (team && !owner && author !== ownUserId && !admins.has(author)) {""",
        "below the first level of the organisation's tree only an admin removes too (desktop, H6)",
    ),
    (
        """            } else if (!rec.is_deleted) {
                verdict = 'blocked';
            }
        }
        verdicts[rec.id] = verdict;""",
        """            } else {
                verdict = 'blocked';
            }
        }
        verdicts[rec.id] = verdict;""",
        "directly below a top-level folder a removal needs what a write needs; a personal "
        "folder's tombstone is sealed with its owner's key (desktop)",
    ),
)


def _decided(app: str) -> str:
    for old, new, _why in DECISIONS:
        assert app.count(old) == 1, old
        app = app.replace(old, new)
    return app


def _function(src: str, name: str) -> str:
    start = src.index(f"function {name}(")
    depth = 0
    for index in range(src.index("{", start), len(src)):
        depth += {"{": 1, "}": -1}.get(src[index], 0)
        if depth == 0:
            return src[start:index + 1]
    raise AssertionError(name)


def _core(op: str, **arguments):
    out = json.loads(sezam_sync_core.call(op, json.dumps(arguments)))
    assert "error" not in out, out
    return out["ok"]


def _envelope(dek_id: str) -> bytes:
    return bytes([1, 1, 0]) + dek_id.encode().ljust(26, b"\0") + bytes(24) + bytes(range(16))


def _payload(rng: random.Random, kind: str, dek_id) -> bytes:
    if dek_id is None:
        return b""
    if dek_id == "malformed":
        return bytes(rng.randrange(256) for _ in range(rng.choice((3, 30, 60))))
    meta = _envelope(dek_id)
    if kind == "entry" and rng.random() < 0.8:
        return len(meta).to_bytes(4, "big") + meta + _envelope(dek_id)
    return meta


def _ids(prefix: str, n: int) -> list[str]:
    return [f"01J{prefix}{i:0{23 - len(prefix)}d}" for i in range(1, n + 1)]


def _case(rng: random.Random, team: dict | None) -> dict:
    members = sorted(team["members"]) if team else []
    # No signer at all: only without a log (the log's rules take an account).
    accounts = members + [OWN, STRANGER] + ([] if team else [None])
    folders = sorted(team["folders"]) if team else []
    team_deks = sorted(team["dek_index"]) if team else []
    personal = _ids("PDEK", 3)
    folder_deks = _ids("FDEK", 2)
    nodes = rng.sample(folders, min(len(folders), rng.randint(0, 2))) + _ids("NODE", rng.randint(2, 6))
    missing = "01JMISSING0000000000000001"
    dek_choices = team_deks + personal + folder_deks + [None, "malformed"]
    objects: list[dict] = []

    def add(**fields):
        objects.append({"access_level": None, "target_user_id": None, "is_deleted": 0, **fields})

    for dek_id in personal:
        add(id=dek_id, object_type="dek", parent_ref=None, signer=rng.choice(accounts), dek=None)
    for dek_id in folder_deks:
        add(id=dek_id, object_type="dek", parent_ref=rng.choice(nodes), signer=rng.choice(accounts), dek=None)
    for node_id in nodes:
        parent = rng.choice([None, None, missing] + [n for n in nodes if n != node_id])
        add(id=node_id, object_type="node", parent_ref=parent, signer=rng.choice(accounts),
            dek=rng.choice(dek_choices), is_deleted=int(rng.random() < 0.1))
    for entry_id in _ids("ENTRY", rng.randint(1, 5)):
        add(id=entry_id, object_type="entry", parent_ref=rng.choice(nodes + [missing]),
            signer=rng.choice(accounts), dek=rng.choice(dek_choices), is_deleted=int(rng.random() < 0.1))
    for env_id in _ids("ENV", rng.randint(0, 3)):
        add(id=env_id, object_type="envelope", parent_ref=rng.choice(folder_deks + personal),
            signer=rng.choice(accounts), target_user_id=rng.choice([a for a in accounts if a]),
            access_level=rng.choice(("write", "read")), dek=None, is_deleted=int(rng.random() < 0.1))
    if rng.random() < 0.3:
        add(id="01JAUDIT000000000000000001", object_type=rng.choice(("audit", "dek_archive")),
            parent_ref=None, signer=rng.choice(accounts), dek=None)
    rng.shuffle(objects)
    previous = None
    if rng.random() < 0.6:
        previous = []
        for obj in objects:
            if obj["object_type"] in ("node", "entry") and rng.random() < 0.7:
                held = dict(obj)
                if rng.random() < 0.5:
                    held["parent_ref"] = rng.choice(nodes + folders + [None])
                if rng.random() < 0.3:
                    held["dek"] = rng.choice(dek_choices)
                held["is_deleted"] = int(rng.random() < 0.1)
                previous.append(held)
    own = rng.choice(members + [OWN]) if team else rng.choice([OWN, rng.choice([a for a in accounts if a])])
    return {"objects": objects, "previous": previous, "own_user_id": own}


def _with_payloads(rng: random.Random, objects: list[dict]) -> list[dict]:
    out = []
    for obj in objects:
        payload = _payload(rng, obj["object_type"], obj.pop("dek"))
        out.append({**obj, "payload": base64.b64encode(payload).decode(), "head": payload[:57].hex()})
    return out


HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const { webcrypto } = require('crypto');
const context = { console, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, BigInt,
  Promise, WebAssembly, crypto: webcrypto, setTimeout, clearTimeout,
  atob: (v) => Buffer.from(v, 'base64').toString('binary') };
context.window = context; context.self = context; context.globalThis = context;
vm.createContext(context);
for (const path of process.argv.slice(1, 5)) vm.runInContext(fs.readFileSync(path, 'utf8'), context);
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
vm.runInContext(input.functions, context);
vm.runInContext(`function sealingDekId(record) {
  let bytes;
  try { bytes = base64ToBytes(record.payload || ''); } catch { return null; }
  if (record.object_type === 'entry' && !isEncryptedEnvelope(bytes)) bytes = bytes.slice(4);
  if (!isEncryptedEnvelope(bytes)) return null;
  const id = bytes.slice(3, 29);
  if (id.some((c) => c > 127)) return null;
  return String.fromCharCode(...id).replace(/\\0/g, '') || null;
}`, context);
vm.runInContext(`(async () => {
  await sodium.ready;
  await SezamSyncCore.ready;
  const teams = __input.teams.map((records) => ({ records, team: SezamTeamLog.replay(records, sodium) }));
  const out = [];
  for (const c of __input.cases) {
    const map = (list) => list === null ? null : Object.fromEntries(list.map((o) => [o.id, o]));
    const log = c.team === null ? null : teams[c.team];
    const admins = log && c.log_admins ? [...webLogAdmins(log)] : null;
    const blocked = unauthorizedWrites(map(c.objects), c.own_user_id, log ? log.team : null,
      map(c.previous), admins ? new Set(admins) : null);
    const dekIds = Object.fromEntries(c.objects.map((o) => [o.id + '/' + o.object_type, sealingDekId(o)]));
    out.push({ blocked: [...blocked], by_team_log: [...blocked.byTeamLog].sort(), dek_ids: dekIds,
      team_admins: admins ? admins.sort() : null });
  }
  return JSON.stringify(out);
})()`, Object.assign(context, { __input: input }))
  .then((r) => process.stdout.write(r))
  .catch((e) => { console.error(e && e.stack); process.exit(1); });
"""


def main() -> None:
    from tests.node_support import node_cmd
    from tests.team_log_vectors import VECTORS_PATH
    from tests.test_team_log_web import web_scripts

    app = subprocess.run(["git", "show", f"{REFERENCE}:web/static/js/app.js"], cwd=ROOT,
                         capture_output=True, check=True).stdout.decode("utf-8")
    app = _decided(app)
    scenarios = {s["name"]: s for s in json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["scenarios"]}
    records = [scenarios[name]["records"] for name in TEAM_SCENARIOS]
    teams = [_core("team_log_replay", records=r, state=None, verified=len(r))["state"] for r in records]
    rng = random.Random(20261128)
    cases = []
    for n in range(CASES):
        index = rng.choice([None, None] + list(range(len(teams))))
        case = _case(rng, teams[index] if index is not None else None)
        case["objects"] = _with_payloads(rng, case["objects"])
        if case["previous"] is not None:
            case["previous"] = _with_payloads(rng, case["previous"])
        cases.append({"name": f"random {n}", "team": index, "log_admins": index is not None and rng.random() < 0.5,
                      **case})
    run = subprocess.run(
        [node_cmd(), "-e", HARNESS, *web_scripts()],
        input=json.dumps({"functions": "const ENVELOPE_ALG = 1; const SCHEMA_VERSION = 1;\n"
                                       + "\n".join(_function(app, f) for f in FUNCTIONS),
                          "teams": records, "cases": cases}),
        capture_output=True, text=True, encoding="utf-8", timeout=300,
    )
    assert run.returncode == 0, run.stderr[-3000:]
    answers = json.loads(run.stdout)
    for case, answer in zip(cases, answers):
        case.pop("log_admins")
        case["team_admins"] = answer["team_admins"]
        for obj in case["objects"] + (case["previous"] or []):
            obj.pop("payload")
        case["dek_ids"] = answer["dek_ids"]
        case["blocked"] = answer["blocked"]
        case["by_team_log"] = answer["by_team_log"]
    OUT.write_text(json.dumps({
        "_comment": __doc__.split("\n\n")[1].replace("\n", " "),
        "reference": f"{REFERENCE}:web/static/js/app.js",
        "decisions": [why for _old, _new, why in DECISIONS],
        "teams": teams,
        "cases": cases,
    }, indent=None, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    blocked = sum(bool(c["blocked"]) for c in cases)
    by_log = sum(bool(c["by_team_log"]) for c in cases)
    print(f"{OUT}: {len(cases)} cases, {blocked} with a blocked write, {by_log} refused by the log")


if __name__ == "__main__":
    main()
