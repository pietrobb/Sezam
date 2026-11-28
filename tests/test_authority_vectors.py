"""The shared authority vectors (tests/vectors/authority.json) on every side:
which pulled folders and items a client does not apply, the key a header
names and the log's admins (core/src/authority.rs, docs/CORE_UNIFICATION.md
U5). core/tests/authority_vectors.rs runs them in the core itself.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from tests.test_review_web import _function, _run_source, pytestmark  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "tests" / "vectors" / "authority.json").read_text(encoding="utf-8"))
TEAM_LOG = json.loads((ROOT / "tests" / "vectors" / "team_log.json").read_text(encoding="utf-8"))
SCENARIOS = ("second_admin_removes_founder", "org_recovery_wrap", "handover_on_ends_the_role_keys")
TEAMLOG_JS = (ROOT / "web" / "static" / "js" / "teamlog.js").read_text(encoding="utf-8")


def _records() -> list[list[dict]]:
    scenarios = {s["name"]: s for s in TEAM_LOG["scenarios"]}
    return [scenarios[name]["records"] for name in SCENARIOS]


def _with_payloads(objects: list[dict] | None) -> list[dict] | None:
    if objects is None:
        return None
    return [{**o, "payload": base64.b64encode(bytes.fromhex(o["head"])).decode()} for o in objects]


def test_the_web_gives_the_vectors_answers():
    cases = [{**c, "objects": _with_payloads(c["objects"]), "previous": _with_payloads(c["previous"])}
             for c in VECTORS["cases"]]
    result = _run_source(
        TEAMLOG_JS + "\n" + "\n".join(_function(n) for n in (
            "sealingDekId", "authorityObjects", "unauthorizedWrites", "webLogAdmins")),
        f"""(() => {{
          const teams = {json.dumps(_records())}.map(records => ({{ records, team: SezamTeamLog.replay(records, sodium) }}));
          const map = list => list === null ? null : Object.fromEntries(list.map(o => [o.id, o]));
          return {json.dumps(cases)}.map(c => {{
            const log = c.team === null ? null : teams[c.team];
            const blocked = unauthorizedWrites(map(c.objects), c.own_user_id, log ? log.team : null,
              map(c.previous), c.team_admins ? new Set(c.team_admins) : null);
            return {{
              blocked: [...blocked], by_team_log: [...blocked.byTeamLog].sort(),
              dek_ids: Object.fromEntries(c.objects.map(o => [o.id + '/' + o.object_type, sealingDekId(o)])),
              team_admins: log && c.team_admins ? [...webLogAdmins(log)].sort() : null,
            }};
          }});
        }})()""",
    )
    for case, got in zip(VECTORS["cases"], result):
        assert got["dek_ids"] == case["dek_ids"], case["name"]
        assert got["blocked"] == case["blocked"], case["name"]
        assert got["by_team_log"] == case["by_team_log"], case["name"]
        assert got["team_admins"] == case["team_admins"], case["name"]
    assert len(result) == len(VECTORS["cases"])


class _LogRows:
    def __init__(self, records: list[dict]):
        self.rows = [{"body": r["body"]} for r in records]

    def fetchall(self, _sql, _params=()):
        return self.rows


def test_the_desktop_names_the_vectors_log_admins():
    from sezam import teamlog
    from sezam.vault.team_log_state import log_admins

    records = _records()
    checked = 0
    for case in VECTORS["cases"]:
        if case["team"] is None or case["team_admins"] is None:
            continue
        team = teamlog.TeamState.from_core(VECTORS["teams"][case["team"]])
        assert sorted(log_admins(_LogRows(records[case["team"]]), team)) == case["team_admins"], case["name"]
        checked += 1
    assert checked


def test_the_server_reads_the_vectors_header_key():
    from server.app.routers.sync import _sealing_dek_id

    checked = 0
    for case in VECTORS["cases"]:
        for o in case["objects"]:
            head = bytes.fromhex(o["head"])
            if o["object_type"] == "node":
                payload, entry = head + bytes(16), False
            elif o["object_type"] == "entry" and head[:2] != b"\x01\x01":
                # The server only takes an item as u32be(len(meta)) + meta.
                meta = head[4:] + bytes(16)
                payload, entry = len(meta).to_bytes(4, "big") + meta, True
            else:
                continue
            assert _sealing_dek_id(payload, entry) == case["dek_ids"][f"{o['id']}/{o['object_type']}"], case["name"]
            checked += 1
    assert checked
