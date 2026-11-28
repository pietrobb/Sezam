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
