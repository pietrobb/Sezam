"""The web binding of the shared sync core (docs/SYNC_SINGLE_SOURCE.md 4b).

web/static/js/vendor/sezam-sync-core.js is built from core/ by
core/build_web.py and committed like the other vendored scripts. It must be
built from the current sources, pinned by the page, and answer exactly as
the desktop's binding of the same crate does.
"""

import base64
import hashlib
import importlib.util
import json
import re
import subprocess

import sezam_sync_core

from tests.node_support import node_cmd, requires_node
from tests.test_review_web import ROOT

spec = importlib.util.spec_from_file_location("build_web", ROOT / "core" / "build_web.py")
build_web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_web)

CORE_JS = build_web.OUT

TEAM_G3 = {"folders": {"F": ["g1", "g2", "g3"]}, "may_hold": ["g3"]}

# One input per operation, plus refused ones: both bindings must agree.
CASES = [
    ("version", {}),
    ("gate", {"checkpoint": {"seq": 9, "anchor_token": "t"},
              "reply": {"gone": False, "head_commit_seq": 12, "check_token": "x"}, "rollback_pending": False}),
    ("gate", {"checkpoint": {"seq": 9}, "reply": {"gone": False, "head_commit_seq": 4}, "rollback_pending": False}),
    # Review c78fd19: a security field left out is refused, not read as false;
    # so is a field the core does not know (a misspelt one).
    ("gate", {"checkpoint": {"seq": 9}, "reply": {"gone": False}}),
    ("gate", {"checkpoint": {"seq": 9}, "reply": {"head_commit_seq": 4}, "rollback_pending": True}),
    ("gate", {"checkpoint": {"seq": 9}, "reply": {"gone": False}, "rollback_pending": False, "rolback": 1}),
    ("next_cursor", {"last_seq": 0, "max_commit_seq": 7, "gc_floor_seq": 10, "head_commit_seq": 9}),
    ("check_state", {"stored": {"seq": 9, "state_hash": "h", "live_state_hash": "l"},
                     "candidate": {"max_commit_seq": 7, "state_hash": "x", "live_state_hash": "l",
                                   "gc_floor_seq": 9, "served": True}}),
    ("decide_pulled", {"unsent": {"version": 4, "hash": "b", "is_deleted": False, "base": {"version": 3, "hash": "a"}},
                       "pulled": {"version": 3, "hash": "a", "is_deleted": False, "own_earlier_push": False}}),
    ("decide_pulled", {"unsent": {"version": 4, "hash": "b", "is_deleted": False},
                       "pulled": {"version": 3, "hash": "a", "is_deleted": False}}),
    # The core rejects older copies and tells equivocation for every client.
    ("against_held", {"gc_floor_seq": 10, "items": [
        {"held": {"version": 5, "hash": "h5", "is_deleted": False, "queued": False}, "pulled": {"version": 4, "hash": "h4"}},
        {"held": {"version": 5, "hash": "h5", "is_deleted": False, "queued": False}, "pulled": {"version": 5, "hash": "x"}},
        {"held": {"version": 5, "hash": "h5", "is_deleted": False, "queued": False}, "pulled": {"version": 5, "hash": "h5"}},
        {"held": {"version": 5, "hash": "h5", "is_deleted": True, "queued": False, "commit_seq": 8},
         "pulled": {"version": 3, "hash": "h3"}},
        {"held": None, "pulled": {"version": 1, "hash": "h1"}},
    ]}),
    ("missing_successor", {"archives": [{"id": "A", "replaced_by": "K"}], "keys": ["K"]}),
    ("order_pulled", {"objects": [{"id": "E", "object_type": "entry"}, {"id": "D", "object_type": "dek"}]}),
    ("parents_first", {"rows": [{"id": "C", "parent_ids": ["P"]}, {"id": "P"}]}),
    ("plan_reapply", {"rows": [{"id": "E", "object_type": "entry"}], "live": {}}),
    # Capability review run 365: a write queued under g1 of a folder re-keyed
    # g1 -> g2 -> g3 goes out under g3 for a member of g3, under nothing
    # replaced for a revoked account.
    ("reseal_targets", {"team": TEAM_G3, "held": ["g3"], "keys": ["g1", "g2", "g3", "x"]}),
    ("reseal_targets", {"team": {**TEAM_G3, "may_hold": []}, "held": ["g3"], "keys": ["g1"]}),
    ("reseal_targets", {"successors": {"a": "b", "b": "c"}, "held": ["c"], "keys": ["a"]}),
    ("may_open_superseded", {"team": TEAM_G3, "key": "g1"}),
    ("may_open_superseded", {"team": {**TEAM_G3, "may_hold": []}, "key": "g1"}),
    ("rekey_due", {"team": TEAM_G3, "keys": ["g1", "g2"]}),
    ("gate", {"checkpoint": "not an object"}),
    ("no_such_operation", {}),
]

RUN = r"""
const fs = require('fs');
const vm = require('vm');
const context = { console, TextEncoder, TextDecoder, atob };
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const core = vm.runInContext('SezamSyncCore', context);
let early;
try { core.call('next_cursor', {}); } catch (err) { early = String(err.message); }
core.ready.then(() => {
  const cases = JSON.parse(process.argv[2]);
  const out = cases.map(([op, args]) => {
    try { return { ok: core.call(op, args) }; } catch (err) { return { error: String(err.message) }; }
  });
  process.stdout.write(JSON.stringify({ early, out }));
});
"""


def test_the_built_file_is_from_the_current_core_sources():
    assert build_web.built_digest() == build_web.source_digest(), (
        "web/static/js/vendor/sezam-sync-core.js is older than core/: run python core/build_web.py"
    )


def test_the_page_pins_the_core_before_the_app():
    index = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    pinned = re.search(r'src="/static/js/vendor/sezam-sync-core\.js"\s+integrity="([^"]+)"', index)
    digest = base64.b64encode(hashlib.sha384(CORE_JS.read_bytes()).digest()).decode()
    assert pinned and pinned.group(1) == f"sha384-{digest}"
    assert index.index("sezam-sync-core.js") < index.index("/static/js/app.js")


@requires_node
def test_the_web_and_desktop_bindings_answer_alike():
    run = subprocess.run(
        [node_cmd(), "-e", RUN, str(CORE_JS), json.dumps(CASES)],
        capture_output=True, text=True, encoding="utf-8", timeout=60, check=True,
    )
    result = json.loads(run.stdout)
    # Called before the module is instantiated: refused, not a wrong answer.
    assert result["early"] == "sync core is not loaded yet"
    for (op, args), web in zip(CASES, result["out"], strict=True):
        # The same JSON text as JSON.stringify sends (error positions match).
        desktop = json.loads(sezam_sync_core.call(op, json.dumps(args, separators=(",", ":"))))
        if "error" in desktop:
            assert web == {"error": f"sync core {op}: {desktop['error']}"}, op
        else:
            assert web == {"ok": desktop["ok"]}, op


def test_the_send_side_after_a_rekey():
    def call(op, **args):
        return json.loads(sezam_sync_core.call(op, json.dumps(args)))["ok"]

    as_is, g3 = {"send": "as_is"}, {"send": "reseal", "key": "g3"}
    assert call("reseal_targets", team=TEAM_G3, held=["g3"], keys=["g1", "g2", "g3", "x"]) == [g3, g3, as_is, as_is]
    # Review c78fd19: a replaced key whose successor is not here (or not the
    # account's to hold) waits; it answered "as it is", and the write left
    # under the retired key a removed member reads.
    revoked = {**TEAM_G3, "may_hold": []}
    assert call("reseal_targets", team=revoked, held=["g3"], keys=["g1"]) == [{"send": "wait", "key": "g3"}]
    assert call("reseal_targets", team=TEAM_G3, held=[], keys=["g2"]) == [{"send": "wait", "key": "g3"}]
    assert call("reseal_targets", successors={"a": "b", "b": "c"}, held=["b"], keys=["a"]) == [
        {"send": "wait", "key": "c"}
    ]
    assert call("against_held", gc_floor_seq=0, items=[
        {"held": {"version": 5, "hash": "h5", "is_deleted": False, "queued": False}, "pulled": {"version": 4, "hash": "h4"}},
        {"held": {"version": 5, "hash": "h5", "is_deleted": False, "queued": False}, "pulled": {"version": 5, "hash": "x"}},
    ]) == ["keep_held", "equivocation"]
    assert call("may_open_superseded", team=TEAM_G3, key="g1") is True
    assert call("may_open_superseded", team=revoked, key="g1") is False
    assert call("rekey_due", team=TEAM_G3, keys=["g1", "g2"]) is False
    assert call("rekey_due", team=TEAM_G3, keys=["g3"]) is True
