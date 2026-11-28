"""U7e (docs/CORE_UNIFICATION.md): tests/vectors/rotated_seals.json and
tests/vectors/revive_folders.json through the core as the desktop asks it,
and through the page's WASM core. The phone runs revive_folders.json
(mobile/test/revive_folders_vectors_test.dart); it seals no team keys."""

from __future__ import annotations

import inspect
import json

import pytest

from sezam.vault import sync_core
from tests.node_support import node_problem
from tests.rotated_revive_vectors import (
    REVIVE_PATH, ROTATED_PATH, build_revive, build_rotated, dump,
)
from tests.test_review_web import _run_source
from tests.test_team_log_web_pull import TEAMLOG_JS

ROTATED = json.loads(ROTATED_PATH.read_text(encoding="utf-8"))
REVIVE = json.loads(REVIVE_PATH.read_text(encoding="utf-8"))
APP_JS = ROTATED_PATH.parents[2] / "web" / "static" / "js" / "app.js"


def _seal_args(case: dict) -> dict:
    return {k: case[k] for k in (
        "state", "done", "bodies", "user_id", "trusted", "blocked", "withheld", "projected",
    )}


def test_the_builder_still_gives_the_files():
    assert dump(build_rotated()) == ROTATED_PATH.read_text(encoding="utf-8")
    assert dump(build_revive()) == REVIVE_PATH.read_text(encoding="utf-8")


@pytest.mark.parametrize("case", ROTATED["cases"], ids=lambda c: c["name"])
def test_each_rotated_case(case):
    assert sync_core.call("team_log_rotated_seals", **_seal_args(case)) == case["expect"]


@pytest.mark.parametrize("case", REVIVE["cases"], ids=lambda c: c["name"])
def test_each_revive_case(case):
    got = sync_core.call("revive_folders", deleted=case["deleted"], work_in=case["work_in"])
    assert got == case["expect"]


def test_the_desktop_has_no_rules_of_its_own():
    from sezam.vault import sync_rekey, sync_state

    seal = inspect.getsource(sync_rekey.RekeyMixin._seal_to_rotated_members)
    for copy in ('"member.keys"', "key_recipients", "may_seal", "is_admin", "current_key"):
        assert copy not in seal, copy
    revive = inspect.getsource(sync_state.SyncStateMixin._revive_folders_of_unsent)
    assert "+ 1" not in revive and "max(" not in revive


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for teamlog.js")
def test_the_page_gives_each_case():
    got = _run_source(TEAMLOG_JS, """(async () => {
        const seals = {}, revive = {};
        for (const c of %s) {
            seals[c.name] = globalThis.SezamSyncCore.call('team_log_rotated_seals', {
                state: c.state, done: c.done, bodies: c.bodies, user_id: c.user_id, trusted: c.trusted,
                blocked: c.blocked, withheld: c.withheld, projected: c.projected,
            });
        }
        for (const c of %s) {
            revive[c.name] = globalThis.SezamSyncCore.call('revive_folders', { deleted: c.deleted, work_in: c.work_in });
        }
        return { seals, revive };
    })()""" % (json.dumps(ROTATED["cases"]), json.dumps(REVIVE["cases"])))
    assert got == {
        "seals": {c["name"]: c["expect"] for c in ROTATED["cases"]},
        "revive": {c["name"]: c["expect"] for c in REVIVE["cases"]},
    }


def test_the_page_has_no_rules_of_its_own():
    text = APP_JS.read_text(encoding="utf-8")
    start = text.index("async function sealToRotatedMembers(")
    seal = text[start:text.index("\n}\n", start)]
    for copy in ("'member.keys'", "keyRecipients", "maySeal", "isAdmin", "currentKey"):
        assert copy not in seal, copy
    start = text.index("async function reviveFoldersOfUnsentWork(")
    revive = text[start:text.index("\n}\n", start)]
    assert "tombstone + 1" not in revive
