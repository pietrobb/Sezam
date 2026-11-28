"""U7f (docs/CORE_UNIFICATION.md, capability run 709):
tests/vectors/team_log_anchor_pin.json through the core as the desktop asks
it, and through the page's WASM core. The phone runs the same file
(mobile/test/team_log_anchor_pin_vectors_test.dart)."""

from __future__ import annotations

import inspect
import json
import re
from types import SimpleNamespace

import pytest

from sezam.vault import sync_core
from tests.node_support import node_problem
from tests.team_log_anchor_pin_vectors import VECTORS_PATH, build_vectors, dump
from tests.test_review_web import _run_source
from tests.test_team_log_web_pull import TEAMLOG_JS

VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
ARGS = ("unreadable", "anchor", "forgotten", "confirmed", "pins", "held", "copy_error")
A, B = "aa" * 32, "bb" * 32
APP_JS = VECTORS_PATH.parents[2] / "web" / "static" / "js" / "app.js"
TEAM_LOG_CLIENT = VECTORS_PATH.parents[2] / "mobile" / "lib" / "services" / "team_log_client.dart"


def test_the_builder_still_gives_the_file():
    assert dump(build_vectors()) == VECTORS_PATH.read_text(encoding="utf-8")


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_each_case(case):
    assert sync_core.call("team_log_anchor_pin", **{k: case[k] for k in ARGS}) == case["expect"]


class _Db:
    def __init__(self, meta, first=None):
        self.meta, self.first = dict(meta), first

    def get_meta(self, key):
        return self.meta.get(key)

    def set_meta(self, key, value):
        self.meta[key] = value

    def fetchone(self, sql, *args):
        return self.first

    def execute(self, sql, args=()):
        self.meta.pop(args[0], None)


def test_the_desktop_pins_no_anchor_the_checkpoint_or_copy_contradicts(monkeypatch):
    """The probe of run 709: copy and pin of genesis B, keys naming A."""
    from sezam.vault import team_log_state as tls

    monkeypatch.setattr(tls, "readable_forgotten_genesis", lambda db: [])
    monkeypatch.setattr(tls, "_held", lambda db, state=None: {"genesis": B, "stored": B})
    db = _Db({tls.GENESIS_META: B})
    tls.record_account_anchor(db, SimpleNamespace(confirmed_genesis=A, pre_anchor=b""))
    assert db.meta.get(tls.CONFIRMED_GENESIS_META) is None
    assert db.meta[tls.ACCOUNT_ANCHOR_META] == A
    with pytest.raises(tls.TeamLogMismatch):
        tls.import_account_anchor(db, SimpleNamespace(confirmed_genesis=A, pre_anchor=b""))


def test_the_desktop_has_no_rules_of_its_own():
    from sezam.vault import team_log_state

    for fn in (team_log_state.record_account_anchor, team_log_state.import_account_anchor):
        text = inspect.getsource(fn)
        assert "forgotten" not in text and "local_refusal" not in text, fn.__name__
    assert '"team_log_anchor_pin"' in inspect.getsource(team_log_state.anchor_pin)


def _function(text, signature):
    start = text.index(signature)
    return text[start:text.index("\n}\n", start)]


def test_the_page_has_no_rules_of_its_own():
    text = APP_JS.read_text(encoding="utf-8").replace("\r\n", "\n")
    for name in ("async function importAccountTeamAnchor(", "async function keepTeamAnchor("):
        body = _function(text, name)
        assert ".includes(" not in body and "loadConfirmedTeamGenesis" not in body, name
        assert "webLocalTeamLogRefusal" not in body, name
    assert "'team_log_anchor_pin'" in _function(text, "async function anchorPin(")


def test_the_phone_has_no_rules_of_its_own():
    text = TEAM_LOG_CLIENT.read_text(encoding="utf-8").replace("\r\n", "\n")
    for name in ("Future<void> recordAccountTeamGenesis(", "Future<void> importAccountTeamGenesis(",
                 "Future<void> keepAccountTeamGenesis("):
        body = _function(text, name)
        assert ".contains(" not in body and "readConfirmedTeamGenesis" not in body, name
    assert "syncCore('team_log_anchor_pin'" in _function(text, "Future<Map> anchorPin(")
    auth = (TEAM_LOG_CLIENT.parent / "auth_service.dart").read_text(encoding="utf-8")
    assert not re.search(r"readConfirmedTeamGenesis\(userId\) == null\)\s*await confirmTeamGenesis", auth)


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for teamlog.js")
def test_the_page_gives_each_case():
    got = _run_source(TEAMLOG_JS, """(async () => {
        const out = {};
        for (const c of %s) {
            const { name, expect, ...input } = c;
            out[name] = globalThis.SezamSyncCore.call('team_log_anchor_pin', input);
        }
        return out;
    })()""" % json.dumps(VECTORS["cases"]))
    assert got == {c["name"]: c["expect"] for c in VECTORS["cases"]}
