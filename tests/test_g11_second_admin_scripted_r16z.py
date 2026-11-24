"""R16-Z SM16 (capability finding 539): the deep run's G11 failure, step by step.

The saved blob (property_seeds.txt, SecondAdminMachine@20) picks rules by
index among the enabled ones: on the fixed server it leaves the G11 path at
draw 25 and still passes. Here SecondAdminMachine runs the G11 rules from the
deep run on 07487c3 in that order, every draw fixed by role (folder, entry and
member names), so the path cannot change silently: a rule whose precondition
is false, or a draw whose role is not on offer, fails the test.

INV-7: after a revocation every member who still has access to a shared folder
decrypts all of its nodes, through tombstone GC, a server backup restore and
a restore from trash (teardown checks it after the settle).
"""

from __future__ import annotations

import contextlib

import pytest
from hypothesis import HealthCheck, Phase, given, settings, strategies as st
from hypothesis.stateful import INVARIANT_MARKER, RULE_MARKER

from tests import test_sync_state_machine as sm
from tests.test_sync_state_machine import loopback_server  # noqa: F401  (fixture)

pytestmark = pytest.mark.skipif(not sm.NODE, reason="the G11 path opens the web client (needs node)")


def _dev(name):
    return ["device", ["lit", name]]


# (rule, arguments, draws): r16_G11_sm.log, the trace of the deep run on 07487c3.
G11 = [
    ("server_lies_about_users", {"lie": "revoked_active"}, [_dev("B")]),
    ("restore_from_trash", {}, [_dev("A")]),
    ("create_entry", {}, [_dev("A"), ["folder", ["node", "F1"]]]),
    ("delete_folder", {}, [_dev("B"), ["folder", ["node", "F1"]]]),
    ("create_folder", {}, [_dev("A"), ["parent", ["node", "F1"]]]),
    ("delete_folder", {}, [_dev("A"), ["folder", ["node", "F2"]]]),
    ("revoke", {"failure": "before"}, [_dev("A"), ["member", ["member", "m7"]]]),
    ("delete_folder", {}, [_dev("B")]),
    ("pull", {"failure": None}, [_dev("A")]),
    ("change_password", {"failure": None}, [_dev("A")]),
    ("push", {"failure": None}, [_dev("B")]),
    ("server_swaps_a_member_key", {"access": "read"},
     [_dev("A"), ["member", ["member", "m6"]], ["folder", ["node", "F9"]]]),
    ("delete_during_rekey", {}, [_dev("A"), ["item", ["item", "entry", ["entry", "E8"]]]]),
    ("gc_tombstones", None, []),
    ("grant", {"access": "write"}, [_dev("A"), ["member", ["member", "m6"]], ["folder", ["node", "F1"]]]),
    ("second_admin_revokes", {"failure": "after"}, [["admin", ["member", "m6"]]]),
    ("push", {"failure": None}, [_dev("A")]),
    ("server_backup", None, []),
    ("restore_from_trash", {}, [_dev("B"), ["trash item", ["trash", "folder", "F1"]]]),
    ("change_password", {"failure": None}, [_dev("B")]),
    ("server_lies_into_full_resync", {"old_wraps": True, "trigger": "gone"}, [_dev("A")]),
    ("gc_tombstones", None, []),
    ("server_restore", None, []),
    ("open_web_tab", None, []),
    # On the fixed server A's held re-key is refused at the grant (step 15),
    # A drops it before its full resync, and the restored server holds no
    # folder the page can see yet: the page draws none.
    ("web_create_entry", {"failure": None}, [["folder", ["node", "F9"]]]),
]
# Steps whose rule may return before its last draws (see above).
MAY_DRAW_LESS = {25}
# What the G11 steps must have done (machine log), whichever way the fix went.
G11_EFFECTS = ("server: tombstone GC collected", "server: backup", "B: restore folder",
               "server: restored from backup", "W: open the web client")


def _names(m) -> dict:
    out = {}
    vaults = [d.vault for d in m.devices.values()] + [x.vault for x in m.members.values() if x.vault is not None]
    for vault in vaults:
        ids = [r["id"] for r in vault.db.fetchall("SELECT id FROM nodes WHERE is_deleted = 0")]
        for nid in [None, *ids]:
            # A member's vault holds folders it has no key for: another vault names them.
            with contextlib.suppress(Exception):
                for node in vault.list_nodes(nid):
                    out.setdefault(node["id"], ["node", node["name"]])
            if nid is not None:
                with contextlib.suppress(Exception):
                    for entry in vault.list_entries(nid):
                        out.setdefault(entry["id"], ["entry", entry["name"]])
    return out


def _role(m, value):
    if isinstance(value, dict):
        return ["trash", value["type"], value["name"]]
    if isinstance(value, tuple):
        return ["item", value[0], _role(m, value[1])]
    if isinstance(value, str) and value in m.members:
        return ["member", m.members[value].name]
    if isinstance(value, str) and value not in m.devices:
        known = _names(m).get(value)
        if known:
            return known
    return ["lit", value]


class _ScriptedData:
    """st.data() for one rule: each draw takes the element with the G11 role."""

    def __init__(self, machine, step, draws):
        self.m, self.step, self.draws = machine, step, list(draws)

    def draw(self, strategy, label=None):
        assert self.draws, f"step {self.step}: draws more than in G11 ({label!r})"
        want_label, role = self.draws.pop(0)
        assert label == want_label, f"step {self.step}: draw {label!r}, G11 drew {want_label!r}"
        offered = list(strategy.elements)
        for value in offered:
            if _role(self.m, value) == role:
                return value
        raise AssertionError(f"step {self.step}: {role} is not on offer {[_role(self.m, v) for v in offered]}")


def _invariants(m) -> None:
    for name in dir(type(m)):
        inv = getattr(getattr(type(m), name, None), INVARIANT_MARKER, None)
        if inv and all(p(m) for p in inv.preconditions):
            inv.function(m)


@settings(max_examples=1, database=None, deadline=None, phases=[Phase.generate],
          suppress_health_check=list(HealthCheck))
@given(st.just(None))
def _run_g11(_):
    m = sm.SecondAdminMachine()
    try:
        _invariants(m)
        for step, (name, kwargs, draws) in enumerate(G11, 1):
            rule = getattr(getattr(type(m), name), RULE_MARKER)
            closed = [p for p in rule.preconditions if not p(m)]
            assert not closed, f"step {step} {name}: precondition false; the G11 path cannot run here"
            data = _ScriptedData(m, step, draws)
            if kwargs is None:
                rule.function(m)
            else:
                rule.function(m, data=data, **kwargs)
            assert not data.draws or step in MAY_DRAW_LESS, f"step {step} {name}: left G11 draws {data.draws}"
            _invariants(m)
        missing = [e for e in G11_EFFECTS if not any(line.startswith(e) for line in m.log)]
        assert not missing, f"the G11 steps did not happen: {missing}"
    finally:
        m.teardown()


def test_g11_second_admin_path_keeps_every_member_able_to_decrypt(loopback_server):  # noqa: F811
    sm.SecondAdminMachine.server = loopback_server
    _run_g11()
