"""CI 44293105454 (stateful-deep): web retry failed "REJECT audit DAG — missing parent".

The browser pulled past the server's backup point, the server was restored
and handed those commit_seqs out again to another device's audit records.
The browser's delta pull then carried a record whose parent sat at a seq it
skipped. The check token told it the history had changed, but the audit DAG
check of the delta ran first and refused it, so it never got to the full
pull a restored server needs.
"""

import sys

from tests import test_sync_state_machine as sm
from tests.test_sync_state_machine import SyncMachine, loopback_server  # noqa: F401


class _Draws:
    def __init__(self, **answers):
        self.answers = answers

    def draw(self, strategy, label=None):
        if label in self.answers:
            return self.answers[label]
        elements = getattr(strategy, "elements", None)
        return list(elements)[0] if elements is not None else False


def test_web_pull_after_server_restore_takes_the_restored_history(loopback_server, monkeypatch):  # noqa: F811
    monkeypatch.setattr(sys.modules[sm.__name__], "coverage_event", lambda _name: None)
    SyncMachine.server = loopback_server
    m = SyncMachine()
    try:
        m.open_web_tab()
        m.server_backup()
        for _ in range(3):
            m.edit_entry(_Draws(device="A"))
            m.push(_Draws(device="A"), None)
        m._web_settle()  # the browser's checkpoint is now past the backup
        m.server_restore()
        for _ in range(5):  # B's audit chain reuses the seqs the browser saw
            m.edit_entry(_Draws(device="B"))
            m.push(_Draws(device="B"), None)
        m._web_settle()  # before: REJECT audit DAG ... missing parent
        assert m.web_view.get("error") is None
    finally:
        m.teardown()
