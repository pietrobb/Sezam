"""Review e4cd15a (low): a deferred member removal on the web needed no new confirmation.

A removal interrupted by a password change on another device is set aside
and finished at the next login, which may come days later, when the admin
may no longer want it. It finished silently. Each one is now confirmed again
by name; a declined one is dropped and the member stays.
"""

from __future__ import annotations

from tests.test_review_web import _run, pytestmark  # noqa: F401
from tests.test_web_set_aside_records_272 import FAKE_NET, JOURNAL
from tests.test_web_old_kek_records import FAKE_IDB

SET_ASIDE_BOB = FAKE_IDB + FAKE_NET + """
  state.kek = oldKek;
  await saveWebRekeyJournal({ revoked_user_id: 'BOB', phase: 'prepared', objects: [{ id: 'OLD' }] }, sodium);
  const sealed = records.get('dirty_state:ME');
  records.delete('dirty_state:ME');
  records.set('stale_kek:1:dirty_state:ME', { ...sealed, id: 'stale_kek:1:dirty_state:ME' });
  state.kek = newKek;
  state.outboxOps = [];
  const users = apiFetch;
  apiFetch = async (path, options = {}) => (
    path === '/api/users' ? [{ id: 'BOB', username: 'bob' }] : users(path, options)
  );
  const asked = [];
  t = (key, params) => `${key} ${JSON.stringify(params || {})}`;
"""


def test_declined_removal_is_dropped_and_the_member_stays():
    script = SET_ASIDE_BOB + """
      confirm = question => { asked.push(question); return false; };
      const unfinished = await finishSetAsideWebRevocations(sodium);
      return { unfinished, asked, calls, ids: [...records.keys()] };
    """
    result = _run(JOURNAL, f"(async () => {{ {script} }})()")
    assert result == {
        "unfinished": [],
        "asked": ['sync.set_aside_revocation_confirm {"user":"bob"}'],
        "calls": [],
        "ids": [],
    }


def test_confirmed_removal_is_finished():
    script = SET_ASIDE_BOB + """
      confirm = question => { asked.push(question); return true; };
      const unfinished = await finishSetAsideWebRevocations(sodium);
      return { unfinished, asked: asked.length, calls, ids: [...records.keys()] };
    """
    result = _run(JOURNAL, f"(async () => {{ {script} }})()")
    assert result == {
        "unfinished": [],
        "asked": 1,
        "calls": ["pull", "sync NEW1-BOB", "DELETE /api/users/BOB"],
        "ids": [],
    }
