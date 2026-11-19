"""Review 1141a20 (R9-G), web: an own item moved to the personal root.

Carol, read-only in the team folder F1, holds an item of her own there sealed
with her personal key (an older device put it there while she could write).
TL7: she may move it back to her personal root - the server takes it
(move_refusal own_personal), the desktop and now the phone judge it so too.
The browser judged the move without ownPersonal: it would not send it, and a
pull hid it as a removal from F1 she had no right to. Someone else's item, or
hers sealed with the folder's key, still may not leave.
"""

from __future__ import annotations

from tests.test_team_log_web_pull import SNAPSHOT, TEAM, WRITER, _run
from tests.test_review_web import pytestmark  # noqa: F401

OWN = """
  put(rec('CAROL_KEY', 'dek', null, ids.C, null),
      rec('CAROL_HOME', 'node', null, ids.C, 'CAROL_KEY'),
      rec('CAROL_OWN', 'entry', ids.F1, ids.C, 'CAROL_KEY'),
      rec('CAROL_TEAM', 'entry', ids.F1, ids.C, ids.K1));
"""


def test_the_browser_sends_an_own_items_move_to_the_personal_root():
    result = _run(WRITER + OWN + """
      state.syncObjects = objects;
      return {
        own: attempt(ids.C, rec('CAROL_OWN', 'entry', 'CAROL_HOME', ids.C, 'CAROL_KEY', { version: 2 })),
        team_key: attempt(ids.C, rec('CAROL_TEAM', 'entry', 'CAROL_HOME', ids.C, 'CAROL_KEY', { version: 2 })),
        bobs: attempt(ids.C, rec('BOB_ITEM', 'entry', 'CAROL_HOME', ids.C, 'CAROL_KEY', { version: 2 })),
      };
    """, TEAM)
    assert result["own"] == "ok"
    for who in ("team_key", "bobs"):
        assert "team log gives no write access here" in result[who], who


def test_a_pull_shows_an_own_item_moved_to_the_personal_root():
    result = _run(SNAPSHOT + OWN + """
      const previous = JSON.parse(JSON.stringify(objects));
      put(rec('CAROL_OWN', 'entry', 'CAROL_HOME', ids.C, 'CAROL_KEY', { version: 2 }),
          rec('CAROL_TEAM', 'entry', 'CAROL_HOME', ids.C, 'CAROL_KEY', { version: 2 }));
      const out = unauthorizedWrites(objects, ids.C, team, previous);  // Carol's own browser
      return { blocked: [...out].sort(), byTeamLog: [...out.byTeamLog].sort() };
    """, TEAM)
    assert result["blocked"] == ["CAROL_TEAM"]
    assert result["byTeamLog"] == ["CAROL_TEAM"]

