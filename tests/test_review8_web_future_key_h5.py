"""Review a159e97 H5 (web): a folder whose only key has an id from the future.

The key was skipped (7c10379 H3: a future id no longer wins by itself) and the
search went on to the parent folder, so a new item was sealed under the
parent's key, which members of the parent only can read. The save is refused.
"""

from __future__ import annotations

from tests.test_review7_web_folder_key_h3 import (
    FUTURE_DEK, SUB, SUB_DEK, TEAM, TEAM_DEK, _dek, _js, _state,
)
from tests.test_review_web import pytestmark  # noqa: F401


def test_a_folder_whose_only_key_is_from_the_future_refuses_the_save():
    state = _state([_dek(TEAM_DEK, TEAM), _dek(FUTURE_DEK, SUB)])
    script = (
        f"(() => {{ try {{ return nearestFolderDekId('{SUB}'); }}"
        " catch (err) { return err.folderKeyFromFuture ? 'refused' : err.message; } })()"
    )
    assert _js(script, state) == "refused"  # before: TEAM_DEK, the parent's key


def test_a_folder_with_a_current_key_still_uses_it():
    state = _state([_dek(SUB_DEK, SUB), _dek(FUTURE_DEK, SUB)])
    assert _js(f"nearestFolderDekId('{SUB}')", state) == SUB_DEK
