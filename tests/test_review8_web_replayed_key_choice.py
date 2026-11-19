"""Review a159e97 (web, medium): a replayed item version brought its old key back.

resolveWriteDekId kept the key named in an existing item's ciphertext. A
server replaying the item's version from before a re-key (validly signed, by
this account) named the key the re-key retired, and the next edit sealed the
item under it again - readable by the member the re-key removed. The key an
edit keeps is now followed to its proven successor.
"""

from __future__ import annotations

from tests.test_review7_web_folder_key_h3 import (
    ADMIN, ENTRY, MEMBER_DEK, SUB, SUB_DEK, TEAM, TEAM_DEK, TIER2_DEK,
    _archive, _dek, _entry, _js, _state,
)
from tests.test_review_web import pytestmark  # noqa: F401

def _resolve(state, parent):
    return _js(f"resolveWriteDekId('{parent}', state.entries['{ENTRY}'])", state)


def test_an_edit_of_a_replayed_version_seals_under_the_successor():
    # SUB_DEK was re-keyed to MEMBER_DEK (the id is just a held key here) by
    # the admin; the server serves the item's old version, still under SUB_DEK.
    state = _state([_dek(SUB_DEK, SUB), _dek(MEMBER_DEK, SUB), _archive(SUB_DEK, MEMBER_DEK, ADMIN)],
                   [_entry(ENTRY, SUB, SUB_DEK, 0)])
    assert _resolve(state, SUB) == MEMBER_DEK  # before: SUB_DEK, the retired key


def test_a_replayed_tier2_item_follows_its_own_keys_successor():
    state = _state([_dek(TEAM_DEK, TEAM), _dek(SUB_DEK, SUB), _dek(TIER2_DEK, TEAM, scope="tier2"),
                    _dek(MEMBER_DEK, TEAM, scope="tier2"), _archive(TIER2_DEK, MEMBER_DEK, ADMIN)],
                   [_entry(ENTRY, TEAM, TIER2_DEK, 2)])
    assert _resolve(state, SUB) == MEMBER_DEK  # before: TIER2_DEK


def test_a_current_key_is_kept():
    state = _state([_dek(SUB_DEK, SUB)], [_entry(ENTRY, SUB, SUB_DEK, 0)])
    assert _resolve(state, SUB) == SUB_DEK
