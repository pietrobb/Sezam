"""#345 bypass of review 7c10379 H3 (web): who may supply a folder's key.

The H3 fix took folder keys, key envelopes and key archives only from this
account and "the admin", known as anyone who signed a top-level folder. The
server decides which top-level folders it takes and serves, so an account it
made ('Eve') signing a top-level folder of her own counted as an admin
everywhere (the same cause as capability run 196 on the desktop): her key for
the admin's empty folder became the key new items there were sealed with, an
envelope from her to a member was opened, and her archive retired the
folder's real key. Now a key counts for a folder only from this account or
the account that signed the top of that folder's tree.
"""

from __future__ import annotations

from tests.test_review7_web_folder_key_h3 import (
    ADMIN, KEYS, MEMBER, MEMBER_DEK, SUB, SUB_DEK, TEAM, TEAM_DEK,
    _archive, _dek, _js, _rec, _state,
)
from tests.test_review_web import pytestmark  # noqa: F401

EVE = "01EV000000000000000000000A"
EVE_ROOT = "01R1000000000000000000000A"
EVE_DEK = "01D9000000000000000000000A"   # newer than SUB_DEK
KEYS[EVE_DEK] = bytes([9]) * 32


def _eve(*objects):
    return [_rec(EVE_ROOT, "node", None, signer=EVE), *objects]


def test_a_key_from_an_account_with_its_own_top_level_folder_is_not_the_folders_key():
    state = _state(_eve(_dek(TEAM_DEK, TEAM), _dek(SUB_DEK, SUB), _dek(EVE_DEK, SUB, signer=EVE)))
    assert _js(f"nearestFolderDekId('{SUB}')", state) == SUB_DEK


def test_her_archive_retires_no_key_of_the_admins_folder():
    state = _state([
        _rec(EVE_ROOT, "node", None, signer=MEMBER),
        _dek(TEAM_DEK, TEAM), _dek(SUB_DEK, SUB), _dek(MEMBER_DEK, SUB, signer=MEMBER),
        _archive(SUB_DEK, MEMBER_DEK, MEMBER),
    ])
    assert _js(f"[nearestFolderDekId('{SUB}'), Object.keys(provenDekSuccessors())]", state) == [
        SUB_DEK, []]


def test_her_envelope_for_a_key_of_the_admins_folder_is_not_opened():
    envelopes = [
        {"id": "01V0000000000000000000000A", "target_user_id": MEMBER,
         "signature_user_id": ADMIN, "parent_ref": SUB_DEK},
        {"id": "01V2000000000000000000000A", "target_user_id": MEMBER,
         "signature_user_id": EVE, "parent_ref": EVE_DEK},
        {"id": "01V4000000000000000000000A", "target_user_id": MEMBER,
         "signature_user_id": MEMBER, "parent_ref": EVE_DEK},
    ]
    state = _state(_eve(_dek(SUB_DEK, SUB), _dek(EVE_DEK, SUB, signer=EVE)), user=MEMBER)
    script = (
        f"keyEnvelopesForUser({envelopes!r}, state.syncObjects, '{MEMBER}').map(e => e.id)"
    ).replace("'", '"')
    assert _js(script, state) == ["01V0000000000000000000000A", "01V4000000000000000000000A"]


def test_her_keys_for_her_own_folder_still_count():
    """A key for a folder in Eve's own tree is hers to make."""
    eve_folder = "01S9000000000000000000000A"
    state = _state(_eve(_rec(eve_folder, "node", EVE_ROOT, signer=EVE),
                        _dek(EVE_DEK, eve_folder, signer=EVE)), user=MEMBER)
    state["nodes"][EVE_ROOT] = {"id": EVE_ROOT, "parent_ref": None}
    state["nodes"][eve_folder] = {"id": eve_folder, "parent_ref": EVE_ROOT}
    envelopes = [{"id": "01V2000000000000000000000A", "target_user_id": MEMBER,
                  "signature_user_id": EVE, "parent_ref": EVE_DEK}]
    script = (
        f"[nearestFolderDekId('{eve_folder}'),"
        f" keyEnvelopesForUser({envelopes!r}, state.syncObjects, '{MEMBER}').length]"
    ).replace("'", '"')
    assert _js(script, state) == [EVE_DEK, 1]


def test_with_a_log_no_other_accounts_key_counts_outside_it():
    """Review 1141a20 H6: with a (trusted) team log the tree owner rule above is
    gone; another account's envelope on a key the log does not know is not
    opened, Eve's for her own folder nor the admin's. Own envelopes stay."""
    eve_folder = "01S9000000000000000000000A"
    state = _state(_eve(_rec(eve_folder, "node", EVE_ROOT, signer=EVE),
                        _dek(EVE_DEK, eve_folder, signer=EVE), _dek(SUB_DEK, SUB)), user=MEMBER)
    envelopes = [
        {"id": "01V0000000000000000000000A", "target_user_id": MEMBER,
         "signature_user_id": ADMIN, "parent_ref": SUB_DEK},
        {"id": "01V2000000000000000000000A", "target_user_id": MEMBER,
         "signature_user_id": EVE, "parent_ref": EVE_DEK},
        {"id": "01V4000000000000000000000A", "target_user_id": MEMBER,
         "signature_user_id": MEMBER, "parent_ref": EVE_DEK},
    ]
    script = (
        "webTeamLogTrusted = () => true;"
        f"[keyEnvelopesForUser({envelopes!r}, state.syncObjects, '{MEMBER}').map(e => e.id),"
        f" keyEnvelopesForUser({envelopes!r}, state.syncObjects, '{MEMBER}',"
        " {team: {dekIndex: {}, members: {}}}, sodium).map(e => e.id)]"
    ).replace("'", '"')
    assert _js(script, state) == [
        ["01V0000000000000000000000A", "01V2000000000000000000000A", "01V4000000000000000000000A"],
        ["01V4000000000000000000000A"],
    ]


def test_a_top_level_folder_that_does_not_open_names_no_owner():
    """A version of the admin's top-level folder re-signed by Eve (a lying
    server serving it) cannot be sealed under the admin's key: it does not
    open here, and its signer owns nothing."""
    from tests.test_review7_web_folder_key_h3 import ROOT
    state = _state([_dek(SUB_DEK, SUB), _dek(EVE_DEK, SUB, signer=EVE)], user=MEMBER)
    state["syncObjects"][ROOT]["signer"] = EVE
    state["syncObjects"][ROOT]["owner_id"] = EVE
    state["nodes"][ROOT]["_undecryptable"] = True
    assert _js(f"nearestFolderDekId('{SUB}')", state) is None
