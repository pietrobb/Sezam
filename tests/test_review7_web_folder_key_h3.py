"""Review 7c10379 H3: what picked the key the web seals new items with.

Any entry with tier 2 in its meta took its key out of the choice. One item a
write member sealed under a folder's key with tier 2 (or the web's own move of
a tier-2 item, which sealed it under the new folder's key) had new items in
that folder sealed under the parent folder's key, which members of the parent
only could read. And the newest key id won: a key a member signed with a ULID
from the future stayed the folder's key after the member was removed. Both
were reproduced in a real browser. Now a folder's keys are ranked like the
desktop's _is_folders_own_key, only the admin's and this account's keys,
envelopes and archives count, and a key id from the future is ignored.
"""

from __future__ import annotations

import base64
import re
import time

from sezam.crypto.aead import encrypt_dek_wrap
from sezam.models import ulid_to_bytes
from tests.test_review_web import APP, _run, pytestmark  # noqa: F401

ADMIN = "01AD000000000000000000000A"
MEMBER = "01ME000000000000000000000A"
ROOT = "01R0000000000000000000000A"
TEAM = "01T0000000000000000000000A"
SUB = "01S0000000000000000000000A"
TEAM_DEK = "01D0000000000000000000000A"
SUB_DEK = "01D1000000000000000000000A"
TIER2_DEK = "01D2000000000000000000000A"   # newer than SUB_DEK
MEMBER_DEK = "01D3000000000000000000000A"
ARCHIVE = "01A0000000000000000000000A"
ENTRY = "01E0000000000000000000000A"
FORGED = "01E1000000000000000000000A"
PLAIN = "01E2000000000000000000000A"


def _future_ulid(days: int = 365) -> str:
    chars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    stamp, out = int(time.time() * 1000) + days * 86_400_000, ""
    for _ in range(10):
        out = chars[stamp % 32] + out
        stamp //= 32
    return out + "0000000000000000"


FUTURE_DEK = _future_ulid()

KEYS = {
    TEAM_DEK: bytes([1]) * 32,
    SUB_DEK: bytes([2]) * 32,
    TIER2_DEK: bytes([3]) * 32,
    MEMBER_DEK: bytes([4]) * 32,
    FUTURE_DEK: bytes([5]) * 32,
}

FUNCTIONS = [
    "nearestFolderDekId", "resolveWriteDekId", "resolveInheritedPersonalDekId",
    "provenDekSuccessors", "finalDekSuccessor", "keyAuthors", "folderTreeOwner", "keyEnvelopesForUser", "ulidTimeMs",
    "unwrapDEK", "buildAAD", "unpadPlaintext",
]
CONSTANTS = (
    "const ENVELOPE_ALG = 1; const SCHEMA_VERSION = 1;\n"
    + re.search(r"const BLOB_KIND = \{.*?\};", APP, re.S).group(0) + "\n"
    + "state.sodium = sodium;\n"
    + "for (const id of Object.keys(state.deks)) state.deks[id] = hex(state.deks[id]);\n"
)


def _rec(obj_id, object_type, parent_ref, signer=ADMIN, **extra):
    return {"id": obj_id, "object_type": object_type, "parent_ref": parent_ref,
            "is_deleted": 0, "version": 1, "signer": signer, "owner_id": signer, **extra}


def _dek(dek_id, parent_ref, signer=ADMIN, scope="folder"):
    return _rec(dek_id, "dek", parent_ref, signer, scope=scope)


def _archive(old_id, new_id, signer):
    blob = encrypt_dek_wrap(KEYS[old_id], KEYS[new_id], ulid_to_bytes(new_id), ulid_to_bytes(ARCHIVE))
    return _rec(ARCHIVE, "dek_archive", new_id, signer,
                payload=base64.b64encode(blob).decode())


def _entry(entry_id, parent_ref, dek_id, tier, signer=ADMIN):
    return {"id": entry_id, "parent_ref": parent_ref, "dekId": dek_id, "tier": tier,
            "owner_id": signer}


def _state(objects, entries=(), held=None, user=ADMIN):
    objects = [_rec(ROOT, "node", None), _rec(TEAM, "node", ROOT), _rec(SUB, "node", TEAM),
               *objects]
    for entry in entries:
        objects.append(_rec(entry["id"], "entry", entry["parent_ref"], entry["owner_id"]))
    dek_ids = [o["id"] for o in objects if o["object_type"] == "dek"]
    return {
        "userId": user,
        "deks": {dek_id: KEYS[dek_id].hex() for dek_id in (held or dek_ids)},
        "nodes": {
            ROOT: {"id": ROOT, "parent_ref": None},
            TEAM: {"id": TEAM, "parent_ref": ROOT, "dekId": TEAM_DEK},
            SUB: {"id": SUB, "parent_ref": TEAM, "dekId": TEAM_DEK},
        },
        "entries": {entry["id"]: entry for entry in entries},
        "syncObjects": {obj["id"]: obj for obj in objects},
    }


def _js(script, state):
    return _run(FUNCTIONS, CONSTANTS + script, state)


def test_a_members_tier2_item_under_the_folder_key_keeps_it_the_folders_key():
    """The reviewer's first variant: one forged tier-2 item."""
    state = _state(
        [_dek(TEAM_DEK, TEAM), _dek(SUB_DEK, SUB)],
        [_entry(FORGED, SUB, SUB_DEK, 2, signer=MEMBER)],
    )
    assert _js(f"nearestFolderDekId('{SUB}')", state) == SUB_DEK


def test_an_honestly_moved_tier2_item_does_not_take_the_folder_key_out():
    """An old web move sealed a tier-2 item under the new folder's key."""
    state = _state(
        [_dek(TEAM_DEK, TEAM), _dek(SUB_DEK, SUB)],
        [_entry(ENTRY, SUB, SUB_DEK, 2)],
    )
    assert _js(f"nearestFolderDekId('{SUB}')", state) == SUB_DEK


def test_a_moved_tier2_item_keeps_its_own_key():
    state = _state(
        [_dek(TEAM_DEK, TEAM), _dek(SUB_DEK, SUB), _dek(TIER2_DEK, TEAM, scope="tier2")],
        [_entry(ENTRY, TEAM, TIER2_DEK, 2)],
    )
    assert _js(f"resolveWriteDekId('{SUB}', state.entries['{ENTRY}'])", state) == TIER2_DEK


def test_with_a_real_tier2_key_the_folder_key_still_wins():
    """The folder key seals a tier-0 item; the newer key only a tier-2 item."""
    state = _state(
        [_dek(SUB_DEK, SUB), _dek(TIER2_DEK, SUB, scope="folder")],
        [_entry(PLAIN, SUB, SUB_DEK, 0), _entry(ENTRY, SUB, TIER2_DEK, 2),
         _entry(FORGED, SUB, SUB_DEK, 2, signer=MEMBER)],
    )
    assert _js(f"nearestFolderDekId('{SUB}')", state) == SUB_DEK


def test_a_key_id_from_the_future_is_not_the_folders_key():
    """The reviewer's second variant: the newest id no longer wins by itself."""
    state = _state([_dek(SUB_DEK, SUB), _dek(FUTURE_DEK, SUB)])
    assert _js(f"nearestFolderDekId('{SUB}')", state) == SUB_DEK


def test_a_key_a_member_signed_is_not_the_folders_key():
    state = _state([_dek(SUB_DEK, SUB), _dek(MEMBER_DEK, SUB, signer=MEMBER)])
    assert _js(f"nearestFolderDekId('{SUB}')", state) == SUB_DEK


def test_a_members_archive_retires_no_folder_key():
    """Else the folder's key counted as retired and the parent's key sealed."""
    state = _state([_dek(TEAM_DEK, TEAM), _dek(SUB_DEK, SUB), _dek(MEMBER_DEK, SUB, signer=MEMBER),
                    _archive(SUB_DEK, MEMBER_DEK, MEMBER)])
    assert _js(f"[nearestFolderDekId('{SUB}'), Object.keys(provenDekSuccessors())]", state) == [
        SUB_DEK, []]


def test_the_admins_archive_still_names_the_successor():
    state = _state([_dek(SUB_DEK, SUB), _dek(MEMBER_DEK, SUB), _archive(SUB_DEK, MEMBER_DEK, ADMIN)])
    assert _js(f"nearestFolderDekId('{SUB}')", state) == MEMBER_DEK


def test_only_the_admins_envelopes_are_opened():
    envelopes = [
        {"id": "01V0000000000000000000000A", "target_user_id": MEMBER, "signature_user_id": ADMIN},
        {"id": "01V1000000000000000000000A", "target_user_id": MEMBER, "signature_user_id": MEMBER},
        {"id": "01V2000000000000000000000A", "target_user_id": MEMBER,
         "signature_user_id": "01EV000000000000000000000A"},
        {"id": "01V3000000000000000000000A", "target_user_id": ADMIN, "signature_user_id": ADMIN},
    ]
    for envelope in envelopes:
        envelope["parent_ref"] = TEAM_DEK
    state = _state([_dek(TEAM_DEK, TEAM)], user=MEMBER)
    script = (
        f"keyEnvelopesForUser({envelopes!r}, state.syncObjects, '{MEMBER}')"
        ".map(e => e.id)"
    ).replace("'", '"').replace("None", "null")
    assert _js(script, state) == ["01V0000000000000000000000A", "01V1000000000000000000000A"]
