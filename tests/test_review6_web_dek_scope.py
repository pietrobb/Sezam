"""Review main@d615826 H3: the server steered the web's choice of DEK.

The DEK ``scope`` label is unsigned. A subfolder's key relabelled 'tier2' was
skipped, and a new entry was sealed under the parent folder's key, which a
member with access to the parent only could read. A personal DEK relabelled
'folder' counted as a retired folder key, and the sweep after a re-key sealed
the personal folder again under the shared parent's key. The sweep also took
the newest ULID under a folder as its current key, with no proof that a
re-key replaced the older one. Now only signed facts decide: the DEK's
parent_ref, a tier-2 entry naming it, and a dek_archive (old key sealed under
the new one) proving each replacement.
"""

from __future__ import annotations

import base64
import re

from sezam.crypto.aead import encrypt_dek_wrap
from sezam.models import ulid_to_bytes
from tests.test_review_web import APP, _run, pytestmark  # noqa: F401

ROOT = "01R0000000000000000000000A"
TEAM = "01T0000000000000000000000A"
SUB = "01S0000000000000000000000A"
ME = "01M0000000000000000000000A"
TEAM_DEK = "01D0000000000000000000000A"
SUB_DEK = "01D1000000000000000000000A"
PERSONAL_DEK = "01D2000000000000000000000A"
NEW_DEK = "01D3000000000000000000000A"
ARCHIVE = "01A0000000000000000000000A"
USER = "01U0000000000000000000000A"  # the admin, signer of every key here
RETIRED_DEK = "01DZ000000000000000000000A"  # a newer ULID than its successor

KEYS = {
    TEAM_DEK: bytes([1]) * 32,
    SUB_DEK: bytes([2]) * 32,
    PERSONAL_DEK: bytes([3]) * 32,
    NEW_DEK: bytes([4]) * 32,
    RETIRED_DEK: bytes([5]) * 32,
}

FUNCTIONS = [
    "provenDekSuccessors", "finalDekSuccessor", "retiredFolderDekIds",
    "nearestFolderDekId", "unwrapDEK", "buildAAD", "unpadPlaintext", "keyAuthors", "folderTreeOwner", "ulidTimeMs",
]
CONSTANTS = (
    "const ENVELOPE_ALG = 1; const SCHEMA_VERSION = 1;\n"
    + re.search(r"const BLOB_KIND = \{.*?\};", APP, re.S).group(0) + "\n"
    + "state.sodium = sodium;\n"
    + "for (const id of Object.keys(state.deks)) state.deks[id] = hex(state.deks[id]);\n"
)


def _dek(dek_id, parent_ref, scope):
    return {"id": dek_id, "object_type": "dek", "parent_ref": parent_ref,
            "is_deleted": 0, "version": 1, "scope": scope, "signer": USER}


def _archive(old_id, new_id):
    blob = encrypt_dek_wrap(KEYS[old_id], KEYS[new_id], ulid_to_bytes(new_id), ulid_to_bytes(ARCHIVE))
    return {"id": ARCHIVE, "object_type": "dek_archive", "parent_ref": new_id,
            "is_deleted": 0, "version": 1, "payload": base64.b64encode(blob).decode(),
            "signer": USER}


def _state(sync_objects, held):
    return {
        "userId": USER,
        "deks": {dek_id: KEYS[dek_id].hex() for dek_id in held},
        "nodes": {
            ROOT: {"id": ROOT, "parent_ref": None},
            TEAM: {"id": TEAM, "parent_ref": ROOT},
            SUB: {"id": SUB, "parent_ref": TEAM},
            ME: {"id": ME, "parent_ref": TEAM, "personal": True, "dekId": PERSONAL_DEK},
        },
        "entries": {},
        "syncObjects": {obj["id"]: obj for obj in sync_objects},
    }


def _js(script, state):
    return _run(FUNCTIONS, CONSTANTS + script, state)


def test_a_subfolder_key_relabelled_tier2_is_still_the_subfolders_key():
    state = _state([_dek(TEAM_DEK, TEAM, "folder"), _dek(SUB_DEK, SUB, "tier2")],
                   [TEAM_DEK, SUB_DEK])
    assert _js(f"nearestFolderDekId('{SUB}')", state) == SUB_DEK


def test_a_personal_key_relabelled_folder_is_not_a_retired_folder_key():
    state = _state([_dek(TEAM_DEK, TEAM, "folder"), _dek(PERSONAL_DEK, None, "folder")],
                   [TEAM_DEK, PERSONAL_DEK])
    assert _js(
        f"({{retired: [...retiredFolderDekIds()], next: finalDekSuccessor('{PERSONAL_DEK}')}})",
        state,
    ) == {"retired": [], "next": None}


def test_a_newer_key_without_an_archive_retires_nothing():
    state = _state([_dek(TEAM_DEK, TEAM, "folder"), _dek(NEW_DEK, TEAM, "folder")],
                   [TEAM_DEK, NEW_DEK])
    assert _js("[...retiredFolderDekIds()]", state) == []


def test_the_archive_decides_which_key_replaced_which():
    """The retired key has the newer ULID; the archive still names its successor."""
    objects = [_dek(RETIRED_DEK, TEAM, "folder"), _dek(NEW_DEK, TEAM, "folder"),
               _archive(RETIRED_DEK, NEW_DEK)]
    state = _state(objects, [RETIRED_DEK, NEW_DEK])
    assert _js(
        f"({{retired: [...retiredFolderDekIds()], next: finalDekSuccessor('{RETIRED_DEK}'), "
        f"current: nearestFolderDekId('{TEAM}')}})",
        state,
    ) == {"retired": [RETIRED_DEK], "next": NEW_DEK, "current": NEW_DEK}


def test_an_archive_under_another_key_proves_nothing():
    """An archive whose header names another key than its parent_ref."""
    archive = _archive(RETIRED_DEK, NEW_DEK)
    archive["parent_ref"] = TEAM_DEK
    objects = [_dek(TEAM_DEK, TEAM, "folder"), _dek(RETIRED_DEK, TEAM, "folder"),
               _dek(NEW_DEK, TEAM, "folder"), archive]
    state = _state(objects, [TEAM_DEK, RETIRED_DEK, NEW_DEK])
    assert _js("[...retiredFolderDekIds()]", state) == []
