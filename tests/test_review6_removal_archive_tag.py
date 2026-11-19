"""Capability review run 140: a removal re-key names the member it removed.

Grant again decided by time whether a re-key had seen a grant, and dropped a
grant made before a re-key that never saw it (the reversed SM62 order, test
in test_grant_under_rekeyed_key_sm62.py). A re-key that removed a member now
tags its archive id with that member, keyed by the new DEK; the id is the
archive's AEAD associated data, so the server can neither forge nor strip it.
Desktop and web compute the same tag.
"""

from __future__ import annotations

from ulid import ULID

from sezam.vault.dek import archive_removed, removal_archive_id
from tests.test_review_web import _run, pytestmark  # noqa: F401

NEW_DEK_ID = "01JD3000000000000000000000"
NEW_DEK = bytes(range(32))
BOB = "01JB0000000000000000000000"
CAROL = "01JC0000000000000000000000"


def test_the_tag_names_only_the_removed_member():
    archive_id = removal_archive_id(NEW_DEK_ID, NEW_DEK, BOB)
    assert str(ULID.from_str(archive_id)) == archive_id
    assert archive_removed(archive_id, NEW_DEK_ID, NEW_DEK, BOB) is True
    assert archive_removed(archive_id, NEW_DEK_ID, NEW_DEK, CAROL) is False


def test_an_untagged_or_foreign_key_archive_is_unknown():
    plain = str(ULID())
    assert archive_removed(plain, NEW_DEK_ID, NEW_DEK, BOB) is None
    # Without the new DEK the tag cannot be made: under another key it is no tag.
    archive_id = removal_archive_id(NEW_DEK_ID, NEW_DEK, BOB)
    assert archive_removed(archive_id, NEW_DEK_ID, bytes(32), BOB) is None


def test_web_and_desktop_tag_the_same_way():
    web_id = _run(
        ["generateULID", "rekeyArchiveChars", "removalArchiveId"],
        f"removalArchiveId('{NEW_DEK_ID}', hex('{NEW_DEK.hex()}'), '{BOB}', sodium)",
    )
    assert archive_removed(web_id, NEW_DEK_ID, NEW_DEK, BOB) is True
    assert archive_removed(web_id, NEW_DEK_ID, NEW_DEK, CAROL) is False
    assert web_id[10:] == removal_archive_id(NEW_DEK_ID, NEW_DEK, BOB)[10:]
