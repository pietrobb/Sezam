"""Review c02cc47 R17-L, web: webIsAdmin answered from a held team log before
it asked whether that log was refused, and trashedNode called a deleted
folder personal without asking who signed it (a personal folder is signed by
its author only, TL7).
"""

from __future__ import annotations

from tests.test_r15_admin_from_log import ADMIN, NOT_ADMIN, _run
from tests.test_review_web import _function, _run_source, pytestmark  # noqa: F401

ME, OTHER = "01ME000000000000000000000A", "01OT000000000000000000000A"


def test_a_refused_log_this_browser_still_holds_makes_nobody_admin():
    result = _run(f"""
        as({ADMIN!r}, true, log, {{ teamLogCause: 'founder_unconfirmed' }});
        return await judge();
    """)
    assert result == NOT_ADMIN


STUBS = """
function base64ToBytes() { return new Uint8Array(40); }
function isEncryptedEnvelope() { return true; }
function decryptEnvelope() { return { personal: true }; }
const BLOB_KIND = { NODE_META: 1 };
"""


def _trashed(signer: str):
    state = {
        "userId": ME, "kekDekIds": [""], "deks": {}, "sodium": True,
        "syncObjects": {"F": {"id": "F", "object_type": "node", "is_deleted": True, "version": 3,
                              "parent_ref": None, "payload": "", "owner_id": ME,
                              "signature_user_id": signer}},
    }
    return _run_source(STUBS + _function("trashedNode"), "trashedNode('F').personal", state)


def test_a_deleted_folder_is_personal_only_when_this_account_signed_it():
    assert _trashed(ME) is True
    assert _trashed(OTHER) is False
