"""Goal #443 (review e443cbc R15, INV-3) on the web: a retired key vouches
only for what a voucher list names: of the account's current key, of the
session's own account (its desktop or phone holds the versions) or of a team
admin.

The web kept the bound of a retired key (``retired_seq``) only per session, so
every sign-in was a device that had not seen one: a server holding a leaked
retired key served a high bound and the object it signed with that key.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.test_archived_key_bound_v4 import _bob_desktop, _forge_envelope, _rotated_team
from tests.test_cross_client_password_change import _web_login
from tests.test_grant_folder_access import _readable_passwords, team  # noqa: F401
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401
from tests.test_review_web import _run, pytestmark  # noqa: F401

VECTORS = json.loads(
    (Path(__file__).resolve().parent / "vectors" / "key_vouchers.json").read_text(encoding="utf-8"))
FUNCTIONS = ["keyVoucherKey", "canonicalKeyVoucherEntries", "keyVoucherMessage", "idBytes26", "vouchedEntries", "hexToBytes"]


def test_web_reproduces_the_key_voucher_vectors():
    result = _run(FUNCTIONS, f"""(() => {{
        const v = {json.dumps(VECTORS)};
        const sodium = globalThis.sodium;
        const messages = v.messages.map(m => bytesToHex(keyVoucherMessage(m.user_id, hex(m.signing_pk), m.entries)));
        const malformed = v.malformed_entries.map(e => {{
            try {{ keyVoucherMessage(v.user_id, hex(v.current_signing_pk), [e]); return false; }}
            catch {{ return true; }}
        }});
        const cases = v.cases.map(c => vouchedEntries(v.user_id, hex(v.current_signing_pk), c.lists, sodium)
            .has(keyVoucherKey(...c.entry)));
        return {{messages, malformed, cases}};
    }})()""")
    assert result["messages"] == [m["message_hex"] for m in VECTORS["messages"]]
    assert all(result["malformed"])
    assert result["cases"] == [c["vouched"] for c in VECTORS["cases"]], [c["name"] for c in VECTORS["cases"]]


def test_a_web_session_refuses_what_a_leaked_retired_key_signs_under_any_bound(
    team, monkeypatch  # noqa: F811
):
    url, db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk = _rotated_team(team, monkeypatch)
    honest = _web_login(url, "bob", PASSWORD, {})
    assert honest["error"] is None, honest
    assert _readable_passwords(honest) == {"vpn": "ops-pw"}  # the old key's entry, vouched by the rotation

    [archive] = db._storage["user_key_archives"]
    archive["retired_seq"] = 10**9
    forged = _forge_envelope(db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk)
    member = _web_login(url, "bob", PASSWORD, {})
    assert member["error"] is not None and forged in str(member["error"]), member
    assert _readable_passwords(member) == {}


def test_a_web_session_reads_what_an_inactive_admin_s_retired_key_signed_from_its_desktop_s_list(
    team, monkeypatch, tmp_path  # noqa: F811
):
    """Capability review run 480: the admin rotated with a client from before
    #443 and never syncs again, so no list of its key exists. Bob's desktop
    holds the folder and vouches for it; every web session of Bob reads it."""
    url, db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk = _rotated_team(team, monkeypatch)
    bob, client = _bob_desktop(tmp_path, url)
    try:
        client.pull()
        client.push()
        db._storage["key_vouchers"] = []
        client.pull()
    finally:
        bob.lock()
    assert {v["user_id"] for v in db._storage["key_vouchers"]} == {bob_id}
    member = _web_login(url, "bob", PASSWORD, {})
    assert member["error"] is None, member
    assert _readable_passwords(member) == {"vpn": "ops-pw"}
    forged = _forge_envelope(db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk)
    member = _web_login(url, "bob", PASSWORD, {})
    assert member["error"] is not None and forged in str(member["error"]), member
