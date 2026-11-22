"""Review e443cbc (R15-M web+mobile, goal #439; INV-3, capability run 458):
web and mobile took the server's unsigned VerifyResponse.is_admin as the admin
flag. The web's state.isAdmin let canEditObject open another's item, the
revocation re-key (buildWebRekeyBatch) and the Shamir setup start; the phone's
sezam_is_admin (kept for offline unlock too) did the same in VaultEntry.canEdit.

A server that calls a member admin made them one in the client; one that calls
the admin a member took their role away. Once a team log is known, admin is who
the verified log says (as on the desktop, which never reads is_admin); a
refused log makes nobody admin; only a vault with no log at all keeps the
server's role (the server authorizes that vault's admin calls itself, S6).
The phone side: mobile/test/r15_admin_from_log_test.dart.
"""
from __future__ import annotations

import json
from pathlib import Path

from tests.test_review_web import APP, _function, _run_source, pytestmark  # noqa: F401

ROOT = Path(__file__).parents[1]
TEAMLOG_JS = (ROOT / "web" / "static" / "js" / "teamlog.js").read_text(encoding="utf-8")
BASIC = next(s for s in json.loads((ROOT / "tests/vectors/team_log.json").read_text(encoding="utf-8"))["scenarios"]
             if s["name"] == "basic")
ADMIN, MEMBER = "01JM0000000000000000000001", "01JM0000000000000000000002"
GATED = ("canEditObject", "buildWebRekeyBatch", "openShamirSetupModal")


def _run(script: str):
    names = ["folderAccessLevelForObject", "canEditObject", "buildWebRekeyBatch", "openShamirSetupModal",
             "webPinnedTeamGenesis"]
    if "function webIsAdmin(" in APP:
        names.append("webIsAdmin")
    helpers = TEAMLOG_JS + "\n" + "\n".join(_function(n) for n in names)
    prelude = f"""
      const TL = globalThis.SezamTeamLog;
      const RECORDS = {json.dumps(BASIC["records"])};
      const log = {{ records: RECORDS, team: TL.replay(RECORDS, sodium) }};
      t = key => key;
      let alerted = null;
      alert = message => {{ alerted = message; }};
      apiFetch = async () => {{ throw new Error('went on as admin'); }};
      document.getElementById = () => null;
      const theirs = {{ id: 'item', owner_id: 'someone-else', write_policy: 'private', parent_ref: 'folder' }};
      const as = (userId, serverSaysAdmin, teamLog, refusal = null) => {{
        state.userId = userId; state.isAdmin = serverSaysAdmin; state.teamLog = teamLog;
        state.teamLogRefusal = refusal; state.confirmedTeamGenesis = null; state.syncCheckpoint = null;
        state.syncObjects = {{}}; state.kek = new Uint8Array(32);
        state.keypair = {{ encryptionSk: new Uint8Array(32) }};
      }};
      const judge = async () => {{
        let rekey;
        try {{ await buildWebRekeyBatch('01JM0000000000000000000003', sodium); rekey = 'went on'; }}
        catch (err) {{ rekey = err.message.includes('admin snapshot') ? 'refused' : 'went on'; }}
        alerted = null;
        try {{ await openShamirSetupModal(); }} catch (_) {{ /* went on to build the modal */ }}
        return {{ edit: canEditObject(theirs), rekey, shamir: alerted === 'recovery.admin_required' ? 'refused' : 'went on' }};
      }};
    """
    return _run_source(helpers, "(async () => {" + prelude + script + "\n})()")


ADMIN_HERE = {"edit": True, "rekey": "went on", "shamir": "went on"}
NOT_ADMIN = {"edit": False, "rekey": "refused", "shamir": "refused"}


def test_with_a_team_log_the_web_takes_admin_from_the_log_never_from_the_server():
    result = _run(f"""
        const out = {{}};
        as({json.dumps(MEMBER)}, true, log); out.member_the_server_calls_admin = await judge();
        as({json.dumps(ADMIN)}, false, log); out.admin_the_server_calls_member = await judge();
        as({json.dumps(ADMIN)}, true, null, {{ teamLogCause: 'unreachable' }}); out.refused_log = await judge();
        // Pinned, but no copy held this session (a sign-in before its pull).
        as({json.dumps(ADMIN)}, true, null); state.confirmedTeamGenesis = log.team.genesisHash;
        out.pinned_no_copy = await judge();
        as('solo', true, null); out.no_log_server_admin = await judge();
        as('solo', false, null); out.no_log_server_member = await judge();
        return out;
    """)
    assert result == {
        "member_the_server_calls_admin": NOT_ADMIN,
        "admin_the_server_calls_member": ADMIN_HERE,
        "refused_log": NOT_ADMIN,
        "pinned_no_copy": NOT_ADMIN,
        "no_log_server_admin": ADMIN_HERE,
        "no_log_server_member": NOT_ADMIN,
    }


def test_no_admin_decision_reads_the_servers_flag_directly():
    for name in GATED:
        assert "state.isAdmin" not in _function(name), name
        assert "webIsAdmin()" in _function(name), name
