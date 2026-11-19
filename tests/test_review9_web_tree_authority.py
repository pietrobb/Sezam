"""Review 1141a20 H5/H6 (web): outside team folders the log, not signatures.

H5: the AAD binds no signer, so a lying server serves the admin's own root as
a byte-identical copy signed by an account it made ('Dan'/'Eve'); the copy
opens. The web then took Dan for the owner of the whole tree, so his key for
the admin's unshared folder became the key new items there were sealed with.
H6: once the organisation has a log, the web still took admins from whoever
signed an envelope or a top-level folder and checked nothing below the first
level. Now, as on the phone (215aa1f), only log admins write outside team
folders and personal trees, and a top-level folder sealed with a key this
account's KEK opens is this account's, whoever signed the copy.
"""

from __future__ import annotations

from tests.team_log_vectors import A, B, C, D, F1, K, Log
from tests.test_team_log_web_pull import SNAPSHOT, TEAM, _run
from tests.test_review_web import pytestmark  # noqa: F401

ROWS = SNAPSHOT + """
  // Dan (not in the log) signed an envelope, which made him an admin by the
  // old rule; the server says Carol may write in OTHER (the admin's unshared
  // folder) and re-signed a root under Dan.
  put(rec('DAN_ENV', 'envelope', ids.K9, ids.D, null, { target_user_id: ids.C, access_level: 'write' }),
      rec('DAN_OUT', 'entry', ids.OTHER, ids.D, ids.K9),
      rec('CAROL_OUT', 'entry', ids.OTHER, ids.C, ids.K9),
      rec('DAN_ROOT', 'node', null, ids.D, ids.K9),
      rec('BELOW_DAN_ROOT', 'entry', 'DAN_ROOT', ids.D, ids.K9),
      rec('ADMIN_OUT', 'entry', ids.OTHER, ids.A, ids.K9),
      rec('OWN', 'dek', null, ids.C, null),
      rec('CAROL_HOME', 'node', ids.ROOT, ids.C, 'OWN'),       // Carol's own tree stays hers
      rec('CAROL_HOME_ITEM', 'entry', 'CAROL_HOME', ids.C, 'OWN'),
      rec('CAROL_HOME_SUB', 'node', 'CAROL_HOME', ids.C, 'OWN'),
      rec('CAROL_DEEP', 'entry', 'CAROL_HOME_SUB', ids.C, 'OWN'),
      rec('SUB', 'node', ids.OTHER, ids.A, ids.K9),
      rec('DAN_DEEP', 'entry', 'SUB', ids.D, ids.K9));
"""


def test_outside_team_folders_the_log_names_the_admin():
    result = _run(ROWS + """
      return {
        logged: [...unauthorizedWrites(objects, ids.B, team, null)].sort(),
        before: [...unauthorizedWrites(objects, ids.B)].sort(),
        handover: [...unauthorizedWrites(objects, ids.B, team, null, new Set([ids.A, ids.D]))].sort(),
      };
    """, TEAM)
    assert result["logged"] == sorted(["DAN_OUT", "CAROL_OUT", "DAN_ROOT", "BELOW_DAN_ROOT", "DAN_DEEP"])
    assert result["before"] == [], "before the log: the old rules"
    # An account the log made admin keeps what it wrote (a handover).
    assert result["handover"] == ["CAROL_OUT"]


def test_log_admins_are_every_admin_the_log_made_still_active():
    def handed_over():
        return Log().genesis().member(B).member(C).key(F1, 0, K[1], None) \
            .access(F1, B, "write").access(F1, C, "read") \
            .member(D, "admin").add("member.role", D, {"user_id": A.uid, "role": "member"})
    handover = handed_over()
    removed = handed_over().remove(A, by=D)
    result = _run(f"""
      const admins = records => [...webLogAdmins({{ records, team: teamOf(records) }})].sort();
      return {{ basic: admins(RECORDS.slice(0, {len(TEAM.records)})), handover: admins(RECORDS),
               removed: admins(SERVED) }};
    """, handover, served=removed)
    assert result["basic"] == [A.uid]
    assert result["handover"] == sorted([A.uid, D.uid]), "the former admin is still an active member"
    assert result["removed"] == [D.uid]


KEYS = """
  const dek = () => new Uint8Array(32).fill(7);
  const ADMIN_KEY = '01JD0000000000000000000002', DAN_KEY = '01JD0000000000000000000003';
  const choose = ({ viewer, rootSigner, logged }) => {
    state.userId = viewer;
    state.syncObjects = Object.fromEntries([
      rec(ids.ROOT, 'node', null, rootSigner, ids.K9),
      rec(ids.OTHER, 'node', ids.ROOT, ids.A, ids.K9),
      rec(ADMIN_KEY, 'dek', ids.OTHER, ids.A, null),
      rec(DAN_KEY, 'dek', ids.OTHER, ids.D, null),
    ].map(o => [o.id, o]));
    state.nodes = { [ids.ROOT]: { id: ids.ROOT, parent_ref: null, dekId: ids.K9 },
                    [ids.OTHER]: { id: ids.OTHER, parent_ref: ids.ROOT, dekId: ids.K9 } };
    state.entries = {};
    state.deks = { [ADMIN_KEY]: dek(), [DAN_KEY]: dek() };
    state.kekDekIds = viewer === ids.A ? [ids.K9] : [];
    state.teamLog = logged ? { records: RECORDS, team: teamOf(RECORDS) } : null;
    return nearestFolderDekId(ids.OTHER);
  };
"""


def test_a_root_re_signed_under_another_account_names_no_key_for_the_admins_folder():
    result = _run(KEYS + """
      return {
        adminNoLog: choose({ viewer: ids.A, rootSigner: ids.D, logged: false }),
        adminLog: choose({ viewer: ids.A, rootSigner: ids.D, logged: true }),
        memberLog: choose({ viewer: ids.B, rootSigner: ids.D, logged: true }),
        honest: choose({ viewer: ids.B, rootSigner: ids.A, logged: true }),
      };
    """, TEAM)
    assert result == {
        "adminNoLog": "01JD0000000000000000000002",   # the root opens under this admin's KEK
        "adminLog": "01JD0000000000000000000002",
        "memberLog": None,                            # Dan is no log admin: no owner, no key
        "honest": "01JD0000000000000000000002",       # Dan's key never counts
    }
