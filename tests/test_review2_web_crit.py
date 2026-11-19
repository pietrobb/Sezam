"""Review 2052248 R-D (web critical findings 7 and 8), run in node."""

from __future__ import annotations


from tests.test_review_web import APP, _function, _run_source, pytestmark  # noqa: F401

ME = "01ME000000000000000000000A"
ADMIN = "01AD000000000000000000000A"


def _class(name: str) -> str:
    start = APP.index(f"class {name} ")
    depth = 0
    for index in range(APP.index("{", start), len(APP)):
        depth += {"{": 1, "}": -1}.get(APP[index], 0)
        if depth == 0:
            return APP[start:index + 1]
    raise AssertionError(name)


def _run(source: str, script: str, state: dict | None = None):
    return _run_source(source, script, state)


# ── 7: a rejected TOFU key change keeps its "accept new key" dialog ──

def _tofu() -> str:
    return _class("TofuKeyChangeError") + "\n" + _class("KeyEpochChangedError") + "\n" + _class(
        "KekRotationRefusedError"
    ) + "\n" + "\n".join(
        _function(name)
        for name in ("tofuKeyChange", "hexToBytes", "getUserSigningPks", "handleLogin", "normalizeUsername")
    )


def test_changed_colleague_key_is_a_typed_error_not_a_silent_null():
    script = """(async () => {
      const shown = [];
      showMITMWarning = (...args) => shown.push(args);
      apiFetch = async () => ({ signing_pk: 'aa'.repeat(32), encryption_pk: 'bb'.repeat(32) });
      checkKnownKey = async () => 'changed';
      console.warn = () => {};
      state.userKeys = {}; state.userId = 'ME';
      let error = null;
      try { await getUserSigningPks('COLLEAGUE'); } catch (e) { error = e; }
      return {
        typed: error instanceof TofuKeyChangeError,
        userId: error && error.userId,
        signing: error && error.signingPkHex,
        shown: shown.length,
        cached: 'COLLEAGUE' in state.userKeys,
      };
    })()"""
    result = _run(_tofu(), script)
    assert result == {
        "typed": True, "userId": "COLLEAGUE", "signing": "aa" * 32,
        "shown": 1, "cached": False,
    }


def test_failed_login_shows_the_key_change_dialog_after_wiping_the_session():
    script = """(async () => {
      const events = [];
      const el = () => ({ value: 'x', textContent: '', classList: { add() {}, remove() {} } });
      const elements = { username: el(), password: el(), 'login-spinner': el(), 'login-error': el() };
      document.getElementById = id => elements[id] || el();
      resetSession = () => events.push('reset');
      showScreen = () => {};
      t = key => key;
      showMITMWarning = (name, id, sig, enc) => events.push(`dialog:${id}:${sig}:${enc}`);
      ensureSodium = async () => ({ memzero() {} });
      resumeKekRotation = async () => {
        throw new TofuKeyChangeError('bob', 'BOB', 'aa', 'bb');
      };
      await handleLogin({ preventDefault() {} });
      return { events, message: elements['login-error'].textContent };
    })()"""
    result = _run(_tofu(), script)
    # The dialog comes AFTER the last reset, so the user can accept the key.
    assert result == {
        "events": ["reset", "reset", "dialog:BOB:aa:bb"],
        "message": "error.tofu_key_changed",
    }


# ── 8: a team member's own item in a shared folder under unreadable folders ──

def _nodes(root_owner: str) -> dict:
    return {
        "userId": ME,
        "deks": {"PDEK": "x"},
        "nodes": {
            "ROOT": {"id": "ROOT", "parent_ref": None, "_undecryptable": True, "owner_id": root_owner},
            "TEAM": {"id": "TEAM", "parent_ref": "ROOT", "owner_id": ADMIN},
            "MINE": {"id": "MINE", "parent_ref": "ROOT", "personal": True, "dekId": "PDEK"},
            "SUB": {"id": "SUB", "parent_ref": "MINE", "owner_id": ME, "dekId": "PDEK"},
        },
    }




def test_unreadable_foreign_ancestor_is_skipped():
    script = """({
      team: resolveInheritedPersonalDekId('TEAM') ?? null,
      personal: resolveInheritedPersonalDekId('SUB'),
    })"""
    assert _run(_function("resolveInheritedPersonalDekId"), script, _nodes(ADMIN)) == {"team": None, "personal": "PDEK"}


def test_own_unreadable_ancestor_still_fails_closed():
    script = """(() => {
      try { resolveInheritedPersonalDekId('TEAM'); return 'resolved'; }
      catch (e) { return e.message; }
    })()"""
    assert _run(_function("resolveInheritedPersonalDekId"), script, _nodes(ME)) == "Parent folder is unavailable."
    unknown = _nodes(ADMIN)
    del unknown["nodes"]["ROOT"]["owner_id"]
    assert _run(_function("resolveInheritedPersonalDekId"), script, unknown) == "Parent folder is unavailable."


def test_member_login_migration_passes_a_shared_folder():
    source = _function("resolveInheritedPersonalDekId") + "\n" + _function("migrateLegacyPersonalDescendants")
    state = _nodes(ADMIN)
    state["rootDekId"] = None
    state["allNodes"] = list(state["nodes"].values())
    state["allEntries"] = [
        {"id": "MYENTRY", "parent_ref": "TEAM", "owner_id": ME, "dekId": "TEAMDEK"},
    ]
    script = """(async () => {
      let pushed = 0;
      pushVaultObjectLocked = async () => { pushed++; };
      return { migrated: await migrateLegacyPersonalDescendants(), pushed };
    })()"""
    assert _run(source, script, state) == {"migrated": False, "pushed": 0}


def test_pull_keeps_the_owner_of_an_unreadable_node():
    pull = _function("pullAndBuildTreeLocked")
    line = next(x for x in pull.splitlines() if "_undecryptable: true, parent_ref" in x
                and "osobne" in x)
    assert "owner_id: obj.owner_id" in line
