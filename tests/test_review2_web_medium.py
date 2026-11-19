"""Review 2052248 R-H (web medium findings), run in node."""

from __future__ import annotations

import json

from tests.test_review2_web_crit import _class, _run
from tests.test_review_web import _function, pytestmark  # noqa: F401

ME = "01ME000000000000000000000A"
ADMIN = "01AD000000000000000000000A"
FOLDER = "01F0000000000000000000000A"
FOLDER_DEK = "01D0000000000000000000000A"
TIER2_DEK = "01Z0000000000000000000000A"  # newer ULID than FOLDER_DEK
KEY_HELPERS = _function("keyAuthors") + _function("folderTreeOwner") + _function("ulidTimeMs")


# ── a tier-2 entry's DEK never becomes the folder DEK ──

def _folder_state(tier2_scope):
    return {
        "userId": ADMIN,
        "deks": {FOLDER_DEK: "x", TIER2_DEK: "y"},
        "nodes": {FOLDER: {"id": FOLDER, "parent_ref": None}},
        "entries": {"E": {"id": "E", "tier": 2, "dekId": TIER2_DEK, "parent_ref": FOLDER}},
        "syncObjects": {
            FOLDER_DEK: {"id": FOLDER_DEK, "object_type": "dek", "parent_ref": FOLDER, "scope": "folder",
                         "signer": ADMIN},
            # The desktop binds a tier-2 DEK to the entry's folder as well.
            TIER2_DEK: {"id": TIER2_DEK, "object_type": "dek", "parent_ref": FOLDER, "scope": tier2_scope,
                        "signer": ADMIN},
            "E": {"id": "E", "object_type": "entry", "parent_ref": FOLDER, "signer": ADMIN},
        },
    }


def test_tier2_dek_labelled_by_the_server_is_not_a_folder_dek():
    assert _run(_function("nearestFolderDekId") + _function("provenDekSuccessors") + KEY_HELPERS, f"nearestFolderDekId('{FOLDER}')",
                _folder_state("tier2")) == FOLDER_DEK


def test_tier2_dek_without_label_is_recognised_by_its_entry():
    assert _run(_function("nearestFolderDekId") + _function("provenDekSuccessors") + KEY_HELPERS, f"nearestFolderDekId('{FOLDER}')",
                _folder_state(None)) == FOLDER_DEK


# ── the root DEK cannot be redirected to someone else's DEK ──

def _select(nodes, sync_objects, kek, held):
    args = ", ".join(json.dumps(v) for v in (nodes, sync_objects))
    script = f"selectRootDekId({args}, new Set({json.dumps(kek)}), {json.dumps(held)}, '{ME}')"
    return _run(_function("selectRootDekId"), script)


def test_root_is_the_own_dek_heading_a_top_level_folder():
    nodes = [
        {"id": "N1", "parent_ref": None, "dekId": "OWNROOT", "owner_id": ME},
        {"id": "N0", "parent_ref": None, "personal": True, "dekId": "PERSONAL", "owner_id": ME},
    ]
    # A member's DEK labelled 'root' (or a legacy plaintext one) is not ours.
    sync = {"EVIL": {"id": "EVIL", "object_type": "dek", "scope": "root"}}
    assert _select(nodes, sync, ["OWNROOT", "PERSONAL"], {"OWNROOT": 1, "PERSONAL": 1, "EVIL": 1}) == "OWNROOT"


def test_root_label_counts_only_for_a_dek_our_kek_opens():
    sync = {
        "EVIL": {"id": "EVIL", "object_type": "dek", "scope": "root"},
        "AUDIT": {"id": "AUDIT", "object_type": "dek", "scope": "audit"},
    }
    # Old code: the first DEK found (here the audit DEK) became the root.
    assert _select([], sync, ["AUDIT"], {"AUDIT": 1}) is None
    sync["MINE"] = {"id": "MINE", "object_type": "dek", "scope": "root"}
    assert _select([], sync, ["AUDIT", "MINE"], {"AUDIT": 1, "MINE": 1}) == "MINE"


def test_second_admin_uses_the_shared_root_of_the_top_level_folder():
    nodes = [{"id": "N1", "parent_ref": None, "dekId": "ADMINROOT", "owner_id": ADMIN}]
    assert _select(nodes, {}, ["MYPERSONAL"], {"ADMINROOT": 1, "MYPERSONAL": 1}) == "ADMINROOT"


def test_pull_no_longer_trusts_legacy_plaintext_dek_objects():
    pull = _function("pullAndBuildTreeLocked")
    assert "meta.scope === 'root'" not in pull
    assert "selectRootDekId(" in pull


# ── a conflict can be resolved by taking the server version ──

def test_discarding_conflicted_changes_drops_them_and_pulls_the_full_snapshot():
    script = """(async () => {
      const calls = [];
      ensureSodium = async () => ({});
      saveWebDirtyState = async (objects, conflicts) => calls.push(['save', Object.keys(objects), Object.keys(conflicts)]);
      pullAndBuildTreeLocked = async () => calls.push(['pull', state.syncObjects]);
      renderWebSyncConflicts = () => calls.push(['render']);
      state.outbox = { A: { id: 'A' }, B: { id: 'B' } };
      state.syncConflicts = { A: { local_object: { id: 'A' } } };
      state.syncObjects = { A: {} };
      await discardWebConflictedChanges(['A']);
      return { calls, dirty: Object.keys(state.outbox), conflicts: Object.keys(state.syncConflicts) };
    })()"""
    result = _run(_function("discardWebConflictedChanges"), script)
    assert result == {
        "calls": [["save", ["B"], []], ["pull", None], ["render"]],
        "dirty": ["B"],
        "conflicts": [],
    }


def test_conflict_banner_offers_the_server_version():
    script = """(() => {
      const made = [];
      const node = tag => ({ tag, children: [], append(...c) { this.children.push(...c); },
        replaceChildren() { this.children = []; }, addEventListener() {}, remove() {} });
      document.getElementById = () => null;
      document.createElement = tag => { const n = node(tag); made.push(n); return n; };
      document.body = { appendChild() {} };
      t = key => key;
      oversizedQueuedObjects = () => [];
      state.syncConflicts = { A: { local_object: { id: 'A', version: 2 }, server_object: { version: 3 } } };
      renderWebSyncConflicts();
      return made[0].children.map(c => c.textContent);
    })()"""
    labels = _run(_function("renderWebSyncConflicts"), script)
    assert "sync.use_server" in labels


# ── the clipboard is cleared after pasting in another app ──

def test_clipboard_clear_refused_without_focus_is_retried_when_focus_returns():
    script = """(async () => {
      const secret = 'hunter2';
      let clip = secret, focused = false;
      const clipboard = {
        readText: async () => { if (!focused) throw new Error('Document is not focused'); return clip; },
        writeText: async v => { if (!focused) throw new Error('Document is not focused'); clip = v; },
      };
      const guard = { value: secret, focusLost: true, pendingClear: null };
      await clearClipboardIfUnchanged(secret, clipboard, guard);  // timer fires while away
      const whileAway = clip;
      focused = true;                                            // user comes back
      await retryPendingClipboardClear(guard, clipboard);
      return { whileAway, after: clip, pending: guard.pendingClear };
    })()"""
    source = _function("clearClipboardIfUnchanged") + "\n" + _function("retryPendingClipboardClear")
    assert _run(source, script) == {"whileAway": "hunter2", "after": "", "pending": None}


def test_retry_after_focus_never_clears_content_another_app_copied():
    script = """(async () => {
      let clip = 'from another app';
      const clipboard = { readText: async () => clip, writeText: async v => { clip = v; } };
      const guard = { value: 'hunter2', focusLost: true, pendingClear: 'hunter2' };
      await retryPendingClipboardClear(guard, clipboard);
      return { clip, pending: guard.pendingClear };
    })()"""
    source = _function("clearClipboardIfUnchanged") + "\n" + _function("retryPendingClipboardClear")
    assert _run(source, script) == {"clip": "from another app", "pending": None}


# ── an unfinishable recovery journal does not block the login ──

def _login_script(journal_salt: str) -> str:
    return """(async () => {
      const events = [];
      const el = () => ({ value: 'x', textContent: '', classList: { add() {}, remove() {} } });
      const elements = { 'login-error': el() };
      document.getElementById = id => elements[id] || el();
      resetSession = () => {};
      showScreen = screen => events.push('screen:' + screen);
      t = key => key;
      console.warn = () => {};
      ensureSodium = async () => ({
        memzero() {}, crypto_sign_detached: () => new Uint8Array(64),
        crypto_hash_sha256: () => new Uint8Array(32),
      });
      resumeKekRotation = async () => { throw new Error('rewrap rejected'); };
      loadKekRotationJournal = async () => ({ username: 'u', argon2_salt: '%s', recovery_store: { blob: 1 } });
      clearKekRotationJournal = async () => events.push('journal-cleared');
      apiFetch = async (url, options = {}) => {
        if (url.startsWith('/api/meta')) return { argon2_salt: 'ab' };
        if (url === '/api/auth/challenge') return { challenge: '00'.repeat(40) };
        if (url === '/api/auth/verify') {
          // The cached keypair is the account's current one (N5).
          return { token: 'T', user_id: 'U', is_admin: false, key_material_hash: '00'.repeat(32) };
        }
        // A journal from before review 688edcb #3b: the blob's epoch is the server's.
        if (url === '/api/sync?since_commit_seq=0') return { key_epoch: 2 };
        if (url === '/api/org-recovery/store') {
          events.push('recovery-stored:' + options.body.key_epoch); return {};
        }
        throw new Error('unexpected ' + url);
      };
      hexToBytes = value => hex(value);
      deriveKEK = async () => new Uint8Array(64);
      accountKdfParams = () => ({});
      loadFromIndexedDB = async () => ({ encrypted_keypair: '00', user_id: 'U' });
      decryptLoginKeypair = () => ({ keypairBytes: new Uint8Array(96), confirmedGenesis: null });
      startJwtRefreshTimer = () => {};
      pullAndBuildTree = async () => {};
      finishSetAsideWebRevocations = async () => [];
      setAsideRecordsOfOldKek = async () => false;  // review 8595ec1 #5: every login
      renderSetAsideWebChanges = async () => {};
      renderUserInfoWithFingerprint = async () => {};
      await handleLogin({ preventDefault() {} });
      return { events, error: elements['login-error'].textContent };
    })()""" % journal_salt


def _login_source() -> str:
    return "\n".join([
        _class("KeyEpochChangedError"), _class("KekRotationRefusedError"),
        _class("TofuKeyChangeError"),
        _function("handleLogin"), _function("openLoginKeypair"), _function("recoverError"),
        _function("deriveLoginKey"), _function("openLoginKeypairAnyForm"),
        _function("signInWithKeypair"), _function("signInWithLoginKeypair"),
        _function("signAuthChallenge"), _function("normalizeUsername"),
        _function("canonicalPassword"), _function("passwordForms"),
        _function("settleUnfinishedKekRotation"), _function("journalRecoveryStore"),
    ])


def test_login_goes_through_when_the_journal_cannot_be_resumed():
    # The server already serves the journal's salt: its push went through.
    assert _run(_login_source(), _login_script("AB")) == {
        "events": ["recovery-stored:2", "journal-cleared", "screen:vault-screen"],
        "error": "",
    }


def test_journal_of_a_rotation_the_server_never_got_is_kept():
    assert _run(_login_source(), _login_script("cd")) == {
        "events": ["screen:vault-screen"], "error": "",
    }
