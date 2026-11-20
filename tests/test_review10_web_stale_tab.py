"""Review 8595ec1 (R10-E, goal #375), #5: a stale web tab after a password change.

Tab A, open since before the password changed (in tab B of the same browser,
or a login there that took a change from another device), saved an edit and
sealed the whole offline queue under the OLD KEK. The keypair cache already
opened with the new password, so the next login set nothing aside and failed
on "Invalid encrypted dirty state" for good; the old password was "wrong".
Only wiping the site data helped, and the unsent edit went with it.

Now the stale tab sets its queue aside (the old password restores it) and
locks; a queue no KEK of the session opens is set aside at login and pull, not
an error, and is never overwritten; a tab that caches a new keypair tells the
others (BroadcastChannel), and those with the old KEK lock at once.
"""

from __future__ import annotations

from tests.test_review_web import APP, _function, _run, pytestmark  # noqa: F401
from tests.test_web_old_kek_records import FAKE_IDB, FUNCTIONS as OLD_KEK_FUNCTIONS

NEW = ["webKekIsCurrent", "sealWebDirtyState", "webDirtyStateOpens", "onWebKeypairChanged"]
# On 8595ec1 the new helpers do not exist: the repro runs the old save.
FUNCTIONS = list(dict.fromkeys(OLD_KEK_FUNCTIONS + ["loadFromIndexedDB", "listSetAsideRecords"] + [
    name for name in NEW if f"function {name}(" in APP
]))

TABS = FAKE_IDB + """
  // The keypair cache opens with the KEK it was sealed under (stand-in wrap).
  decryptLoginKeypair = (envelope, kek) => {
    if (bytesToHex(envelope) !== bytesToHex(kek)) throw new Error('wrong key');
    return { keypairBytes: new Uint8Array(96) };
  };
  let ended = null;
  endSessionWithMessage = key => { ended = key; };
  t = key => key;
  const cacheUnder = kek => records.set('keypair', { id: 'keypair', user_id: 'ME', encrypted_keypair: bytesToHex(kek) });
  const stale = () => [...records.keys()].filter(id => id.startsWith('stale_kek:'));
"""


def test_a_stale_tab_sets_its_queue_aside_and_the_next_login_works():
    script = TABS + """
      cacheUnder(newKek);  // tab B changed the password
      state.kek = oldKek;  // tab A still has the old one
      state.kdf = { argon2_salt: 'aa'.repeat(16), argon2_params: { m: 1 } };
      let saveError = null;
      try { await saveWebDirtyState({ OBJ: { id: 'OBJ' } }, {}, sodium); } catch (e) { saveError = e.message; }

      state.kek = newKek;  // the next login, with the new password
      let loaded = null, loadError = null;
      try { loaded = await loadWebDirtyState(sodium); } catch (e) { loadError = e.message; }
      const aside = stale();
      return {
        saveError, ended, loaded, loadError,
        aside: aside.map(id => id.split(':').slice(2).join(':')),
        kdf: aside.length ? records.get(aside[0]).kdf : null,
        changes: (await listSetAsideRecords()).changes.length,
      };
    """
    result = _run(FUNCTIONS, f"(async () => {{ {script} }})()")
    assert result["loadError"] is None, result["loadError"]  # 8595ec1: Invalid encrypted dirty state
    assert result["loaded"] == {"objects": {}, "conflicts": {}, "ops": [], "sent": {}}
    assert result["saveError"] == "sync.stale_tab" and result["ended"] == "sync.stale_tab"
    assert result["aside"] == ["dirty_state:ME"] and result["changes"] == 1
    # The previous password's salt and params: the banner restores the edit with it.
    assert result["kdf"] == {"argon2_salt": "aa" * 16, "argon2_params": {"m": 1}}


def test_a_queue_the_kek_does_not_open_is_set_aside_not_overwritten():
    script = TABS + """
      cacheUnder(oldKek);
      state.kek = oldKek;  // a stale tab of an older release sealed this
      await idbKeysRequest('readwrite', store => store.put({ id: 'dirty_state:ME',
        ...(() => { const n = sodium.randombytes_buf(24);
                    const c = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                      new TextEncoder().encode(JSON.stringify({ objects: { OLD: { id: 'OLD' } }, conflicts: {} })),
                      webDirtyStateAAD(), null, n, oldKek);
                    return { encrypted_dirty_state: bytesToHex(new Uint8Array([...n, ...c])), kdf: null }; })() }));
      cacheUnder(newKek);
      state.kek = newKek;  // this tab has the new KEK and saves its own queue
      await saveWebDirtyState({ NEW: { id: 'NEW' } }, {}, sodium);
      return { ended, live: Object.keys((await loadWebDirtyState(sodium)).objects), aside: stale().length };
    """
    result = _run(FUNCTIONS, f"(async () => {{ {script} }})()")
    assert result == {"ended": None, "live": ["NEW"], "aside": 1}  # 8595ec1: aside 0, OLD lost


def test_a_tab_with_the_old_kek_locks_when_another_caches_a_new_keypair():
    script = TABS + """
      cacheUnder(newKek);
      state.kek = newKek;
      await onWebKeypairChanged({ userId: 'ME' }, sodium);
      const current = ended;
      await onWebKeypairChanged({ userId: 'SOMEONE' }, sodium);
      state.kek = oldKek;
      await onWebKeypairChanged({ userId: 'SOMEONE' }, sodium);
      const otherAccount = ended;
      await onWebKeypairChanged({ userId: 'ME' }, sodium);
      return { current, otherAccount, stale: ended };
    """
    result = _run(FUNCTIONS, f"(async () => {{ {script} }})()")
    assert result == {"current": None, "otherAccount": None, "stale": "sync.stale_tab"}
    save = _function("saveToIndexedDB")
    assert "new BroadcastChannel('sezam-keypair')" in save and "postMessage({ userId: data.user_id })" in save
    assert "onWebKeypairChanged(event.data, _sodium)" in APP


def test_login_and_pull_set_aside_what_the_kek_does_not_open():
    login = _function("handleLogin")
    set_aside = login.index("await setAsideRecordsOfOldKek(_sodium, keyChanged);")
    assert set_aside < login.index("if (keyChanged) {") < login.index("await pullAndBuildTree();")
    # Review 8bc70f7 H4: the pull loads the queue through the loader forget-pin shares.
    pull = _function("pullAndBuildTreeLocked")
    assert "await loadWebLocalStateLocked(session, _sodium);" in pull
    assert "await setAsideRecordsOfOldKek(_sodium, false);" in _function("loadWebLocalStateLocked")
