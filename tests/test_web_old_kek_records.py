"""Lockout review #4 (web): login after the password changed on another device.

The sync checkpoint, unsent changes and re-key journals in IndexedDB were
sealed under the old KEK. After the login with the new password fetched the
keypair from the server, loadSyncCheckpoint threw "Invalid encrypted sync
checkpoint" and the login failed, on every later attempt too, until the user
wiped the site data (losing the unsent changes as well).
"""

from __future__ import annotations

from tests.test_review_web import WEB_DIRTY_SAVE, _function, _run, pytestmark  # noqa: F401

FUNCTIONS = [
    "syncCheckpointRecordId", "syncCheckpointAAD", "syncCheckpointKey", "loadSyncCheckpoint", "saveSyncCheckpoint",
    "webDirtyStateRecordId", "webDirtyStateAAD", "loadWebDirtyState", "saveWebDirtyState",
    "webRekeyJournalRecordId", "webRekeyJournalAAD", "legacyWebRekeyRecordIds", "loadLegacyWebRekeyJournal",
    "webOutboxOps", "changeWebOutboxOps", "saveWebRekeyJournal", "validWebOutboxOps", "idbKeysRequest",
    "setAsideRecordsOfOldKek", "hexToBytes", "bytesToHex",
] + WEB_DIRTY_SAVE

FAKE_IDB = """
  const records = new Map();
  const later = fn => setTimeout(fn, 0);
  const fakeDb = {
    transaction() {
      const tx = {};
      const request = result => { const req = { result }; later(() => req.onsuccess && req.onsuccess()); return req; };
      tx.objectStore = () => ({
        get: id => request(records.has(id) ? JSON.parse(JSON.stringify(records.get(id))) : undefined),
        getAllKeys: () => request([...records.keys()]),
        put: value => { records.set(value.id, JSON.parse(JSON.stringify(value))); return request(value.id); },
        delete: id => { records.delete(id); return request(undefined); },
      });
      later(() => tx.oncomplete && tx.oncomplete());
      return tx;
    },
  };
  openDB = async () => fakeDb;
  const oldKek = sodium.randombytes_buf(32);
  const newKek = sodium.randombytes_buf(32);
  state.userId = 'ME';
  state.outboxLoaded = true;  // the login's pull loaded the queue
  state.outbox = {}; state.syncConflicts = {}; state.outboxOps = [];
  // A re-key record of the version before S3 (pending_rekey:, of its own).
  const legacyRekeyRecord = (journal, kek) => {
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      new TextEncoder().encode(JSON.stringify(journal)), webRekeyJournalAAD(journal.revoked_user_id), null, nonce, kek);
    return { id: `pending_rekey:ME:${journal.revoked_user_id}`, encrypted_journal: bytesToHex(new Uint8Array([...nonce, ...sealed])) };
  };
"""


def test_records_under_the_old_kek_are_set_aside_not_deleted():
    script = FAKE_IDB + """
      state.kek = oldKek;
      await saveSyncCheckpoint({ last_sync_seq: 7, state_hash: 'a'.repeat(64), timestamp: 1 }, sodium);
      state.outbox = { OBJ: { id: 'OBJ' } };
      await saveWebRekeyJournal({ revoked_user_id: 'BOB', phase: 'prepared', objects: [] }, sodium);
      const legacy = legacyRekeyRecord({ revoked_user_id: 'CAROL', phase: 'prepared', objects: [] }, oldKek);
      records.set(legacy.id, legacy);

      state.kek = newKek;
      let failedBefore = false;
      try { await loadSyncCheckpoint(sodium); } catch { failedBefore = true; }
      const unsentSetAside = await setAsideRecordsOfOldKek(sodium);
      const ids = [...records.keys()].sort();
      return {
        failedBefore, unsentSetAside,
        live: ids.filter(id => !id.startsWith('stale_kek:')),
        stale: ids.filter(id => id.startsWith('stale_kek:')).map(id => id.split(':').slice(2).join(':')),
        checkpoint: await loadSyncCheckpoint(sodium),
        dirty: await loadWebDirtyState(sodium),
        keptCiphertext: ids.filter(id => id.startsWith('stale_kek:'))
          .every(id => records.get(id).encrypted_dirty_state || records.get(id).encrypted_journal),
        // The removal in the set-aside outbox is named without the old password.
        setAsideQueue: ids.filter(id => id.endsWith(':dirty_state:ME'))
          .map(id => [records.get(id).revocations, records.get(id).has_changes]),
      };
    """
    result = _run(FUNCTIONS, f"(async () => {{ {script} }})()")
    # SM89/SM90: the rollback checkpoint is sealed with a key of this browser,
    # so a key change elsewhere no longer drops it.
    assert result["failedBefore"] is False
    assert result["unsentSetAside"] is True
    assert result["live"] == ["sync_checkpoint:ME", "sync_checkpoint_key:ME"]
    assert sorted(result["stale"]) == ["dirty_state:ME", "pending_rekey:ME:CAROL"]
    assert result["keptCiphertext"] is True
    assert result["setAsideQueue"] == [[["BOB"], True]]
    assert result["checkpoint"]["last_sync_seq"] == 7
    assert result["dirty"] == {"objects": {}, "conflicts": {}, "ops": [], "sent": {}}


def test_records_the_current_kek_opens_stay():
    script = FAKE_IDB + """
      state.kek = newKek;
      await saveSyncCheckpoint({ last_sync_seq: 7, state_hash: 'a'.repeat(64), timestamp: 1 }, sodium);
      await saveWebDirtyState({ OBJ: { id: 'OBJ' } }, {}, sodium);
      const unsentSetAside = await setAsideRecordsOfOldKek(sodium);
      return { unsentSetAside, ids: [...records.keys()].sort(),
               seq: (await loadSyncCheckpoint(sodium)).last_sync_seq };
    """
    result = _run(FUNCTIONS, f"(async () => {{ {script} }})()")
    assert result == {"unsentSetAside": False, "seq": 7,
                      "ids": ["dirty_state:ME", "sync_checkpoint:ME", "sync_checkpoint_key:ME"]}


def test_login_sets_old_records_aside_only_after_the_server_keypair_replaced_the_cache():
    keypair = _function("openLoginKeypair")
    cache_replaced = keypair.index("kekChangedElsewhere = true;")
    server_only = keypair.index("if (!fromIndexedDB || options.localOnly) {")
    assert "throw decryptError;" in keypair[server_only:cache_replaced]
    assert server_only < cache_replaced
    login = _function("handleLogin")
    assert "const { importedBackup, kekChangedElsewhere } = opened;" in login
    # Review 8595ec1 #5: every login sets aside what its KEK does not open; the
    # server's keypair replaces the cache only after that, on a key change.
    set_aside = login.index("const unsentSetAside = await setAsideRecordsOfOldKek(_sodium, keyChanged);")
    assert login.index("const keyChanged = Boolean(kekChangedElsewhere || importedBackup);") < set_aside
    assert login.index("state.userId = authResp.user_id;") < set_aside
    assert set_aside < login.index("if (keyChanged) {") < login.index("await pullAndBuildTree();")
