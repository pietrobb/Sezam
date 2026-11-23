"""Review 688edcb, web #4 and M5.

#4: after a password change on another device the web set its unsent
changes and re-key journals aside under ``stale_kek:*`` and nothing read
them again: the changes were lost, and a revocation interrupted mid-way left
the member in place with access. Now the revocation is finished from the
server's state and the changes are restored with the previous password.

M5: a re-key batch the server refused (409) was pushed unchanged on every
Retry and never went through; it is rebuilt from the server's state.
"""

from __future__ import annotations

from tests.test_review_web import APP, WEB_DIRTY_SAVE, _function, _run, pytestmark  # noqa: F401
from tests.test_web_old_kek_records import FAKE_IDB

# Envelope constants as globals, where the extracted helpers look them up.
CONSTANTS = APP[
    APP.index("const ENVELOPE_ALG"):APP.index("};", APP.index("const BLOB_KIND")) + 2
].replace("const ", "globalThis.")

# S3: the re-key is an operation of the outbox record (dirty_state).
OUTBOX_OPS = [
    "webOutboxOps", "pendingWebRevocations", "loadWebRekeyJournal", "changeWebOutboxOps",
    "saveWebRekeyJournal", "clearWebRekeyJournal", "validWebOutboxOps",
    "webDirtyStateRecordId", "webDirtyStateAAD", "loadWebDirtyState", "saveWebDirtyState",
] + WEB_DIRTY_SAVE

JOURNAL = OUTBOX_OPS + [
    "idbKeysRequest", "hexToBytes", "bytesToHex",
    "pushWebRekeyBatch", "sendWebTeamRecords", "noteWebTeamRecordsSent", "prepareWebRekeyJournal", "finishWebRevocation",
    "listSetAsideRecords", "finishSetAsideWebRevocations", "dropSetAsideRevocation",
]

CHANGES = [
    "syncCheckpointRecordId", "syncCheckpointAAD", "syncCheckpointKey", "loadSyncCheckpoint", "saveSyncCheckpoint",
    "webDirtyStateRecordId", "webDirtyStateAAD", "loadWebDirtyState", "saveWebDirtyState", "validWebOutboxOps",
    "webRekeyJournalRecordId", "webRekeyJournalAAD", "legacyWebRekeyRecordIds", "loadLegacyWebRekeyJournal",
    "idbKeysRequest", "discardSetAsideWebChanges",
    "setAsideRecordsOfOldKek", "hexToBytes", "bytesToHex",
    "listSetAsideRecords", "openSetAsideWebChanges", "restoreSetAsideWebChanges",
    "passwordForms", "canonicalPassword",
    "wrapDEK", "wrapDEKWithKey", "unwrapDEK", "buildAAD", "padPlaintext", "unpadPlaintext",
    "generateULID",
] + WEB_DIRTY_SAVE

# A network that records requests: /api/sync refuses any batch with an object
# id in `refuse` (409, as the server does for an atomic conflict).
FAKE_NET = """
  const calls = [];
  const refuse = new Set();
  let built = 0;
  apiFetch = async (path, options = {}) => {
    const method = options.method || 'GET';
    if (path === '/api/sync') {
      const ids = options.body.objects.map(o => o.id);
      calls.push(`sync ${ids.join(',')}`);
      if (ids.some(id => refuse.has(id))) {
        const err = new Error('Atomic batch conflict'); err.status = 409; throw err;
      }
      return { accepted: ids.map(id => ({ id })), conflicts: [] };
    }
    calls.push(`${method} ${path}`);
    return {};
  };
  pullAndBuildTree = async () => { calls.push('pull'); };
  buildWebRekeyBatch = async revoked => {
    built += 1;
    return { objects: [{ id: `NEW${built}-${revoked}` }], folders_rekeyed: 1 };
  };
  ensureSodium = async () => sodium;
  t = key => key;
  assertSyncUnitFits = () => {};
  // One request, as postAtomicSyncBatch sends a batch this small.
  postAtomicSyncBatch = (objects, fields) => apiFetch('/api/sync', {
    method: 'POST', body: { ...fields, objects, atomic_batch: true },
  });
  confirm = () => true;  // the admin confirms a set-aside removal (review e4cd15a)
"""


def test_a_revocation_set_aside_by_a_password_change_is_finished():
    script = FAKE_IDB + FAKE_NET + """
      state.kek = oldKek;
      await saveWebRekeyJournal({ revoked_user_id: 'BOB', phase: 'prepared', objects: [{ id: 'OLD' }] }, sodium);
      // The password changed elsewhere; the login set the outbox aside.
      const sealed = records.get('dirty_state:ME');
      records.delete('dirty_state:ME');
      records.set('stale_kek:1:dirty_state:ME', { ...sealed, id: 'stale_kek:1:dirty_state:ME' });
      state.kek = newKek;
      state.outboxOps = [];

      const unfinished = await finishSetAsideWebRevocations(sodium);
      return { unfinished, calls, ids: [...records.keys()] };
    """
    result = _run(JOURNAL, f"(async () => {{ {script} }})()")
    # Rebuilt from the server's state (the old batch was sealed under the old
    # KEK and is never sent), pushed, then the member is removed.
    assert result == {
        "unfinished": [],
        "calls": ["GET /api/users", "pull", "sync NEW1-BOB", "DELETE /api/users/BOB"],
        "ids": [],
    }


def test_an_unfinished_set_aside_revocation_stays_for_the_next_login():
    script = FAKE_IDB + FAKE_NET + """
      records.set('stale_kek:1:pending_rekey:ME:BOB', { id: 'stale_kek:1:pending_rekey:ME:BOB', encrypted_journal: '00' });
      buildWebRekeyBatch = async () => { throw new Error('A complete unlocked admin snapshot is required'); };
      state.kek = newKek;
      const unfinished = await finishSetAsideWebRevocations(sodium);
      return { unfinished, ids: [...records.keys()] };
    """
    result = _run(JOURNAL, f"(async () => {{ {script} }})()")
    assert result == {"unfinished": ["BOB"], "ids": ["stale_kek:1:pending_rekey:ME:BOB"]}


def test_retry_rebuilds_a_refused_rekey_batch_instead_of_resending_it():
    functions = JOURNAL + ["retryAllWebDirtyObjects", "saveWebDirtyState", "webDirtyStateRecordId",
                           "webDirtyStateAAD"] + WEB_DIRTY_SAVE
    script = FAKE_IDB + FAKE_NET + """
      state.kek = newKek;
      state.outbox = {}; state.syncConflicts = {};
      globalThis.oversizedQueuedObjects = () => [];
      await saveWebRekeyJournal({ revoked_user_id: 'BOB', phase: 'prepared', objects: [{ id: 'OLD' }] }, sodium);
      refuse.add('OLD');  // an object in the batch changed on the server since it was built
      await retryAllWebDirtyObjects();
      return { calls, ids: [...records.keys()] };
    """
    result = _run(functions, f"(async () => {{ {script} }})()")
    assert result == {
        "calls": ["sync OLD", "pull", "sync NEW1-BOB", "DELETE /api/users/BOB", "pull"],
        "ids": [],
    }


def test_a_network_failure_keeps_the_batch_for_the_next_retry():
    script = FAKE_IDB + FAKE_NET + """
      state.kek = newKek;
      await saveWebRekeyJournal({ revoked_user_id: 'BOB', phase: 'prepared', objects: [{ id: 'OLD' }] }, sodium);
      apiFetch = async () => { throw new Error('Failed to fetch'); };
      let error = null;
      try { await finishWebRevocation('BOB', sodium); } catch (err) { error = err.message; }
      const journal = await loadWebRekeyJournal('BOB', sodium);
      return { error, built, phase: journal.phase, objects: journal.objects.map(o => o.id) };
    """
    result = _run(JOURNAL, f"(async () => {{ {script} }})()")
    assert result == {"error": "Failed to fetch", "built": 0, "phase": "prepared", "objects": ["OLD"]}


SET_ASIDE_CHANGES = FAKE_IDB + """
  bytesToBase64 = bytes => Buffer.from(bytes).toString('base64');  // no btoa in the harness
  // Argon2 stand-in: the KEK is a hash of the password form and salt.
  deriveKEK = async (password, salt) => sodium.crypto_generichash(64, `${password}:${bytesToHex(salt)}`);
  buildSignedSyncObject = async (_s, fields, bytes) => ({ ...fields, payload: bytesToBase64(bytes), resigned: true });
  t = key => key;
  const oldSalt = 'aa'.repeat(16);
  const oldKdfKek = (await deriveKEK('old-pw', hexToBytes(oldSalt))).slice(0, 32);
  state.kek = oldKdfKek;
  state.kdf = { argon2_salt: oldSalt, argon2_params: { time_cost: 3, memory_cost: 65536, parallelism: 1 } };
  const DEK_ID = '01BX5ZZKBKACTAV9WEVGEMMVRZ';
  const dek = sodium.randombytes_buf(32);
  const queued = {
    E1: { id: 'E1', object_type: 'entry', version: 2, payload: 'ZW50cnk=' },
    E2: { id: 'E2', object_type: 'entry', version: 5, payload: 'b2xk' },
    [DEK_ID]: { id: DEK_ID, object_type: 'dek', version: 1, parent_ref: 'N1',
                payload: bytesToBase64(wrapDEK(dek, DEK_ID, 1, oldKdfKek, sodium)) },
  };
  await saveWebDirtyState(queued, {}, sodium);
  // Password changed on another device: new salt, new KEK; the login sets the queue aside.
  state.kek = newKek;
  state.kdf = { argon2_salt: 'bb'.repeat(16), argon2_params: { time_cost: 3, memory_cost: 65536, parallelism: 1 } };
  await setAsideRecordsOfOldKek(sodium);
  const staleId = [...records.keys()].find(id => id.startsWith('stale_kek:'));
"""


def test_unsent_changes_set_aside_by_a_password_change_are_restored_with_the_old_password():
    script = SET_ASIDE_CHANGES + """
      state.outbox = { E2: { id: 'E2', object_type: 'entry', version: 6, payload: 'bmV3' } };
      state.syncConflicts = {};
      let wrong = null;
      try { await restoreSetAsideWebChanges(staleId, 'not-it', sodium); } catch (err) { wrong = err.message; }
      const restored = await restoreSetAsideWebChanges(staleId, 'old-pw', sodium);
      const live = await loadWebDirtyState(sodium);   // sealed under the new KEK now
      const dekObject = live.objects[DEK_ID];
      const unwrapped = unwrapDEK(base64ToBytes(dekObject.payload), newKek, DEK_ID, 1, sodium);
      return {
        wrong, restored, ids: Object.keys(live.objects).sort(),
        e1: live.objects.E1.version, e2: live.objects.E2.version,
        dekRewrapped: bytesToHex(unwrapped) === bytesToHex(dek) && dekObject.resigned === true,
        stale: [...records.keys()].filter(id => id.startsWith('stale_kek:')),
      };
    """
    result = _run(CHANGES, f"(async () => {{ {CONSTANTS}\n{script} }})()")
    assert result["wrong"] == "sync.set_aside_wrong_password"
    assert result["restored"] == 3
    assert result["ids"] == sorted(["E1", "E2", "01BX5ZZKBKACTAV9WEVGEMMVRZ"])
    assert result["e1"] == 2
    assert result["e2"] == 6  # the change made in this session wins
    assert result["dekRewrapped"] is True
    assert result["stale"] == []


def test_changes_set_aside_without_kdf_data_are_reported_not_guessed():
    script = SET_ASIDE_CHANGES + """
      const record = records.get(staleId);
      delete record.kdf;  // set aside by a version that did not keep the salt
      records.set(staleId, record);
      let error = null;
      try { await restoreSetAsideWebChanges(staleId, 'old-pw', sodium); } catch (err) { error = err.message; }
      return { error, kept: records.has(staleId) };
    """
    result = _run(CHANGES, f"(async () => {{ {CONSTANTS}\n{script} }})()")
    assert result == {"error": "sync.set_aside_unrecoverable", "kept": True}


def test_login_offers_set_aside_work_back_and_lock_clears_the_password_field():
    login = _function("handleLogin")
    finish = login.index("await finishSetAsideWebRevocations(_sodium)")
    assert login.index("await settleUnfinishedKekRotation(") < finish
    assert finish < login.index("await renderSetAsideWebChanges()") < login.index("showScreen('vault-screen')")
    assert "document.getElementById('set-aside-banner')?.remove();" in _function("clearSensitiveDom")
    assert "kdf: state.kdf || null" in _function("sealWebDirtyState")
    assert "state.kdf = null;" in _function("resetSession")
