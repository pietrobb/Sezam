"""S3 (docs/SYNC_SINGLE_SOURCE.md 3.8): the web's re-key is an outbox operation.

Capability run 359: an unfinished revocation waited in a `pending_rekey:`
record of its own beside the outbox (state.outbox), Retry hard-coded the
order between the two, and it cleaned up re-key objects queued in both. Now
the re-key is an operation of the one outbox record, in queue order, and a
record of the version before is moved into it.
"""

from __future__ import annotations

from tests.test_review_web import _function, _run, pytestmark  # noqa: F401
from tests.test_web_old_kek_records import FAKE_IDB
from tests.test_web_set_aside_records_272 import FAKE_NET, JOURNAL

FUNCTIONS = JOURNAL + [
    "retryAllWebDirtyObjects", "adoptLegacyWebRekeyJournals", "legacyWebRekeyRecordIds",
    "loadLegacyWebRekeyJournal", "webRekeyJournalRecordId", "webRekeyJournalAAD",
]

# Each single write leaves the queue when the server takes it.
SINGLE_PUSH = """
  globalThis.oversizedQueuedObjects = () => [];
  resealUnderFolderSuccessor = async object => object;
  pushEncryptedVaultObject = async object => {
    calls.push(`push ${object.id}`);
    const outbox = { ...state.outbox };
    delete outbox[object.id];
    await saveWebDirtyState(outbox, state.syncConflicts, sodium);
    state.outbox = outbox;
  };
  // What the page's first pull after a reload does with the stored queue.
  const reload = async () => {
    state.outbox = {}; state.syncConflicts = {}; state.outboxOps = []; state.outboxLoaded = false;
    const stored = await loadWebDirtyState(sodium);
    state.outbox = stored.objects; state.syncConflicts = stored.conflicts; state.outboxOps = stored.ops;
    state.outboxLoaded = true;
    await adoptLegacyWebRekeyJournals(sodium);
  };
"""


def test_an_unfinished_revocation_and_a_later_edit_wait_in_one_queue_in_order():
    script = FAKE_IDB + FAKE_NET + SINGLE_PUSH + """
      state.kek = newKek;
      // The admin removes Bob; the network is down after the batch is built.
      const online = apiFetch;
      apiFetch = async () => { throw new Error('Failed to fetch'); };
      let first = null;
      try { await finishWebRevocation('BOB', sodium); } catch (err) { first = err.message; }
      apiFetch = online;
      // Then edits an entry of the folder Bob had.
      const outbox = { ...state.outbox, U1: { id: 'U1', payload: 'edit' } };
      await saveWebDirtyState(outbox, state.syncConflicts, sodium);
      state.outbox = outbox;

      await reload();
      const stored = [...records.keys()].sort();
      const queued = { ops: state.outboxOps.map(op => [op.kind, op.revoked_user_id, op.phase]),
                       writes: Object.keys(state.outbox) };
      calls.length = 0;
      await retryAllWebDirtyObjects();
      return { first, stored, queued, calls, after: [...records.keys()] };
    """
    result = _run(FUNCTIONS, f"(async () => {{ {script} }})()")
    assert result["first"] == "Failed to fetch"
    # One record holds both: no re-key record beside the outbox.
    assert result["stored"] == ["dirty_state:ME"]
    assert result["queued"] == {"ops": [["rekey", "BOB", "prepared"]], "writes": ["U1"]}
    # The re-key goes first, as its one atomic batch, and Bob is removed; the
    # edit after it (resealed under the folder's new key) goes alone.
    assert result["calls"] == ["sync NEW1-BOB", "DELETE /api/users/BOB", "push U1", "pull"]
    assert result["after"] == []


def test_a_re_key_record_of_the_version_before_moves_into_the_queue():
    script = FAKE_IDB + FAKE_NET + SINGLE_PUSH + """
      state.kek = newKek;
      const legacy = legacyRekeyRecord(
        { revoked_user_id: 'BOB', phase: 'prepared', objects: [{ id: 'R1', payload: 'p-r1' }] }, newKek);
      records.set(legacy.id, legacy);
      // An even older version queued R1 as a single write too; U1 is an edit.
      state.outbox = { R1: { id: 'R1', payload: 'p-r1' }, U1: { id: 'U1', payload: 'edit' } };
      await saveWebDirtyState(state.outbox, state.syncConflicts, sodium);

      await reload();
      const stored = [...records.keys()].sort();
      const queued = { ops: state.outboxOps.map(op => [op.revoked_user_id, op.objects.map(o => o.id)]),
                       writes: Object.keys(state.outbox) };
      await reload();  // moved once: a second load finds nothing to move
      return { stored, queued, again: state.outboxOps.length };
    """
    result = _run(FUNCTIONS, f"(async () => {{ {script} }})()")
    assert result["stored"] == ["dirty_state:ME"]
    assert result["queued"] == {"ops": [["BOB", ["R1"]]], "writes": ["U1"]}
    assert result["again"] == 1


def test_no_password_change_while_a_re_key_waits():
    publish = _function("publishWebTeamAnchorLocked")
    assert "(state.outboxOps || []).length" in publish
    assert publish.index("(state.outboxOps || []).length") < publish.index("throw new Error(t('team.publish_unsent'))")
