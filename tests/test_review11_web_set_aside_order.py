"""Review 4acfdde R11 (medium): the web's set-aside changes after password
changes on other devices.

- Records were restored oldest first, and the queue's copy wins over a
  restored one, so a newer record's edit of an object lost to the older.
- One record whose password was forgotten stopped the restore of every newer
  record.
- Discard dropped every record at once.

Records are now restored newest first; one the password does not open holds
back only the older ones (which would otherwise win over it), and each record
is discarded on its own.
"""

from __future__ import annotations

from tests.test_review_web import _function, _run, pytestmark  # noqa: F401
from tests.test_web_set_aside_records_272 import CHANGES, CONSTANTS
from tests.test_web_old_kek_records import FAKE_IDB

FUNCTIONS = CHANGES + ["restoreAllSetAsideWebChanges", "setAsideStamp"]

RECORDS = FAKE_IDB + """
  bytesToBase64 = bytes => Buffer.from(bytes).toString('base64');
  deriveKEK = async (password, salt) => sodium.crypto_generichash(64, `${password}:${bytesToHex(salt)}`);
  buildSignedSyncObject = async (_s, fields, bytes) => ({ ...fields, payload: bytesToBase64(bytes) });
  t = key => key;
  const params = { time_cost: 3, memory_cost: 65536, parallelism: 1 };
  // A queue sealed under `password`, set aside at `stamp` by a password change elsewhere.
  const setAside = async (password, salt, objects, stamp) => {
    state.kek = (await deriveKEK(password, hexToBytes(salt))).slice(0, 32);
    state.kdf = { argon2_salt: salt, argon2_params: params };
    await saveWebDirtyState(objects, {}, sodium);
    state.kek = newKek;
    state.kdf = { argon2_salt: 'ff'.repeat(16), argon2_params: params };
    await setAsideRecordsOfOldKek(sodium, false);
    const id = [...records.keys()].find(k => k.startsWith('stale_kek:') && !k.startsWith('stale_kek:00'));
    const record = records.get(id);
    records.delete(id);
    const fixed = `stale_kek:00${stamp}:dirty_state:ME`;
    records.set(fixed, { ...record, id: fixed });
  };
  const entry = (id, payload) => ({ id, object_type: 'entry', version: 2, payload });
  const stale = () => [...records.keys()].filter(k => k.startsWith('stale_kek:')).sort();
  const queue = async () => {
    const live = await loadWebDirtyState(sodium);
    return Object.fromEntries(Object.values(live.objects).map(o => [o.id, o.payload]));
  };
  state.outbox = {}; state.syncConflicts = {};
"""


def _go(script: str) -> dict:
    return _run(FUNCTIONS, f"(async () => {{ {CONSTANTS}\n{RECORDS}\n{script} }})()")


def test_the_newer_set_aside_edit_of_an_object_wins():
    result = _go("""
      await setAside('pw-1', 'a1'.repeat(16), { E1: entry('E1', 'b2xkZXI=') }, 1000);
      await setAside('pw-1', 'a2'.repeat(16), { E1: entry('E1', 'bmV3ZXI=') }, 2000);
      const outcome = await restoreAllSetAsideWebChanges('pw-1', sodium);
      return { outcome, queue: await queue(), stale: stale() };
    """)
    assert result == {
        "outcome": {"restored": 2, "waiting": 0},
        "queue": {"E1": "bmV3ZXI="},  # 'newer', not 'older'
        "stale": [],
    }


def test_a_forgotten_password_holds_back_only_the_older_records():
    result = _go("""
      await setAside('pw-1', 'a1'.repeat(16), { E1: entry('E1', 'b2xkZXN0') }, 1000);
      await setAside('pw-2', 'a2'.repeat(16), { E1: entry('E1', 'bWlk') }, 2000);
      await setAside('pw-3', 'a3'.repeat(16), { E2: entry('E2', 'bmV3ZXN0') }, 3000);
      const first = await restoreAllSetAsideWebChanges('pw-3', sodium);
      const afterFirst = { queue: await queue(), stale: stale() };
      // pw-2 is forgotten: that record alone is discarded, the oldest then comes back.
      await discardSetAsideWebChanges(['stale_kek:002000:dirty_state:ME']);
      const second = await restoreAllSetAsideWebChanges('pw-1', sodium);
      return { first, afterFirst, second, queue: await queue(), stale: stale() };
    """)
    assert result["first"] == {"restored": 1, "waiting": 2}
    assert result["afterFirst"] == {
        "queue": {"E2": "bmV3ZXN0"},
        "stale": ["stale_kek:001000:dirty_state:ME", "stale_kek:002000:dirty_state:ME"],
    }
    assert result["second"] == {"restored": 1, "waiting": 0}
    assert result["queue"] == {"E1": "b2xkZXN0", "E2": "bmV3ZXN0"}
    assert result["stale"] == []


def test_a_password_that_opens_nothing_changes_nothing():
    result = _go("""
      await setAside('pw-1', 'a1'.repeat(16), { E1: entry('E1', 'b2xk') }, 1000);
      let error = null;
      try { await restoreAllSetAsideWebChanges('not-it', sodium); } catch (err) { error = err.message; }
      return { error, stale: stale() };
    """)
    assert result == {"error": "sync.set_aside_wrong_password", "stale": ["stale_kek:001000:dirty_state:ME"]}


def test_a_record_no_password_opens_holds_nothing_back():
    result = _go("""
      await setAside('pw-1', 'a1'.repeat(16), { E1: entry('E1', 'b2xk') }, 1000);
      await setAside('pw-1', 'a2'.repeat(16), { E2: entry('E2', 'bmV3') }, 2000);
      const record = records.get('stale_kek:002000:dirty_state:ME');
      delete record.kdf;  // set aside by a version that did not keep the salt
      records.set('stale_kek:002000:dirty_state:ME', record);
      const outcome = await restoreAllSetAsideWebChanges('pw-1', sodium);
      return { outcome, queue: await queue(), stale: stale() };
    """)
    assert result == {
        "outcome": {"restored": 1, "waiting": 0},
        "queue": {"E1": "b2xk"},
        "stale": ["stale_kek:002000:dirty_state:ME"],
    }


def test_the_banner_discards_each_record_on_its_own():
    banner = _function("renderSetAsideWebChanges")
    assert "discardSetAsideWebChanges([id])" in banner
    assert "discardSetAsideWebChanges(changes)" not in banner
    assert "restoreAllSetAsideWebChanges(password.value, _sodium)" in banner
