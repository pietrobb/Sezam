"""Review d615826 H7: an interrupted first login after a password change elsewhere.

The login fetched the keypair under the new password from the server and put
it into the browser's cache at once; the records sealed under the old KEK were
set aside only later in handleLogin. A login interrupted in between (tab
closed, network gone) left a cache the new password opens, so the next login
no longer saw that the KEK had changed, never set the old records aside, and
their failing checkpoint blocked every login in this browser.
"""

from __future__ import annotations

from tests.test_review_web import _function, _run, pytestmark  # noqa: F401

FUNCTIONS = ["openLoginKeypair", "hexToBytes"]

FAKE = """
  const NEW = new Uint8Array(64).fill(1);
  const SERVER_WRAP = 'aa'.repeat(80);
  const CACHED_WRAP = 'bb'.repeat(80);
  let cache = { id: 'keypair', encrypted_keypair: CACHED_WRAP, user_id: 'ME' };
  globalThis.t = key => key;
  globalThis.loadFromIndexedDB = async () => cache && { ...cache };
  globalThis.saveToIndexedDB = async record => { cache = { id: 'keypair', ...record }; };
  globalThis.accountKdfParams = () => ({ time_cost: 3, memory_cost: 65536, parallelism: 4 });
  globalThis.decryptLoginKeypair = (envelope, kek) => {
    // The cache is under the old KEK; only the server's wrap opens with the new one.
    if (bytesToHex(envelope) !== SERVER_WRAP || kek[0] !== 1) throw new Error('ciphertext cannot be decrypted');
    return { keypairBytes: new Uint8Array(96), confirmedGenesis: null };
  };
  globalThis.apiFetch = async (path, options) => {
    if (path === '/api/auth/recover') return { encrypted_keypair: SERVER_WRAP, user_id: 'ME' };
    throw new Error('unexpected ' + path);
  };
  const attempt = () => openLoginKeypair('alice', 'new-pw', {}, null, sodium, { derivedKey: NEW });
"""


def test_a_login_interrupted_after_the_keypair_still_sees_the_password_change():
    script = FAKE + """
      const first = await attempt();
      // The login is interrupted here, before handleLogin set the records aside.
      const cacheAfterFirst = cache.encrypted_keypair;
      const second = await attempt();
      return {
        first: first.kekChangedElsewhere, second: second.kekChangedElsewhere,
        cacheAfterFirst, serverWrap: second.encryptedKeypairHex, userId: second.keypairUserId,
      };
    """
    result = _run(FUNCTIONS, f"(async () => {{ {script} }})()")
    assert result["first"] is True
    assert result["cacheAfterFirst"] == "bb" * 80
    assert result["second"] is True
    assert result["serverWrap"] == "aa" * 80
    assert result["userId"] == "ME"


def test_login_replaces_the_cache_only_after_the_old_records_are_set_aside():
    login = _function("handleLogin")
    set_aside = login.index("await setAsideRecordsOfOldKek(_sodium, keyChanged)")
    cache = login.index("encrypted_keypair: opened.encryptedKeypairHex")
    assert set_aside < login.index("if (keyChanged) {") < cache
    assert cache < login.index("await pullAndBuildTree();")
    assert "saveToIndexedDB" not in _function("openLoginKeypair")[
        _function("openLoginKeypair").index("if (!fromIndexedDB || options.localOnly) {"):
    ]
