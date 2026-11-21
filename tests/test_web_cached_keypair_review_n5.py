"""Lockout review N5: a browser with a cached keypair after a rotation elsewhere.

The web login opened the keypair cached in IndexedDB with whatever password
derived the KEK it was cached under and signed in with its identity key; the
server never said whether that wrap was still the account's. After the key
material moved on elsewhere the browser unlocked with the outdated password
and wrote records under the outdated KEK. /auth/verify now returns the hash of
the account's current wrap; a cached copy that differs (or whose key the
server refuses) is replaced by the server's copy under this password's proof,
so the outdated password ends as a wrong password.
"""

from __future__ import annotations

import hashlib

import pytest

from tests.test_review_web import _function, _run, pytestmark  # noqa: F401
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_regular_user,
    _sign_challenge,
    app_client,
    mock_db,
)

USER_ID = "USER0000000000000000000001"

FUNCTIONS = [
    "signInWithKeypair", "signInWithLoginKeypair", "recoverError", "recoverFailureMessage",
    "hexToBytes", "signAuthChallenge", "mergePreAnchor", "parsePreAnchor",
]

# The current password derives CURRENT (KEK || proof); the outdated one OLD.
# The server holds the wrap SERVER_WRAP that only CURRENT's KEK opens.
FAKE_SERVER = """
  globalThis.PRE_ANCHOR_ENTRY_LEN = 60; globalThis.PRE_ANCHOR_MAX = 8;
  const CURRENT = new Uint8Array(64).fill(1);
  const OLD = new Uint8Array(64).fill(2);
  const SERVER_WRAP = 'aa'.repeat(80);
  const CACHED_WRAP = 'bb'.repeat(80);
  const sha = value => bytesToHex(sodium.crypto_hash_sha256(hexToBytes(value)));
  const calls = [];
  const cache = [];
  const signing = sodium.crypto_sign_keypair();
  const keypair = () => { const kp = new Uint8Array(96); kp.set(signing.privateKey, 0); return kp; };
  globalThis.t = key => key;
  globalThis.saveToIndexedDB = async record => { cache.push(record); };
  globalThis.decryptLoginKeypair = (envelope, kek) => {
    if (bytesToHex(envelope) !== SERVER_WRAP || kek[0] !== 1) throw new Error('ciphertext cannot be decrypted');
    return { keypairBytes: keypair(), confirmedGenesis: null };
  };
  globalThis.apiFetch = async (path, options) => {
    calls.push({ path, auth: (options.headers || {}).Authorization || null });
    if (path === '/api/auth/challenge') return { challenge: '00'.repeat(40) };
    if (path === '/api/auth/verify') {
      return { token: 'T' + calls.length, user_id: 'ME', is_admin: false, key_material_hash: sha(SERVER_WRAP) };
    }
    if (path === '/api/auth/logout') return { status: 'ok' };
    if (path === '/api/auth/recover') {
      if (options.body.auth_proof !== bytesToHex(CURRENT.subarray(32, 64))) {
        const err = new Error('Recovery failed'); err.status = 401; throw err;
      }
      return { encrypted_keypair: SERVER_WRAP, user_id: 'ME' };
    }
    throw new Error('unexpected ' + path);
  };
  globalThis.accountKdfParams = () => ({ time_cost: 3, memory_cost: 65536, parallelism: 4 });
  const opened = (derivedKey, wrap, cachedKeypair) => ({
    derivedKey, keypairBytes: keypair(), cachedKeypair, encryptedKeypairHex: wrap,
  });
  const run = async o => {
    try {
      const r = await signInWithLoginKeypair('alice', o, {}, sodium);
      return { token: r.authResp.token, replaced: !!r.keypairBytes, calls, cache };
    } catch (err) {
      return { error: err.message, wrongPassword: !!err.wrongPassword, calls, cache };
    }
  };
"""


def _login(case: str) -> dict:
    return _run(FUNCTIONS, f"(async () => {{ {FAKE_SERVER} return await run({case}); }})()")


def test_outdated_password_on_a_stale_cache_is_a_wrong_password():
    result = _login("opened(OLD, CACHED_WRAP, true)")
    assert result["wrongPassword"] is True
    assert result["error"] == "error.wrong_password"
    assert result["cache"] == []
    paths = [c["path"] for c in result["calls"]]
    assert paths == [
        "/api/auth/challenge", "/api/auth/verify", "/api/auth/logout", "/api/auth/recover",
    ]
    # The token the stale cache got is revoked, not kept.
    assert result["calls"][2]["auth"] == "Bearer T2"


def test_current_password_on_a_stale_cache_takes_the_server_copy():
    result = _login("opened(CURRENT, CACHED_WRAP, true)")
    assert result["replaced"] is True
    assert result["cache"] == [{"encrypted_keypair": "aa" * 80, "user_id": "ME"}]
    paths = [c["path"] for c in result["calls"]]
    assert paths[-2:] == ["/api/auth/challenge", "/api/auth/verify"]
    assert result["token"] == "T6"


def test_cache_that_is_the_current_wrap_signs_in_directly():
    result = _login("opened(CURRENT, SERVER_WRAP, true)")
    assert result["replaced"] is False
    assert result["token"] == "T2"
    assert [c["path"] for c in result["calls"]] == ["/api/auth/challenge", "/api/auth/verify"]


def test_refused_cached_key_falls_back_to_the_server_copy():
    script = FAKE_SERVER + """
      const verify = apiFetch;
      let refused = false;
      apiFetch = async (path, options) => {
        if (path === '/api/auth/verify' && !refused) {
          refused = true; calls.push({ path });
          const err = new Error('Authentication failed'); err.status = 401; throw err;
        }
        return verify(path, options);
      };
      return await run(opened(OLD, CACHED_WRAP, true));
    """
    result = _run(FUNCTIONS, f"(async () => {{ {script} }})()")
    assert result["wrongPassword"] is True
    assert [c["path"] for c in result["calls"]][-1] == "/api/auth/recover"


def test_login_signs_in_only_through_the_cache_check():
    login = _function("handleLogin")
    assert "signInWithLoginKeypair(username, opened, meta, _sodium)" in login
    assert "/api/auth/verify" not in login
    assert login.index("signInWithLoginKeypair(") < login.index("state.keypair = {")
    assert "cachedKeypair = fromIndexedDB && !kekChangedElsewhere" in _function("openLoginKeypair")


def test_server_keys_naming_another_genesis_sign_in_and_keep_the_cached_anchor():
    # Capability run 416 (INV-7): a password changed on a device that left the
    # log. Before: TEAM LOG MISMATCH, the sign-in failed, and the way out
    # (forgetting the pins) needs a signed-in browser.
    script = FAKE_SERVER + """
      decryptLoginKeypair = (envelope, kek) => {
        if (bytesToHex(envelope) !== SERVER_WRAP || kek[0] !== 1) throw new Error('ciphertext cannot be decrypted');
        return { keypairBytes: keypair(), confirmedGenesis: 'b'.repeat(64) };
      };
      const o = opened(CURRENT, CACHED_WRAP, true);
      o.confirmedGenesis = 'a'.repeat(64);
      try {
        const r = await signInWithLoginKeypair('alice', o, {}, sodium);
        return { token: r.authResp.token, genesis: r.confirmedGenesis, cached: r.cachedGenesis, cache };
      } catch (err) { return { error: err.message }; }
    """
    result = _run(FUNCTIONS, f"(async () => {{ {script} }})()")
    assert result.get("error") is None, result
    assert result["genesis"] == "b" * 64 and result["cached"] == "a" * 64
    assert result["cache"] == [{"encrypted_keypair": "aa" * 80, "user_id": "ME"}]
    login = _function("handleLogin")
    assert login.index("keepTeamAnchor(signedIn.cachedGenesis") < login.index("importAccountTeamAnchor(")


@pytest.mark.asyncio
async def test_verify_reports_the_current_key_material_hash(app_client, mock_db):
    sk, _ = _create_regular_user(mock_db._storage, username="alice")
    wrap = b"\x5a" * 120
    mock_db._storage["users"][0]["encrypted_keypair"] = wrap
    challenge = (await app_client.post(
        "/api/auth/challenge", json={"username": "alice"}
    )).json()["challenge"]
    resp = await app_client.post("/api/auth/verify", json={
        "username": "alice", "challenge": challenge,
        "signature": _sign_challenge(sk, bytes.fromhex(challenge)).hex(),
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["user_id"] == USER_ID
    assert resp.json()["key_material_hash"] == hashlib.sha256(wrap).hexdigest()
