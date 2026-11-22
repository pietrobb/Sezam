"""Capability review run 49 (lockout review #7, web): the approval wait must not
poll /api/auth/recover.

pollForApproval re-derived the KEK and called /recover every 5 s while the
account was pending. Each round counted as a failed recovery against the
browser's address, so after ~50 s the address hit the 429 limit; the approved
owner (and everyone behind the same NAT) was refused and the poll swallowed
the 429 into a silent timeout. It now signs challenges with the keypair
onboarding still holds and reports throttling instead of hiding it.
"""

from __future__ import annotations

from tests.test_review_web import _run, pytestmark  # noqa: F401

FUNCTIONS = ["pollForApproval", "recoverFailureMessage", "signAuthChallenge", "signedInUserId"]

SETUP = """
  // Fast-forward past the 10 min timeout after 20 rounds so a poll that
  // never succeeds ends instead of spinning.
  let ticks = 0;
  const realNow = Date.now;
  setTimeout = fn => {
    if (++ticks > 20) Date.now = () => realNow() + 11 * 60 * 1000;
    return Promise.resolve().then(fn);
  };
  t = key => key;
  escapeHtml = value => value;
  ensureSodium = async () => sodium;
  hexToBytes = value => hex(value);
  const calls = [];
  startJwtRefreshTimer = () => calls.push('jwt');
  saveToIndexedDB = async record => calls.push('idb:' + record.encrypted_keypair);
  pullAndBuildTree = async () => calls.push('pull');
  renderUserInfoWithFingerprint = async () => {};
  showScreen = name => calls.push('screen:' + name);
  const el = () => ({
    textContent: '', innerHTML: '',
    classList: { add() {}, remove() {} },
    parentNode: { insertBefore() {} },
    remove() {},
  });
  document.createElement = () => ({ ...el(), addEventListener() {}, style: {} });
  const statusEl = el(), errorEl = el();
  const kp = sodium.crypto_sign_keypair();
  const keys = {
    signingSk: kp.privateKey.slice(),
    encryptionSk: sodium.randombytes_buf(32),
    kek: sodium.randombytes_buf(32),
    userId: 'U1', encryptedKeypairHex: 'abcd',
  };
  const error = status => Object.assign(new Error('x'), { status });
"""


def test_approval_is_detected_by_challenge_signing_not_recover():
    result = _run(FUNCTIONS, """
(async () => {
""" + SETUP + """
  let verifies = 0;
  apiFetch = async (path, opts) => {
    calls.push(path);
    if (path === '/api/auth/challenge') return { challenge: '00'.repeat(40) };
    if (path === '/api/auth/verify') {
      verifies += 1;
      if (verifies <= 3) throw error(401);  // still pending
      return { token: 'T', user_id: 'U1', is_admin: false };
    }
    throw error(500);
  };
  await pollForApproval('alice', keys, statusEl, errorEl);
  return {
    recover: calls.filter(c => c.startsWith('/api/auth/recover') || c.startsWith('/api/meta')).length,
    verifies,
    token: state.token,
    screen: calls.includes('screen:vault-screen'),
    idb: calls.includes('idb:abcd'),
    keyKept: state.keypair.signingSk.some(b => b !== 0),
  };
})()
""")
    assert result == {
        "recover": 0, "verifies": 4, "token": "T",
        "screen": True, "idb": True, "keyKept": True,
    }


def test_throttling_during_the_wait_is_reported_and_keys_are_wiped_on_timeout():
    result = _run(FUNCTIONS, """
(async () => {
""" + SETUP + """
  apiFetch = async path => {
    if (path === '/api/auth/challenge') throw error(429);
    throw error(500);
  };
  await pollForApproval('alice', keys, statusEl, errorEl);
  return {
    error: errorEl.textContent,
    status: statusEl.textContent,
    wiped: [keys.signingSk, keys.encryptionSk, keys.kek].every(k => k.every(b => b === 0)),
  };
})()
""")
    assert result == {
        "error": "error.recover_rate_limited", "status": "approval.timeout", "wiped": True,
    }
