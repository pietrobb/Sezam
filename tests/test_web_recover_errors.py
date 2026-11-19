"""Lockout review #7 (web): a throttled or locked /recover is not "Wrong password".

Every /api/auth/recover failure (429 from the address limit, 423 lock, server
down) was shown as "Wrong password", so a user with the correct password kept
retyping it and only fed the counters.
"""

from __future__ import annotations

import re

import tests.test_review_web as web
from tests.test_review_web import APP, _function, _run, pytestmark  # noqa: F401

SCRIPT = """
(async () => {
  API_BASE = '';
  t = key => key;
  const messages = {};
  for (const status of [401, 423, 429, 500]) {
    fetch = async () => ({
      ok: false, status, statusText: 'x', headers: { get: () => null },
      json: async () => ({ detail: 'server says ' + status }),
    });
    try { await apiFetch('/api/auth/recover', { method: 'POST', body: {} }); }
    catch (err) { messages[status] = recoverFailureMessage(err); }
  }
  messages.network = recoverFailureMessage(new TypeError('Failed to fetch'));
  return messages;
})()
"""


def _api_fetch_source() -> str:
    # _function stops at the {} default parameter; take the whole top-level body.
    sources = []
    for head in ("const WEB_FETCH_TIMEOUT_MS", "async function apiFetch("):
        start = APP.index(head)
        sources.append(APP[start:APP.index("\n}\n", start) + 2])
    return "\n".join(sources)


def test_recover_failures_are_told_apart(monkeypatch):
    monkeypatch.setattr(web, "_function", lambda name: _api_fetch_source() if name == "apiFetch" else _function(name))
    messages = _run(["apiFetch", "recoverFailureMessage"], SCRIPT, state={})
    assert messages == {
        "401": "error.wrong_password",
        "423": "error.recover_locked",
        "429": "error.recover_rate_limited",
        "500": "error.recover_unavailable",
        "network": "error.recover_unavailable",
    }


def test_login_maps_every_recover_call_through_the_helper():
    login = _function("handleLogin") + "\n" + _function("openLoginKeypair")
    calls = [m.start() for m in re.finditer(r"apiFetch\('/api/auth/recover'", login)]
    assert len(calls) >= 2
    for start in calls:
        window = login[start:start + 400]
        assert "throw recoverError(recoverErr);" in window
    assert "new Error(recoverFailureMessage(recoverErr))" in _function("recoverError")
    assert "throw new Error(t('error.wrong_password'));" not in login
