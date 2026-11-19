"""Review a159e97 (web, medium): the sync lock had no timeout.

A request the server (or a dead connection) never answered held the page's
sync lock for good: every later pull, push and sign-in waited behind it until
a reload. Each request now fails after WEB_FETCH_TIMEOUT_MS, body included.
"""

from __future__ import annotations

from tests.test_review_web import APP, _run_source, pytestmark  # noqa: F401


def _source(name: str) -> str:
    """A function with a default argument (``= {}``) the generic extractor trips on."""
    start = APP.index(f"function {name}(")
    if APP[max(0, start - 6):start] == "async ":
        start -= 6
    depth = 0
    for index in range(APP.index(") {", start) + 2, len(APP)):
        depth += {"{": 1, "}": -1}.get(APP[index], 0)
        if depth == 0:
            return APP[start:index + 1]
    raise AssertionError(name)


SCRIPT = r"""
  var API_BASE = '', WEB_FETCH_TIMEOUT_MS = 50;
  state.token = null;
  // A server that never answers: only an abort ends the request.
  fetch = (url, init = {}) => new Promise((_, reject) => {
    if (init.signal) init.signal.addEventListener('abort', () => reject(init.signal.reason));
    // (no signal: never settles, the lock is held for good)
  });
  (async () => {
    const first = withWebSyncLock(() => apiFetch('/api/sync/pull')).then(() => 'answered', err => err.message);
    const second = withWebSyncLock(async () => 'second ran');
    const stuck = new Promise(resolve => setTimeout(() => resolve('stuck'), 2000));
    return [await Promise.race([first, stuck]), await Promise.race([second, stuck])];
  })()
"""


def test_a_request_that_is_never_answered_releases_the_sync_lock():
    helpers = _source("fetchWithTimeout") + "\n" + _source("apiFetch")
    first, second = _run_source(helpers, SCRIPT)
    assert first == "No answer from the server in 0.05 s"  # before: 'stuck'
    assert second == "second ran"
