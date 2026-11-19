"""Review main@7c10379 (R7-H, web; the mobile sync lock of review d615826).

The page pulls after a sign-in, after every save and on Retry, and nothing
kept two of those apart. Mobile got its lock in d615826 (1f08642); the web
did not, and in one tab:

- a pull answered before a save's push, but finishing after the save's own
  pull, went to the server's older seq: the page raised ROLLBACK DETECTED
  and asked to accept a server rolled back, on an ordinary save;
- a pull wrote back the queue it had read before an edit was queued offline
  (its push failed): the edit was gone from the queue, and after a reload.

Pulls and the queue's read-modify-writes now run alone; pushes may still
overlap each other (review 526419e #2), not a pull.
"""

from __future__ import annotations

import pytest

import tests.web_tab as wt
from sezam import cli
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401

# A pull held at `hold` ('fetch': its GET /api/sync reply; 'hash': after it
# read the queue), a save started meanwhile (its push optionally failing),
# the pull let go once the save is done or waits for it.
OVERLAP = r"""
  async overlap(step) {
    let release; const gate = new Promise(r => { release = r; });
    let held = false;
    const name = step.hold === 'fetch' ? 'fetch' : 'computeWebStateHash';
    const orig = context[name];
    context[name] = step.hold === 'fetch'
      ? async (url, options = {}) => {
          const resp = await orig(url, options);
          if (!held && (options.method || 'GET') === 'GET' && url.includes('/api/sync?')) {
            held = true; await gate;
          }
          return resp;
        }
      : async (...args) => {
          if (!held) { held = true; await gate; }
          return orig(...args);
        };
    try {
      const pull = page('pullAndBuildTree')().then(() => null, e => e.message || String(e));
      while (!held) await new Promise(r => setTimeout(r, 5));
      if (step.push_fails) failNext = { method: 'POST', path: '/api/sync', mode: 'before' };
      const saving = tabActions.save_object(step);
      await Promise.race([saving, new Promise(r => setTimeout(r, 2000))]);
      release();
      const el = await saving;
      const pulled = await pull;
      const save = el && el.classList ? (el.classList.contains('hidden') ? null : el.textContent) : (el || null);
      return pulled ? `pull: ${pulled}` : (save && !step.push_fails ? `save: ${save}` : null);
    } finally {
      context[name] = orig;
      failNext = null;
    }
  },
  async view() { return null; },"""


@pytest.fixture
def overlapping_tab(monkeypatch):
    monkeypatch.setattr(wt, "TAB", wt.TAB.replace("  async view() { return null; },", OVERLAP, 1))


def _signed_in(url, tmp_path):
    laptop = _vault(tmp_path / "laptop", "admin")
    node = laptop.create_node("Servers")
    cli._server_connect_flow(url, laptop, PASSWORD)
    tab = wt.WebTab(url, tmp_path / "tab.log")
    assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
    # Something new on the server, so the held pull has a delta to apply.
    laptop.create_entry(node, "from-laptop", [{"key": "password", "value": "l1", "sensitive": True}])
    _client(laptop, url).push()
    return laptop, node, tab


def _names(view):
    return sorted(e["name"] for e in view["entries"])


def test_a_pull_finishing_after_a_save_is_no_rollback(server, tmp_path, overlapping_tab):  # noqa: F811
    url, _db = server
    laptop, node, tab = _signed_in(url, tmp_path)
    try:
        r = tab.do("overlap", hold="fetch", mode="entry", name="from-web", parent=node,
                   fields=[{"key": "password", "value": "w1"}])
        assert r["error"] is None, r
        assert r["confirms"] == [], r
        assert _names(r["view"]) == ["from-laptop", "from-web"], r
        assert tab.do("refresh")["error"] is None
    finally:
        tab.kill()
        laptop.lock()


def test_an_edit_queued_offline_during_a_pull_stays_queued(server, tmp_path, overlapping_tab):  # noqa: F811
    url, _db = server
    laptop, node, tab = _signed_in(url, tmp_path)
    try:
        r = tab.do("overlap", hold="hash", push_fails=True, mode="entry", name="offline-web",
                   parent=node, fields=[{"key": "password", "value": "w2"}])
        assert r["error"] is None, r
        assert r["view"]["dirty"], r
        idb = tab.close()
        tab = wt.WebTab(url, tmp_path / "tab2.log", idb=idb)
        r = tab.do("login", username="admin", password=PASSWORD)
        assert r["error"] is None, r
        assert r["view"]["dirty"], r
        assert "offline-web" in _names(r["view"]), r
        # Retry sends it: the edit reaches the server.
        assert tab.do("retry")["error"] is None
        laptop_view = _client(laptop, url)
        laptop_view.pull()
        names = {e["name"] for e in laptop.list_entries(node)}
        assert names == {"from-laptop", "offline-web"}, names
    finally:
        tab.kill()
        laptop.lock()
