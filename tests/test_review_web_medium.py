"""Regressions for code review HEAD 2c7e809, medium web items W2-W3.

W1 (clipboard clear without readText) lives in test_crypto.TestWebClipboardSafety,
W4 (exact CDN files in CSP) in test_server_spec.
"""

from __future__ import annotations

from tests.test_review_web import APP, _function, _run, pytestmark  # noqa: F401


# ── W2 / sync redesign S2: no ETag, the checkpoint is the only pull state ──


def test_web_keeps_no_etag_and_never_takes_a_304():
    # A stored ETag was a second copy of the checkpoint: one past what a pull
    # brought answered every later pull with 304 (docs/SYNC_SINGLE_SOURCE.md).
    for gone in ("lastETag", "lastResponseETag", "If-None-Match", "status === 304"):
        assert gone not in APP, gone
    pull = _function("pullAndBuildTreeLocked")
    assert "throw new Error('Invalid sync response')" in pull


# ── W3: an edit may not be stacked on top of an unresolved conflict ──


def test_edit_on_conflicted_object_is_blocked_but_retry_is_allowed():
    script = """
      globalThis.t = key => key;
      const conflicts = { OBJ: { local_object: { id: 'OBJ', version: 4 }, server_version: 4 } };
      const outcome = obj => {
        try { assertNotStackedOnConflict(obj, conflicts); return 'ok'; }
        catch (err) { return err.isSyncConflict ? 'blocked' : String(err); }
      };
      ({
        newEditOnConflict: outcome({ id: 'OBJ', version: 5 }),
        retryQueuedVersion: outcome({ id: 'OBJ', version: 4 }),
        unrelatedObject: outcome({ id: 'OTHER', version: 9 }),
        noConflicts: (() => { assertNotStackedOnConflict({ id: 'OBJ', version: 5 }, undefined); return 'ok'; })(),
      })
    """
    result = _run(["assertNotStackedOnConflict"], script)
    assert result == {
        "newEditOnConflict": "blocked",
        "retryQueuedVersion": "ok",
        "unrelatedObject": "ok",
        "noConflicts": "ok",
    }


def test_every_push_goes_through_the_conflict_guard():
    push = _function("pushEncryptedVaultObjectLocked")
    assert push.index("assertNotStackedOnConflict(vaultObj)") < push.index("state.outbox[vaultObj.id] = vaultObj")
