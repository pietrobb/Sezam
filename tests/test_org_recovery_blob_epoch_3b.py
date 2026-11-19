"""Review 688edcb #3b: the org recovery blob took its epoch from the server.

/api/org-recovery/store recorded the account's key epoch at the time of the
upload, not the epoch of the KEK the client actually wrapped. A web session
still holding the KEK from before a password change elsewhere stored a blob
that wraps the old KEK, and /status reported it current until recovery failed
late. The client now sends the epoch it wrapped; the server refuses a blob
from another epoch and stores the client's epoch.
"""

from __future__ import annotations

import pytest

from tests.test_org_recovery_epoch import ADMIN, _auth, _set_epoch, _store_body
from tests.test_review_web import _function, _run, pytestmark  # noqa: F401
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    app_client,
    mock_db,
)
from tests.test_web_org_recovery_epoch import STUBS


@pytest.mark.asyncio
async def test_blob_wrapping_an_older_kek_is_refused_not_stored_as_current(
    app_client, mock_db  # noqa: F811
):
    _create_admin_user(mock_db._storage)
    _set_epoch(mock_db, ADMIN, 3)  # the password was changed on another device

    stale = await app_client.post(
        "/api/org-recovery/store", json=_store_body(key_epoch=2), headers=_auth(ADMIN, "admin")
    )

    assert stale.status_code == 409, stale.text
    assert "key epoch 2" in stale.json()["detail"]
    assert mock_db._storage["org_recovery_blobs"] == []

    current = await app_client.post(
        "/api/org-recovery/store", json=_store_body(key_epoch=3), headers=_auth(ADMIN, "admin")
    )
    assert current.status_code == 200, current.text
    assert mock_db._storage["org_recovery_blobs"][0]["key_epoch"] == 3
    assert (await app_client.get("/api/org-recovery/status")).json()["stale"] is False


@pytest.mark.asyncio
async def test_blob_without_its_epoch_is_refused(app_client, mock_db):  # noqa: F811
    _create_admin_user(mock_db._storage)
    body = _store_body()
    del body["key_epoch"]

    resp = await app_client.post("/api/org-recovery/store", json=body, headers=_auth(ADMIN, "admin"))

    assert resp.status_code == 400
    assert "key epoch" in resp.json()["detail"]
    assert mock_db._storage["org_recovery_blobs"] == []


def test_web_setup_sends_the_epoch_of_the_kek_it_wrapped():
    script = STUBS + """
      state.keyEpoch = 4;
      confirm = () => true;
      apiFetch = async (path, options = {}) => {
        if (path === '/api/org-recovery/status') return { configured: false };
        if (path === '/api/org-recovery/store') calls.stored.push(options.body);
        return {};
      };
      await handleShamirGenerate();
      return calls;
    """
    calls = _run(["handleShamirGenerate", "bytesToHex"], f"(async () => {{ {script} }})()")
    assert calls["stored"][0]["key_epoch"] == 4


def test_web_org_recovery_journals_the_new_epoch_with_the_blob():
    body = _function("handleOrgRecovery")
    store = body.index("recovery_store: {")
    assert "key_epoch: state.keyEpoch + 1," in body[store:body.index("},", store)]


def test_web_journal_from_before_the_fix_stores_its_own_epoch():
    script = """
      const journal = { key_epoch: 7, recovery_store: { wrapped_kek: 'aa', threshold: 2 } };
      const fresh = { key_epoch: 7, recovery_store: { wrapped_kek: 'aa', key_epoch: 7 } };
      return [journalRecoveryStore(journal, 7), journalRecoveryStore(fresh, 9)];
    """
    old, new = _run(["journalRecoveryStore"], f"(() => {{ {script} }})()")
    assert old == {"wrapped_kek": "aa", "threshold": 2, "key_epoch": 7}
    assert new["key_epoch"] == 7
