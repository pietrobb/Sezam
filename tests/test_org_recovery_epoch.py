"""Lockout review #3: the server org-recovery blob outlived the KEK it wraps.

Any password change (desktop, web or mobile) re-keys the owner's keypair but
leaves the blob on the old KEK, so recovery failed late with "Failed to
decrypt keypair with recovered KEK" while the UI still offered it. The blob
now records the owner's key epoch and /status and /blob report it stale. A
second admin can no longer silently void the first admin's shares.
"""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

from sezam import cli
from tests.test_ai_r1_snapshots import _cli_env
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    NEW_PASSWORD,
    PASSWORD,
    _vault,
    server,
)
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    app_client,
    mock_db,
)

ADMIN = "ADMIN000000000000000000001"
OTHER = "ADMIN000000000000000000002"


def _store_body(**extra):
    return {
        "wrapped_kek": os.urandom(72).hex(),
        "recovery_signing_pk": os.urandom(32).hex(),
        "threshold": 2,
        "total_shares": 3,
        "key_epoch": 0,
        **extra,
    }


def _auth(user_id, username):
    return {"Authorization": f"Bearer {_create_jwt(user_id, username, True)}"}


def _set_epoch(mock_db, user_id, epoch):
    rows = mock_db._storage["sync_state"]
    for row in rows:
        if row["user_id"] == user_id:
            row["key_epoch"] = epoch
            return
    rows.append({"user_id": user_id, "key_epoch": epoch})


@pytest.mark.asyncio
async def test_blob_turns_stale_after_the_owner_changes_password(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    _set_epoch(mock_db, ADMIN, 2)
    stored = await app_client.post(
        "/api/org-recovery/store", json=_store_body(key_epoch=2), headers=_auth(ADMIN, "admin")
    )
    assert stored.status_code == 200, stored.text
    assert mock_db._storage["org_recovery_blobs"][0]["key_epoch"] == 2

    status = (await app_client.get("/api/org-recovery/status", headers=_auth(ADMIN, "admin"))).json()
    assert status["configured"] and status["stale"] is False
    assert status["created_by"] == ADMIN
    assert (await app_client.get("/api/org-recovery/blob")).json()["stale"] is False

    _set_epoch(mock_db, ADMIN, 3)  # a password change on any client
    assert (await app_client.get("/api/org-recovery/status")).json()["stale"] is True
    assert (await app_client.get("/api/org-recovery/blob")).json()["stale"] is True

    # Setting it up again under the current KEK makes it usable again.
    again = await app_client.post(
        "/api/org-recovery/store", json=_store_body(key_epoch=3), headers=_auth(ADMIN, "admin")
    )
    assert again.status_code == 200
    assert len(mock_db._storage["org_recovery_blobs"]) == 1
    assert (await app_client.get("/api/org-recovery/status")).json()["stale"] is False


@pytest.mark.asyncio
async def test_legacy_blob_without_epoch_is_stale_once_the_owner_rotated(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    mock_db._storage["org_recovery_blobs"].append({
        "id": 1, "wrapped_kek": os.urandom(72), "recovery_signing_pk": os.urandom(32),
        "threshold": 2, "total_shares": 3, "created_by": ADMIN, "created_at": 1,
    })
    assert (await app_client.get("/api/org-recovery/status")).json()["stale"] is False
    _set_epoch(mock_db, ADMIN, 1)
    assert (await app_client.get("/api/org-recovery/status")).json()["stale"] is True


@pytest.mark.asyncio
async def test_second_admin_cannot_silently_replace_the_first_admins_setup(
    app_client, mock_db
):
    _create_admin_user(mock_db._storage)
    _create_admin_user(mock_db._storage, OTHER, "admin2")
    first = _store_body()
    assert (await app_client.post(
        "/api/org-recovery/store", json=first, headers=_auth(ADMIN, "admin")
    )).status_code == 200

    refused = await app_client.post(
        "/api/org-recovery/store", json=_store_body(), headers=_auth(OTHER, "admin2")
    )
    assert refused.status_code == 409
    blob = mock_db._storage["org_recovery_blobs"]
    assert len(blob) == 1 and blob[0]["created_by"] == ADMIN
    assert blob[0]["wrapped_kek"].hex() == first["wrapped_kek"]

    replaced = await app_client.post(
        "/api/org-recovery/store",
        json=_store_body(replace_other_admin=True),
        headers=_auth(OTHER, "admin2"),
    )
    assert replaced.status_code == 200
    assert mock_db._storage["org_recovery_blobs"][0]["created_by"] == OTHER


def test_cli_change_password_warns_that_web_org_recovery_went_stale(
    server, tmp_path, monkeypatch
):
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    user_id = laptop.db.get_meta("user_id")
    laptop.lock()
    db._storage["org_recovery_blobs"].append({
        "id": 1, "wrapped_kek": os.urandom(72), "recovery_signing_pk": os.urandom(32),
        "threshold": 2, "total_shares": 3, "created_by": user_id, "created_at": 1,
        "key_epoch": 0,
    })
    _cli_env(tmp_path / "laptop", monkeypatch)

    result = CliRunner().invoke(
        cli.main, ["change-password"], input=f"{PASSWORD}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\n"
    )
    assert result.exit_code == 0, result.output
    assert "organization recovery shares" in result.output
