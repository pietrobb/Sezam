"""Review 526419e V6: /api/org-recovery/store was a password oracle.

Planting a new recovery key needs the current password's proof (e4cd15a #1),
and a wrong one counts towards the name lock - but every proof was verified,
also on a locked name. The holder of a stolen identity key (a JWT is all the
endpoint asks for) kept guessing; the right guess went through even while
the name was locked, and the thief then reset the password with their own
recovery key. The store now has the K1 gate's one checked proof per window.
"""

from __future__ import annotations

import os

import pytest

from tests.test_grant_folder_access import team  # noqa: F401  (fixture)
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    server,
)
from tests.test_lone_admin_org_recovery import _store_body, _user


def _store(client, proof: bytes):
    return client._request(
        "POST", "/api/org-recovery/store",
        _store_body(current_auth_proof=bytes(proof).hex()), auth=True,
    )


def test_locked_name_gets_one_checked_store_proof_per_window(team):  # noqa: F811
    url, db, admin, admin_client, _bob, _folders = team
    admin_id = admin.db.get_meta("user_id")
    right = admin.current_auth_proof(PASSWORD)
    _user(db, admin_id)["recovery_attempts"] = 19  # recovery_max_total=20

    with pytest.raises(RuntimeError, match="423"):
        _store(admin_client, os.urandom(32))  # the guess that locks the name is checked ...
    attempts = _user(db, admin_id)["recovery_attempts"]
    for _ in range(3):  # ... the next ones in the window are not
        with pytest.raises(RuntimeError, match="429"):
            _store(admin_client, os.urandom(32))
    with pytest.raises(RuntimeError, match="429"):
        _store(admin_client, right)  # not even the right one: no oracle
    assert _user(db, admin_id)["recovery_attempts"] == attempts
    assert not db._storage.get("org_recovery_blobs")

    for slot in db._storage.get("recovery_probe_slots", []):
        slot["probe_at"] -= 300_001  # the window passes
    _store(admin_client, right)
    assert db._storage["org_recovery_blobs"][0]["created_by"] == admin_id
