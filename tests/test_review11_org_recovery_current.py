"""Review 4acfdde (R11 #2): a new org recovery setup voids the shares of the old one.

The server took a recovery proof for the stored blob's key and for every key
the team log names. A setup the log never heard of (the web's anchor failed
with only a console warning) left the log naming the previous key, and the
previous shares still reset the admin's account; so did the shares of an
admin another admin had replaced. Only the newest of the stored blob and the
logged keys counts now: the blob ranks with the log head at the time it was
stored, a logged key with its last org.recovery record.
"""

from __future__ import annotations

import os

import pytest

from sezam.vault.key_rotation import org_recovery_server_wrap, org_recovery_signing_key
from sezam.vault.sync_common import server_error
from tests.server_admin_lie import users_row_deciding
from tests.test_integration_client_server import PASSWORD, _client
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review2_server_mariadb import mariadb  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401  (fixture)


def _store(vault, client, *, anchor: bool, replace: bool = False) -> bytes:
    """A web setup (app.js handleShamirGenerate): store, then anchorWebOrgRecovery."""
    secret = os.urandom(32)
    pk = bytes(org_recovery_signing_key(secret).verify_key).hex()
    body = {
        "wrapped_kek": org_recovery_server_wrap(vault.dek_mgr._kek, secret).hex(),
        "recovery_signing_pk": pk, "threshold": 2, "total_shares": 3,
        "key_epoch": int(vault.db.get_meta("key_epoch") or "0"),
    }
    if replace:
        body["replace_other_admin"] = True
    client.store_org_recovery(body, vault.current_auth_proof(PASSWORD))
    if anchor:
        client.append_team_log([("org.recovery", {"recovery_pk": pk})])
    return secret


def _recovers(client, secret: bytes) -> str | None:
    """The account the shares' proof opens (web handleOrgRecovery), or None when refused."""
    challenge = client._request("POST", "/api/org-recovery/challenge")["challenge"]
    signature = org_recovery_signing_key(secret).sign(bytes.fromhex(challenge)).signature.hex()
    try:
        return client._request("POST", "/api/org-recovery/keypair", {
            "challenge": challenge, "signature": signature,
        })["user_id"]
    except RuntimeError as exc:
        assert server_error(exc, 401), exc
        return None


def _blob_for(client, secret: bytes) -> bool:
    pk = bytes(org_recovery_signing_key(secret).verify_key).hex()
    try:
        client._request("GET", f"/api/org-recovery/blob?recovery_signing_pk={pk}")
    except RuntimeError as exc:
        assert server_error(exc, 404), exc
        return False
    return True


def test_a_setup_the_log_never_named_voids_the_older_shares(team, server):  # noqa: F811
    url, _ = server
    _, admin, admin_client, bob, _ = team
    _found_with_bob(admin_client, bob)
    admin_id = admin.db.get_meta("user_id")
    first = _store(admin, admin_client, anchor=True)
    assert _recovers(admin_client, first) == admin_id

    second = _store(admin, admin_client, anchor=False)  # the log still names the first key
    assert _recovers(admin_client, first) is None
    assert not _blob_for(admin_client, first)
    assert _recovers(admin_client, second) == admin_id
    assert _blob_for(admin_client, second)
    status = admin_client._request("GET", "/api/org-recovery/status")
    assert status["recovery_signing_pk"] == bytes(org_recovery_signing_key(second).verify_key).hex()

    # Its anchor arriving later changes nothing.
    admin_client.append_team_log([("org.recovery", {
        "recovery_pk": bytes(org_recovery_signing_key(second).verify_key).hex(),
    })])
    assert _recovers(admin_client, first) is None
    assert _recovers(admin_client, second) == admin_id


def test_another_admins_setup_voids_the_replaced_admins_shares(team, server):  # noqa: F811
    url, db = server
    _, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    first = _store(admin, admin_client, anchor=True)  # the log names it for admin

    bob_id = bob.db.get_meta("user_id")
    next(u for u in db._storage["users"] if u["id"] == bob_id)["is_admin"] = 1
    bob_client = _client(bob, url)  # an admin by the users row only, not by the log
    with pytest.raises(RuntimeError) as refused:  # INV-1 (R15-F1-S2): the log says who the admin is
        _store(bob, bob_client, anchor=False, replace=True)
    assert server_error(refused.value, 403), refused.value
    assert _recovers(bob_client, first) == admin.db.get_meta("user_id")
    # A server that still takes the users row let him replace it: the newest counts.
    with users_row_deciding():
        second = _store(bob, bob_client, anchor=False, replace=True)
    assert _recovers(bob_client, first) is None
    assert not _blob_for(bob_client, first)
    assert _recovers(bob_client, second) == bob_id


@pytest.mark.asyncio
async def test_a_blob_from_before_the_upgrade_ranks_with_the_log_head(mariadb):  # noqa: F811
    """On a real MariaDB: the log_seq column arrives by migration, and a blob
    stored before it ranks with the log head at the upgrade."""
    async with mariadb.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("ALTER TABLE org_recovery_blobs DROP COLUMN log_seq")
            await cur.execute(
                "INSERT INTO org_recovery_blobs (id, wrapped_kek, recovery_signing_pk, created_by, "
                "created_at) VALUES (1, %s, %s, 'A', 0)", (b"w" * 72, b"k" * 32),
            )
            for seq in (0, 1, 2):
                await cur.execute(
                    "INSERT INTO team_log (seq, prev, hash, body, sig, author, created_at) "
                    "VALUES (%s, %s, %s, '{}', %s, 'A', 0)",
                    (seq, "0" * 64, f"{seq:064d}", "0" * 128),
                )
    await mariadb.create_schema()
    async with mariadb.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT log_seq FROM org_recovery_blobs WHERE id = 1")
            assert (await cur.fetchone())[0] == 2
