"""Lockout review #7: /api/auth/recover must not let a stranger lock the owner out.

The per-name limits (3/h, 10 total -> 24 h lock) were checked before the
proof, so anyone who knew a username locked its owner out of password
recovery (web login, mobile unlock after a password change) with ten random
proofs. The proof is now verified first and guessing is bounded per client
address instead.

Review 688edcb V2: the address limit must not refuse a correct proof (one NAT
locked out a whole office), and a locked name rations verification so that
guessing from many addresses stays bounded.
"""

from __future__ import annotations

import hashlib
import hmac
import os

import pytest
from httpx import ASGITransport, AsyncClient

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    app_client,
    mock_db,
)


def _with_known_proof(user_row: dict) -> bytes:
    proof = os.urandom(32)
    verify_salt = os.urandom(32)
    user_row["verify_salt"] = verify_salt
    user_row["auth_proof_hash"] = hmac.new(verify_salt, proof, hashlib.sha256).hexdigest()
    return proof


def _client_from(ip: str) -> AsyncClient:
    from server.app.main import app

    transport = ASGITransport(app=app, raise_app_exceptions=False, client=(ip, 40000))
    return AsyncClient(transport=transport, base_url="http://test")


async def _recover(client: AsyncClient, proof: bytes, username: str = "admin") -> int:
    resp = await client.post(
        "/api/auth/recover", json={"username": username, "auth_proof": proof.hex()}
    )
    return resp.status_code


@pytest.mark.asyncio
async def test_strangers_wrong_proofs_do_not_lock_the_owner_out(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    row = mock_db._storage["users"][0]
    proof = _with_known_proof(row)

    async with _client_from("198.51.100.20") as owner:
        assert await _recover(owner, proof) == 200  # the owner's usual network

    async with _client_from("203.0.113.7") as stranger:
        statuses = [await _recover(stranger, os.urandom(32)) for _ in range(10)]
    assert statuses[-1] == 423  # the name is locked for wrong proofs ...
    assert row["recovery_locked"] == 1

    async with _client_from("198.51.100.20") as owner:
        assert await _recover(owner, proof) == 200  # ... never for the owner's
    assert row["recovery_locked"] == 0
    assert row["recovery_attempts"] == 0


@pytest.mark.asyncio
async def test_typos_within_the_hour_do_not_block_the_correct_password(app_client, mock_db):
    """Mobile sends every offline typo to /recover; 3/h used to block the 4th try."""
    _create_admin_user(mock_db._storage)
    proof = _with_known_proof(mock_db._storage["users"][0])

    async with _client_from("198.51.100.20") as owner:
        typos = [await _recover(owner, os.urandom(32)) for _ in range(4)]
        assert typos == [401, 401, 401, 401]
        assert await _recover(owner, proof) == 200


@pytest.mark.asyncio
async def test_wrong_proofs_are_bounded_per_address_across_names(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    proof = _with_known_proof(mock_db._storage["users"][0])

    async with _client_from("203.0.113.7") as attacker:
        # Failures count per address across names (no spreading over names).
        for name in ("ghost", "ghost2"):
            for _ in range(5):
                assert await _recover(attacker, os.urandom(32), name) == 401
        assert await _recover(attacker, os.urandom(32)) == 429

    async with _client_from("198.51.100.20") as owner:
        assert await _recover(owner, proof) == 200


@pytest.mark.asyncio
async def test_exhausted_address_still_accepts_a_correct_proof(app_client, mock_db):
    """Review 688edcb V2: ten typos from one office NAT (any names) answered
    every colleague's correct password with 429 for an hour."""
    _create_admin_user(mock_db._storage)
    proof = _with_known_proof(mock_db._storage["users"][0])

    async with _client_from("203.0.113.7") as office:
        for n in range(10):
            assert await _recover(office, os.urandom(32), f"ghost{n}") == 401
        assert await _recover(office, os.urandom(32), "ghost") == 429
        assert await _recover(office, proof) == 200


@pytest.mark.asyncio
async def test_locked_name_rations_guesses_from_many_addresses(app_client, mock_db):
    """Review 688edcb V2: with the proof verified before the name lock, a
    locked name no longer bounded guessing - a botnet tried 10 proofs per hour
    from every address. A locked name now verifies one proof per window from
    each network (capability run 83: per network, so no network holds the
    owner's slot) and three from all networks together (run 85)."""
    _create_admin_user(mock_db._storage)
    row = mock_db._storage["users"][0]
    proof = _with_known_proof(row)

    async with _client_from("203.0.113.7") as first:
        for _ in range(10):
            await _recover(first, os.urandom(32))
        assert await _recover(first, os.urandom(32)) == 429  # its window runs
    assert row["recovery_locked"] == 1

    for host in range(1, 21):
        async with _client_from(f"192.0.2.{host}") as bot:
            if host <= 3:
                assert await _recover(bot, os.urandom(32)) == 423  # verified ...
            resp = await bot.post(  # ... then even a correct guess waits
                "/api/auth/recover", json={"username": "admin", "auth_proof": proof.hex()}
            )
            assert resp.status_code == 429
            assert 1 <= int(resp.headers["Retry-After"]) <= 300
            assert "admin" in resp.json()["detail"]
    assert row["recovery_locked"] == 1

    _age_probe_slots(mock_db, 300_001)
    async with _client_from("192.0.2.50") as bot:
        assert await _recover(bot, os.urandom(32)) == 423  # next window
        assert await _recover(bot, os.urandom(32)) == 429
    async with _client_from("198.51.100.77") as owner_elsewhere:
        assert await _recover(owner_elsewhere, proof) == 200
    assert row["recovery_locked"] == 0


def _age_probe_slots(mock_db, ms: int) -> None:
    for slot in mock_db._storage.get("recovery_probe_slots", []):
        slot["probe_at"] -= ms
    for ration in mock_db._storage.get("recovery_name_rations", []):
        ration["window_started_at"] -= ms
    for user in mock_db._storage["users"]:  # the shared slot before run 83
        if user.get("recovery_probe_at"):
            user["recovery_probe_at"] -= ms


@pytest.mark.asyncio
async def test_attacker_holding_the_ration_does_not_refuse_the_owner(app_client, mock_db):
    """Capability review run 83: the locked-name ration was one slot shared by
    every network, and each wrong proof restarted it - one attacker taking the
    slot the moment it opened answered the owner's correct proof from any new
    network with 429, and re-locked the name whenever the lock expired."""
    _create_admin_user(mock_db._storage)
    row = mock_db._storage["users"][0]
    proof = _with_known_proof(row)

    async with _client_from("203.0.113.7") as attacker:
        for _ in range(10):
            await _recover(attacker, os.urandom(32))
    assert row["recovery_locked"] == 1

    owner_statuses = []
    for _ in range(5):
        _age_probe_slots(mock_db, 300_001)
        async with _client_from("192.0.2.50") as attacker:
            assert await _recover(attacker, os.urandom(32)) == 423  # takes its slot
            assert await _recover(attacker, os.urandom(32)) == 429  # ... and waits
        async with _client_from("198.51.100.77") as owner:  # never recovered here
            owner_statuses.append(await _recover(owner, proof))
        row["recovery_locked"] = 1  # the attacker locks it again at once
    assert owner_statuses == [200] * 5


@pytest.mark.asyncio
async def test_locked_name_caps_checked_guesses_across_networks(app_client, mock_db):
    """Capability review run 85: with one ration slot per network, a locked
    name verified one proof per window from EVERY network - N networks (an
    IPv6 /48 holds 65,536 /64s) got N checked guesses per window, the
    per-address rate V2 called the bug. Checked guesses on a locked name are
    now capped per window across all networks."""
    from server.app.config import ServerConfig

    cap = ServerConfig.recovery_locked_probes_per_window
    _create_admin_user(mock_db._storage)
    row = mock_db._storage["users"][0]
    _with_known_proof(row)

    async with _client_from("203.0.113.7") as first:
        for _ in range(10):
            await _recover(first, os.urandom(32))
    assert row["recovery_locked"] == 1

    checked_per_round = []
    for _ in range(3):
        _age_probe_slots(mock_db, 300_001)
        statuses = []
        for n in range(200):
            async with _client_from(f"2001:db8:0:{n:x}::1") as bot:
                statuses.append(await _recover(bot, os.urandom(32)))
        assert set(statuses) <= {423, 429}
        checked_per_round.append(statuses.count(423))
    assert checked_per_round == [cap] * 3


async def _three_networks_fill_the_ration(mock_db) -> None:
    _age_probe_slots(mock_db, 300_001)
    for host in (50, 51, 52):
        async with _client_from(f"192.0.2.{host}") as attacker:
            assert await _recover(attacker, os.urandom(32)) == 423


async def _locked_by_attacker(mock_db) -> tuple[dict, bytes]:
    row = mock_db._storage["users"][0]
    proof = _with_known_proof(row)
    async with _client_from("203.0.113.7") as attacker:
        for _ in range(10):
            await _recover(attacker, os.urandom(32))
    assert row["recovery_locked"] == 1
    return row, proof


@pytest.mark.asyncio
async def test_owner_who_logged_in_from_a_network_recovers_under_a_wide_attack(
    app_client, mock_db
):
    """Capability review run 88: three attacking networks fill the per-name
    ration each window, and only networks the owner had already RECOVERED from
    skipped it - an owner who only ever logged in with a device got 429 from
    every network. A signed device login now records its network too."""
    from tests.test_server_spec import _do_challenge_verify

    sk, _ = _create_admin_user(mock_db._storage)
    async with _client_from("198.51.100.77") as laptop:  # a normal device login
        await _do_challenge_verify(laptop, mock_db._storage, sk, "admin")
    row, proof = await _locked_by_attacker(mock_db)

    owner_statuses = []
    for _ in range(5):
        await _three_networks_fill_the_ration(mock_db)
        async with _client_from("198.51.100.77") as owner:  # e.g. the device was lost
            owner_statuses.append(await _recover(owner, proof))
        row["recovery_locked"] = 1
    assert owner_statuses == [200] * 5


@pytest.mark.asyncio
async def test_registration_network_skips_the_ration(app_client, mock_db):
    """Run 88: a new account had no network past the ration until its first
    /recover. The network it registered from (invitation redeemed there) counts
    as the owner's."""
    import json

    from tests.test_server_spec import _do_challenge_verify, _make_ed25519_keypair

    admin_sk, _ = _create_admin_user(mock_db._storage)
    async with _client_from("198.51.100.5") as admin:
        token = await _do_challenge_verify(admin, mock_db._storage, admin_sk, "admin")
        invite = await admin.post(
            "/api/users/invite", headers={"Authorization": f"Bearer {token}"}
        )
    _, pk = _make_ed25519_keypair()
    async with _client_from("2001:db8:7:7::42") as newcomer:
        resp = await newcomer.post("/api/users/register", json={
            "invitation_token": invite.json()["invitation_token"],
            "username": "newbie", "signing_pk": pk.hex(), "encryption_pk": pk.hex(),
        })
    assert resp.status_code == 200, resp.text
    row = next(u for u in mock_db._storage["users"] if u["username"] == "newbie")
    assert len(json.loads(row["recovery_trusted_nets"])) == 1


@pytest.mark.asyncio
async def test_untrusted_owner_under_a_wide_attack_is_told_to_ask_an_admin(
    app_client, mock_db
):
    """Run 88, the honest limit: any cap on checked guesses can be filled. With
    recovery_locked_probes_per_window (3) or more attacking networks, an owner
    on a network the account never used waits (429, Retry-After, admin hint);
    fewer attacking networks cannot refuse it."""
    _create_admin_user(mock_db._storage)
    row, proof = await _locked_by_attacker(mock_db)

    await _three_networks_fill_the_ration(mock_db)
    async with _client_from("198.51.100.99") as owner:  # never used by the account
        resp = await owner.post(
            "/api/auth/recover", json={"username": "admin", "auth_proof": proof.hex()}
        )
    assert resp.status_code == 429
    assert "admin" in resp.json()["detail"] and int(resp.headers["Retry-After"]) >= 1

    _age_probe_slots(mock_db, 300_001)
    for host in (50, 51):  # two networks: one slot of the three stays free
        async with _client_from(f"192.0.2.{host}") as attacker:
            assert await _recover(attacker, os.urandom(32)) == 423
    async with _client_from("198.51.100.99") as owner:
        assert await _recover(owner, proof) == 200
    assert row["recovery_locked"] == 0


@pytest.mark.asyncio
async def test_ipv6_addresses_of_one_host_share_the_address_limit(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    for host in range(10):
        async with _client_from(f"2001:db8:1:2::{host + 1:x}") as attacker:
            assert await _recover(attacker, os.urandom(32), f"ghost{host}") == 401
    async with _client_from("2001:db8:1:2::ff") as attacker:
        assert await _recover(attacker, os.urandom(32), "ghost") == 429
    async with _client_from("2001:db8:1:3::1") as neighbour:
        assert await _recover(neighbour, os.urandom(32), "ghost") == 401


@pytest.mark.asyncio
async def test_correct_proofs_while_pending_do_not_lock_the_address(app_client, mock_db):
    """Capability review run 49: the web approval wait polled /recover every 5 s
    with the correct proof; each poll of the pending account counted as a failed
    recovery, so after ~50 s the address got 429 and the approved owner (and
    everyone behind the same NAT) stayed locked out for an hour."""
    _create_admin_user(mock_db._storage)
    row = mock_db._storage["users"][0]
    proof = _with_known_proof(row)
    row["status"] = "pending"
    _create_admin_user(mock_db._storage, user_id="01HSECONDUSER0000000000000", username="other")
    other = mock_db._storage["users"][1]
    other_proof = _with_known_proof(other)

    async with _client_from("198.51.100.20") as owner:
        polls = [await _recover(owner, proof) for _ in range(12)]
        assert polls == [401] * 12  # still pending: indistinguishable from a wrong proof
        row["status"] = "active"  # admin approves
        assert await _recover(owner, proof) == 200
        assert await _recover(owner, other_proof, "other") == 200


@pytest.mark.asyncio
async def test_wrong_proofs_against_a_pending_account_still_count(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    row = mock_db._storage["users"][0]
    _with_known_proof(row)
    row["status"] = "pending"
    async with _client_from("203.0.113.7") as attacker:
        statuses = [await _recover(attacker, os.urandom(32)) for _ in range(11)]
    assert statuses[-1] == 429


@pytest.mark.asyncio
async def test_address_window_expires(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    async with _client_from("203.0.113.7") as client:
        for n in range(10):
            await _recover(client, os.urandom(32), f"ghost{n}")
        assert await _recover(client, os.urandom(32), "ghost") == 429
        for limit in mock_db._storage["recovery_ip_limits"]:
            limit["window_started_at"] -= 3_600_001
        assert await _recover(client, os.urandom(32), "ghost") == 401
