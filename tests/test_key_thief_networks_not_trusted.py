"""Review e4cd15a (low): /auth/verify made a key thief's networks trusted.

Capability run 88 counted the network of every signed device login as the
owner's, so it skipped the locked-name ration. A signed login proves only the
identity key, which a thief has too: each network the thief signed in from
went on verifying the thief's password guesses on a locked name. Now a
network that guesses wrong on a locked name loses the trust, and a signed
login while the name is locked adds none.
"""

from __future__ import annotations

import os

import pytest

from tests.test_recover_lockout_dos import (
    _client_from,
    _locked_by_attacker,
    _recover,
    _three_networks_fill_the_ration,
)
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _do_challenge_verify,
    app_client,
    mock_db,
)


@pytest.mark.asyncio
async def test_guessing_network_loses_the_trust_its_signed_login_gave(app_client, mock_db):
    sk, _ = _create_admin_user(mock_db._storage)
    async with _client_from("198.51.100.66") as thief:  # signs in with the stolen key
        await _do_challenge_verify(thief, mock_db._storage, sk, "admin")
    row, proof = await _locked_by_attacker(mock_db)

    async with _client_from("198.51.100.66") as thief:
        # Review 526419e N4: three wrong proofs, not the first, take the trust.
        for _ in range(3):
            assert await _recover(thief, os.urandom(32)) == 423
        assert await _recover(thief, os.urandom(32)) == 429  # no longer trusted
        assert await _recover(thief, proof) == 429


@pytest.mark.asyncio
async def test_owner_typo_at_home_during_an_attack_keeps_the_trust(app_client, mock_db):
    """Review 526419e N4: one typo on the owner's home network while attackers
    hold the name locked took the home network's trust, and the attackers'
    ration then refused the owner's correct password at home as well."""
    sk, _ = _create_admin_user(mock_db._storage)
    async with _client_from("198.51.100.88") as laptop:
        await _do_challenge_verify(laptop, mock_db._storage, sk, "admin")
    row, proof = await _locked_by_attacker(mock_db)
    await _three_networks_fill_the_ration(mock_db)

    async with _client_from("198.51.100.88") as owner:
        assert await _recover(owner, os.urandom(32)) == 423  # the typo
        assert await _recover(owner, proof) == 200


@pytest.mark.asyncio
async def test_correct_proof_clears_the_wrong_ones(app_client, mock_db):
    """Strikes do not add up across the owner's occasional typos."""
    sk, _ = _create_admin_user(mock_db._storage)
    async with _client_from("198.51.100.89") as laptop:
        await _do_challenge_verify(laptop, mock_db._storage, sk, "admin")
    row, proof = await _locked_by_attacker(mock_db)
    async with _client_from("198.51.100.89") as owner:
        for _ in range(2):
            assert await _recover(owner, os.urandom(32)) == 423
        assert await _recover(owner, proof) == 200
    row, proof = await _locked_by_attacker(mock_db)
    await _three_networks_fill_the_ration(mock_db)
    async with _client_from("198.51.100.89") as owner:
        for _ in range(2):
            assert await _recover(owner, os.urandom(32)) == 423
        assert await _recover(owner, proof) == 200


@pytest.mark.asyncio
async def test_signed_login_on_a_locked_name_adds_no_trust(app_client, mock_db):
    sk, _ = _create_admin_user(mock_db._storage)
    row, proof = await _locked_by_attacker(mock_db)
    async with _client_from("198.51.100.67") as thief:
        await _do_challenge_verify(thief, mock_db._storage, sk, "admin")
        assert await _recover(thief, os.urandom(32)) == 423
        assert await _recover(thief, os.urandom(32)) == 429


@pytest.mark.asyncio
async def test_owner_network_keeps_its_trust_while_unlocked(app_client, mock_db):
    """The owner's typos before any lock do not cost the network its trust."""
    sk, _ = _create_admin_user(mock_db._storage)
    async with _client_from("198.51.100.77") as laptop:
        await _do_challenge_verify(laptop, mock_db._storage, sk, "admin")
        assert await _recover(laptop, os.urandom(32)) == 401
    row, proof = await _locked_by_attacker(mock_db)
    await _three_networks_fill_the_ration(mock_db)
    async with _client_from("198.51.100.77") as owner:
        assert await _recover(owner, proof) == 200
