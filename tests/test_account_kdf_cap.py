"""Lockout review #6: one Argon2 memory cap for the server and every client.

The server accepted account params up to 1 GiB, but mobile only derives up to
256 MiB: an account stored with more locked every mobile unlock out (its
keypair journal was written, then refused on every unlock).
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from server.app.models.schemas import (
    KeypairUploadRequest,
    account_kdf_params,
)


def _upload(memory_cost: int) -> dict:
    return {
        "encrypted_keypair": "00" * 80,
        "argon2_salt": "11" * 16,
        "auth_salt": "22" * 16,
        "auth_proof": "33" * 32,
        "argon2_params": {"time_cost": 3, "memory_cost": memory_cost, "parallelism": 4},
    }


def test_key_material_above_256_mib_is_refused():
    assert KeypairUploadRequest(**_upload(262_144)).argon2_params.memory_cost == 262_144
    with pytest.raises(ValidationError):
        KeypairUploadRequest(**_upload(262_145))
    with pytest.raises(ValidationError):
        KeypairUploadRequest(**_upload(1_048_576))


def test_params_stored_before_the_cap_are_still_reported_as_stored():
    """Any other value would derive a KEK that opens nothing."""
    stored = json.dumps({"time_cost": 3, "memory_cost": 524_288, "parallelism": 4, "hash_len": 64})
    assert account_kdf_params(stored)["memory_cost"] == 524_288
