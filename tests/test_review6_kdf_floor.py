"""Review main@d615826: the server could force cheap KDF params.

A server announcing a password change made elsewhere (new salt, higher
key_epoch) also names the KDF params. The desktop derived the password with
whatever it got, so a server offering cheap params received an auth proof it
could crack offline. The web's hard floor (spec 7.2) now applies, lowered only
to params this vault itself was created with.
"""

from __future__ import annotations

import json

import pytest

from sezam.vault.crud import server_account_kdf


class _Meta:
    def __init__(self, salt, params):
        self._meta = {"argon2_salt": salt, "argon2_params": json.dumps(params)}

    def get_meta(self, key):
        return self._meta.get(key)

    def get_meta_json(self, key):
        value = self._meta.get(key)
        return json.loads(value) if value else None


LOCAL = {"time_cost": 3, "memory_cost": 262144, "parallelism": 4, "hash_len": 64}


def _server(time_cost, memory_cost, salt="bb" * 16):
    return {"argon2_salt": salt, "argon2_params": {
        "time_cost": time_cost, "memory_cost": memory_cost, "parallelism": 1, "hash_len": 64,
    }}


@pytest.mark.parametrize("time_cost, memory_cost", [(1, 262144), (3, 8192)])
def test_cheap_params_for_new_key_material_are_refused(time_cost, memory_cost):
    with pytest.raises(RuntimeError, match="below the minimum"):
        server_account_kdf(_server(time_cost, memory_cost), _Meta("aa" * 16, LOCAL))
    with pytest.raises(RuntimeError, match="below the minimum"):
        server_account_kdf(_server(time_cost, memory_cost))


def test_the_mobile_and_web_profiles_still_open_the_account():
    for time_cost, memory_cost in [(2, 131072), (2, 65536)]:
        params = server_account_kdf(_server(time_cost, memory_cost), _Meta("aa" * 16, LOCAL))
        assert (params.time_cost, params.memory_cost) == (time_cost, memory_cost)


def test_a_vault_made_with_lighter_params_accepts_those():
    light = {"time_cost": 1, "memory_cost": 8192, "parallelism": 1, "hash_len": 64}
    params = server_account_kdf(_server(1, 8192), _Meta("aa" * 16, light))
    assert (params.time_cost, params.memory_cost) == (1, 8192)
