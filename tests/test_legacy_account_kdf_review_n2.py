"""Lockout review N2: accounts stored before per-account KDF params.

Such an account has argon2_params NULL on the server, which /api/meta reports
as the 128 MiB default. Every client then derived with it blindly, so an
account the desktop created with other params opened on no other device:
the proof never matched and the user only ever saw "wrong password".

Now the device that holds the key material reports the real params (signed
challenge, current salt only, NULL only), the first proof that matches stores
the params it was derived with, key material is never stored without params,
and a client with the same salt locally uses its own params instead of the
server's guess.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from sezam import cli
from sezam.crypto.kdf import Argon2Params, derive_kek_and_proof
from sezam.vault import crud
from sezam.vault.crud import Vault, recover_with_password
from sezam.vault.sync_client import SyncClient
from server.app.models.schemas import KeypairUploadRequest
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401
from tests.node_support import node_cmd, requires_node

# Not the server default (3 / 128 MiB / 4) and cheap enough for tests.
LAPTOP = Argon2Params(time_cost=2, memory_cost=65_536, parallelism=2)
# Module attributes are read inside the tests so they fail (not error) on old code.
KDF_REPORTED_META_KEY = "kdf_params_reported_salt"
APP_JS = Path(__file__).resolve().parents[1] / "web" / "static" / "js" / "app.js"


def _connected_laptop(url, db, path):
    """Laptop vault on the server; ``user()`` reads its current server row
    (a rolled-back request replaces the mock's row objects)."""
    laptop = Vault.create(path, PASSWORD, LAPTOP)
    laptop.db.set_meta("username", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    user_id = laptop.db.get_meta("user_id")
    return laptop, lambda: next(u for u in db._storage["users"] if u["id"] == user_id)


def _make_legacy(laptop: Vault, user) -> None:
    """Server row and laptop as they were before per-account params."""
    user()["argon2_params"] = None
    laptop.db.execute("DELETE FROM vault_meta WHERE key = ?", (KDF_REPORTED_META_KEY,))


def _client(vault: Vault, url: str) -> SyncClient:
    client = SyncClient(vault.db, url, vault.keypair, vault.db.get_meta("user_id"))
    client.set_dek_manager(vault.dek_mgr)
    client.authenticate()
    return client


def _stored(user) -> dict | None:
    return json.loads(user["argon2_params"]) if user.get("argon2_params") else None


def test_desktop_reports_the_params_of_a_legacy_account_and_a_new_device_logs_in(
    server, tmp_path  # noqa: F811
):
    url, db = server
    laptop, user = _connected_laptop(url, db, tmp_path / "laptop")
    _make_legacy(laptop, user)
    meta = SyncClient(laptop.db, url, laptop.keypair, "")._request(
        "GET", "/api/meta?username=admin"
    )
    assert meta["argon2_params"]["memory_cost"] == 131_072  # the blind guess

    _client(laptop, url)
    assert _stored(user()) == LAPTOP.account_dict()
    assert laptop.db.get_meta(KDF_REPORTED_META_KEY) == laptop.db.get_meta("argon2_salt")

    # A brand-new device now derives with the real params and gets in.
    phone = Vault.create(tmp_path / "phone", PASSWORD, Argon2Params())
    phone.db.set_meta("username", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    assert phone.db.get_meta("user_id") == laptop.db.get_meta("user_id")
    assert phone.keypair.signing_pk == laptop.keypair.signing_pk
    laptop.lock()
    phone.lock()


def test_first_matching_proof_stores_its_params_and_stored_ones_never_move(
    server, tmp_path  # noqa: F811
):
    url, db = server
    laptop, user = _connected_laptop(url, db, tmp_path / "laptop")
    salt = bytes.fromhex(laptop.db.get_meta("argon2_salt"))
    request = SyncClient(laptop.db, url, laptop.keypair, "")._request

    def post(body):
        return request("POST", "/api/auth/recover", body)

    user()["argon2_params"] = None
    kek, resp = recover_with_password(post, "admin", PASSWORD, salt, LAPTOP)
    kek[:] = b"\x00" * len(kek)
    assert _stored(user()) == LAPTOP.account_dict()
    assert resp["argon2_params"] == LAPTOP.account_dict()

    # A correct proof claiming other params changes nothing once stored.
    kek, proof = derive_kek_and_proof(PASSWORD, salt, LAPTOP, exact=True)
    kek[:] = b"\x00" * len(kek)
    other = {"time_cost": 3, "memory_cost": 131_072, "parallelism": 4, "hash_len": 64}
    resp = post({"username": "admin", "auth_proof": proof.hex(), "argon2_params": other})
    assert _stored(user()) == LAPTOP.account_dict()
    assert resp["argon2_params"] == LAPTOP.account_dict()

    # A wrong proof stores nothing.
    user()["argon2_params"] = None
    with pytest.raises(RuntimeError, match="Server error 401"):
        recover_with_password(post, "admin", "not-the-password", salt, LAPTOP)
    assert user()["argon2_params"] is None
    laptop.lock()


def test_backfill_needs_the_current_salt_and_never_replaces_params(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, user = _connected_laptop(url, db, tmp_path / "laptop")
    client = _client(laptop, url)
    params = LAPTOP.account_dict()

    def put(salt_hex, kdf, signed=True):
        body = {"argon2_salt": salt_hex, "argon2_params": kdf}
        if signed:
            body["challenge"], body["signature"] = client._signed_challenge()
        return client._request("PUT", "/api/me/kdf-params", body, auth=True)

    salt_hex = laptop.db.get_meta("argon2_salt")
    user()["argon2_params"] = None
    with pytest.raises(RuntimeError, match="Server error 409"):
        put("ab" * 16, params)
    with pytest.raises(RuntimeError, match="Server error 422"):
        put(salt_hex, params, signed=False)
    assert user()["argon2_params"] is None

    other = {"time_cost": 3, "memory_cost": 131_072, "parallelism": 4, "hash_len": 64}
    user()["argon2_params"] = json.dumps(other)
    with pytest.raises(RuntimeError, match="Server error 409"):
        put(salt_hex, params)
    assert _stored(user()) == other
    assert put(salt_hex, other)["status"] == "ok"
    laptop.lock()


def test_key_material_is_never_stored_without_params():
    body = {
        "encrypted_keypair": "00" * 80,
        "argon2_salt": "11" * 16,
        "auth_salt": "22" * 16,
        "auth_proof": "33" * 32,
    }
    # Review 688edcb N2: the schema lets it through so the routers can refuse
    # it with 426 and a reason (tests/test_old_client_kdf_params_n2b.py).
    from fastapi import HTTPException

    from server.app.routers.auth import require_kdf_params_json

    with pytest.raises(HTTPException) as refused:
        require_kdf_params_json(KeypairUploadRequest(**body).argon2_params)
    assert refused.value.status_code == 426


def test_local_params_of_the_same_salt_beat_the_server_guess(tmp_path):
    vault = Vault.create(tmp_path / "v", PASSWORD, LAPTOP)
    salt = vault.db.get_meta("argon2_salt")
    guess = {"time_cost": 3, "memory_cost": 131_072, "parallelism": 4, "hash_len": 64}
    assert crud.server_account_kdf({"argon2_salt": salt.upper(), "argon2_params": guess}, vault.db) == LAPTOP
    # Other key material (password changed elsewhere): the server's params.
    other = crud.server_account_kdf({"argon2_salt": "ab" * 16, "argon2_params": guess}, vault.db)
    assert other.memory_cost == 131_072
    with pytest.raises(RuntimeError, match="KDF parameters"):
        crud.server_account_kdf({"argon2_salt": "ab" * 16}, vault.db)
    vault.lock()


# ── web ──


def _function(src: str, name: str) -> str:
    import re

    match = re.search(rf"^(async )?function {name}\(", src, re.M)
    assert match, name
    end = re.search(r"^(async )?function |^// ── ", src[match.end():], re.M)
    return src[match.start(): match.end() + (end.start() if end else len(src))]


@requires_node
def test_web_refuses_missing_params_and_sends_the_derived_ones_to_recover():
    src = APP_JS.read_text(encoding="utf-8")
    functions = "\n".join(
        _function(src, name)
        for name in (
            "normalizeKdfParams", "accountKdfParams", "deriveKEK", "openLoginKeypair",
            "deriveLoginKey", "recoverError",
        )
    )
    script = f"""
const ARGON2_HARD_FLOOR = {{ time: 2, mem: 65536, parallelism: 1 }};
const ARGON2_ACCOUNT_MAX = {{ time: 20, mem: 262144, parallelism: 8 }};
async function deriveKEKViaWorker() {{ return new Uint8Array(64); }}
const bytesToHex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const hexToBytes = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
const t = key => key;
function recoverFailureMessage() {{ return 'other'; }}
async function loadFromIndexedDB() {{ return null; }}
async function saveToIndexedDB() {{}}
const bodies = [];
async function apiFetch(path, options) {{
  bodies.push(options.body);
  return {{ encrypted_keypair: 'aa', user_id: 'U1' }};
}}
function decryptLoginKeypair() {{ return {{ keypairBytes: new Uint8Array(96), confirmedGenesis: null }}; }}
const sodium = {{ memzero(b) {{ b.fill(0); }} }};
{functions}
(async () => {{
  const out = {{}};
  try {{ accountKdfParams({{ argon2_salt: '00'.repeat(16) }}); out.missing = 'ok'; }}
  catch (e) {{ out.missing = e.message; }}
  const params = {{ time_cost: 2, memory_cost: 65536, parallelism: 2 }};
  await openLoginKeypair('admin', 'pw', {{ argon2_salt: '00'.repeat(16), argon2_params: params }},
                         null, sodium);
  out.body = bodies[0];
  console.log(JSON.stringify(out));
}})().catch(e => {{ console.error(e); process.exit(1); }});
"""
    proc = subprocess.run(
        [node_cmd(), "-e", script], capture_output=True, text=True, encoding="utf-8", timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["missing"] == "error.kdf_params_unsupported"
    assert out["body"]["argon2_params"] == {
        "time_cost": 2, "memory_cost": 65536, "parallelism": 2, "hash_len": 64,
    }
