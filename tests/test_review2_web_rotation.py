"""Review 2052248 #1 on the web client (R-C4).

The web KEK rotation (org recovery) pushed the re-wrapped DEKs and replaced
the key material with two separate requests and never advanced key_epoch, so
the other devices never noticed and an interruption left DEKs under a key the
server no longer vouched for. It must use the single rotation push, and a
running session must notice a rotation made elsewhere.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess

import pytest
from nacl.signing import SigningKey

from sezam import cli
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)
from tests.test_review_web import APP, SYNC_CORE_JS, VENDOR, _function
from tests.node_support import node_cmd, requires_node

pytestmark = requires_node

NEW_PASSWORD = "web-rotated-pw!"

HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const { webcrypto } = require('crypto');
const input = JSON.parse(Buffer.from(process.argv[4], 'base64').toString('utf8'));
let realFetch = fetch;
const context = {
  crypto: webcrypto, console, Uint8Array, TextEncoder, TextDecoder, Buffer, Promise, JSON,
  Number, Map, Set, Math, Error, WebAssembly, setTimeout, clearTimeout, AbortSignal,
  atob: value => Buffer.from(value, 'base64').toString('binary'),
  API_BASE: input.url,
  fetch: (url, opts) => {
    if (input.dropSync && opts && opts.method === 'POST' && url.endsWith('/api/sync')) {
      return Promise.reject(new Error('network down'));
    }
    return realFetch(url, opts);
  },
  t: key => key,
  refreshJWT: async () => false,
  clearKekRotationJournal: async () => { context.cleared = true; },
};
context.window = context; context.self = context; context.globalThis = context;
context.bytesToHex = value => Buffer.from(value).toString('hex');
vm.createContext(context);
for (const path of process.argv.slice(1, 3)) vm.runInContext(fs.readFileSync(path, 'utf8'), context);
vm.runInContext(Buffer.from(process.argv[3], 'base64').toString('utf8'), context);
(async () => {
  await context.sodium.ready;
  context.state = input.state;
  const hex = value => Uint8Array.from(Buffer.from(value, 'hex'));
  let error = null;
  try {
    await context.applyKekRotationJournal(
      input.journal, hex(input.authProof), hex(input.signingSk), context.sodium,
      input.recoverySk ? hex(input.recoverySk) : null
    );
  } catch (err) {
    error = err.message;
    context.errorName = err.name;
  }
  console.log(JSON.stringify({
    error, token: context.state.token, keyEpoch: context.state.keyEpoch,
    cleared: !!context.cleared, errorName: context.errorName || null,
  }));
})().catch(error => { console.error(error); process.exit(1); });
"""


def _api_fetch() -> str:
    """apiFetch has a default ``options = {}`` the generic extractor trips on."""
    timeout = APP.index("const WEB_FETCH_TIMEOUT_MS")
    timeout_source = APP[timeout:APP.index("\n}\n", timeout) + 2] + "\n"
    start = APP.index("async function apiFetch(")
    depth = 0
    for index in range(APP.index(") {", start) + 2, len(APP)):
        depth += {"{": 1, "}": -1}.get(APP[index], 0)
        if depth == 0:
            return timeout_source + APP[start:index + 1]
    raise AssertionError("apiFetch")


def _apply(url: str, journal: dict, auth_proof: str, signing_sk: str, token: str,
           drop_sync: bool = False, recovery_sk: str | None = None) -> dict:
    typed_error = "class KeyEpochChangedError" + APP.split(
        "class KeyEpochChangedError", 1
    )[1].split("function endSessionForKeyEpochChange", 1)[0]
    helpers = "\n".join([
        typed_error, "function assertSyncUnitFits() {}",
        "const MAX_PUSH_OBJECTS = 1000; const MAX_PUSH_REQUEST_BYTES = 15 * 1024 * 1024;",
        _function("splitForPush"), _function("postAtomicSyncBatch"),
        _function("applyKekRotationJournal"), _api_fetch(),
        _function("hexToBytes"), _function("signAuthChallenge"),
    ])
    payload = json.dumps({
        "url": url, "journal": journal, "authProof": auth_proof, "signingSk": signing_sk,
        "state": {"token": token, "keyEpoch": 0}, "dropSync": drop_sync,
        "recoverySk": recovery_sk,
    })
    out = subprocess.run(
        [
            node_cmd(), "-e", HARNESS,
            str(VENDOR / "libsodium-sumo.min.js"),
            str(VENDOR / "libsodium-wrappers.min.js"),
            base64.b64encode(helpers.encode()).decode(),
            base64.b64encode(payload.encode()).decode(),
        ],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_web_rotation_is_one_resendable_push_other_devices_follow(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    user_id = laptop.db.get_meta("user_id")

    def server_user():
        return next(u for u in db._storage["users"] if u["id"] == user_id)

    def server_epoch():
        return next(s for s in db._storage["sync_state"] if s["user_id"] == user_id)["key_epoch"]

    # The web journal: DEKs re-wrapped under the new KEK and the new key
    # material (built here with the desktop crypto; the web code under test
    # is the protocol that sends it).
    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    client = _client(laptop, url)
    deks = [o for o in client._collect_dirty_objects() if o["object_type"] == "dek"]
    material = client._key_rotation_payload(1)
    journal = {
        "username": "admin",
        "user_id": user_id,
        "argon2_salt": material["argon2_salt"],
        "argon2_params": material["argon2_params"],
        "encrypted_keypair": material["encrypted_keypair"],
        "deks": deks,
        "key_epoch": 1,
        "recovery_store": None,
    }
    # libsodium's 64-byte Ed25519 secret key: seed || public key.
    signing_sk = (bytes(laptop.keypair.signing_sk) + laptop.keypair.signing_pk).hex()
    old_keypair = server_user()["encrypted_keypair"]
    # The web rotates only in org recovery, without the old password: the
    # server takes it on proof of the reconstructed recovery key (688edcb K1).
    recovery_key = SigningKey.generate()
    db._storage["org_recovery_blobs"].append({
        "id": 1, "wrapped_kek": b"", "recovery_signing_pk": bytes(recovery_key.verify_key),
        "threshold": 2, "total_shares": 3, "created_by": user_id, "created_at": 0,
        "key_epoch": 0,
    })
    recovery_sk = (bytes(recovery_key) + bytes(recovery_key.verify_key)).hex()

    refused = _apply(url, journal, material["auth_proof"], signing_sk, client.token)
    assert "key reset" in refused["error"], refused
    assert server_user()["encrypted_keypair"] == old_keypair

    failed = _apply(url, journal, material["auth_proof"], signing_sk, client.token,
                    drop_sync=True, recovery_sk=recovery_sk)
    assert failed["error"] == "network down" and not failed["cleared"]
    assert server_user()["encrypted_keypair"] == old_keypair
    assert server_epoch() == 0

    done = _apply(url, journal, material["auth_proof"], signing_sk, client.token,
                  recovery_sk=recovery_sk)
    assert done["error"] is None and done["cleared"], done
    assert done["keyEpoch"] == 1 and done["token"] != client.token
    assert server_epoch() == 1
    assert bytes(server_user()["encrypted_keypair"]).hex() == material["encrypted_keypair"]

    # The response was lost: resending the journal is harmless.
    again = _apply(url, journal, material["auth_proof"], signing_sk, done["token"])
    assert again["error"] is None, again
    assert server_epoch() == 1

    # Another device signs in with the new password and reads everything.
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, NEW_PASSWORD)
    assert phone.db.get_meta("key_epoch") == "1"
    assert _entry_value(phone, "Servers", "db01", "password") == "s3cret"
    phone.lock()
    laptop.lock()


def test_web_rotation_that_lost_to_another_device_is_dropped(server, tmp_path):  # noqa: F811
    """Capability finding (run 10): rival rotations from the same epoch.

    The desktop changed the password first (epoch 1); the web's org-recovery
    rotation also targets epoch 1. It used to fail with a raw 409 on every
    replay and the journal stayed. Now it is a typed key-epoch change, the
    journal is dropped and the server keeps the winner's key material.
    """
    from tests.test_integration_client_server import _rotate_on_laptop

    url, db = server
    laptop, web_device = _rotate_on_laptop(url, tmp_path)
    user_id = laptop.db.get_meta("user_id")
    winner = bytes(
        next(u for u in db._storage["users"] if u["id"] == user_id)["encrypted_keypair"]
    )

    proof = web_device.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    client = _client(web_device, url)
    deks = [o for o in client._collect_dirty_objects() if o["object_type"] == "dek"]
    material = client._key_rotation_payload(1)
    journal = {
        "username": "admin", "user_id": user_id,
        "argon2_salt": material["argon2_salt"], "argon2_params": material["argon2_params"],
        "encrypted_keypair": material["encrypted_keypair"], "deks": deks,
        "key_epoch": 1, "recovery_store": None,
    }
    signing_sk = (bytes(web_device.keypair.signing_sk) + web_device.keypair.signing_pk).hex()

    lost = _apply(url, journal, material["auth_proof"], signing_sk, client.token)
    assert lost["errorName"] == "KeyEpochChangedError", lost
    assert lost["error"] == "error.key_epoch_changed" and lost["cleared"]
    assert bytes(
        next(u for u in db._storage["users"] if u["id"] == user_id)["encrypted_keypair"]
    ) == winner
    web_device.lock()
    laptop.lock()


SESSION_HARNESS = r"""
const vm = require('vm');
const input = JSON.parse(Buffer.from(process.argv[1], 'base64').toString('utf8'));
const context = { console, Promise, Number, JSON, Error, TextEncoder, TextDecoder, atob };
context.globalThis = context;
vm.createContext(context);
// The page loads the shared sync core before app.js.
vm.runInContext(require('fs').readFileSync(process.argv[2], 'utf8'), context);
vm.runInContext(require('fs').readFileSync(0, 'utf8'), context);
context.state = input.state;
context.ensureSodium = async () => ({});
context.apiFetch = async () => ({ objects: [], key_epoch: input.serverEpoch, max_commit_seq: 3 });
context.t = key => key;
context.endSessionForKeyEpochChange = () => { context.ended = true; };
(async () => {
  let error = null;
  try { await context.pullAndBuildTreeLocked(); } catch (err) { error = err.message; }
  console.log(JSON.stringify({ error, ended: !!context.ended }));
})();
"""


def _pull(state: dict, server_epoch: int) -> dict:
    payload = json.dumps({"state": state, "serverEpoch": server_epoch})
    out = subprocess.run(
        [
            node_cmd(), "-e", SESSION_HARNESS,
            base64.b64encode(payload.encode()).decode(),
            str(SYNC_CORE_JS),
        ],
        input=_function("pullAndBuildTreeLocked"), encoding="utf-8",
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_running_web_session_ends_when_the_key_epoch_moves_elsewhere():
    base = {"syncCheckpointLoaded": True, "outboxLoaded": True, "lastCommitSeq": 3}
    running = _pull({**base, "syncObjects": {}, "keyEpoch": 1}, server_epoch=2)
    assert running == {"error": "error.key_epoch_changed", "ended": True}

    # The first pull of a login takes the epoch of the KEK it just derived.
    login = _pull({**base, "syncObjects": None, "keyEpoch": 0}, server_epoch=2)
    assert not login["ended"] and login["error"] != "error.key_epoch_changed"
