"""Lockout review M8: the master password is normalized to NFC on every client.

The KDF took the password's UTF-8 bytes as they came. The same visible
password typed as "é" (U+00E9) on one device and as "e" + U+0301 on another
(another keyboard, OS or a paste) derived different KEKs: the account did not
open on the other client. Desktop, web and mobile now derive from NFC. A vault
or account created before the change derived from the typed form, so an
existing password is also tried as typed and decomposed (NFD).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import unicodedata
from pathlib import Path

import pytest

from sezam.crypto import kdf
from sezam.crypto.kdf import Argon2Params, _derive_material
from sezam.vault.crud import Vault
from tests.node_support import node_cmd, requires_node

FAST = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
NFC = "Žltý kôň úpel ďábelské ódy"
NFD = unicodedata.normalize("NFD", NFC)
ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "web" / "static" / "js" / "app.js"


def test_forms_differ():
    assert NFC != NFD and unicodedata.normalize("NFC", NFD) == NFC


def test_both_forms_derive_the_same_kek():
    salt = bytes(16)
    assert kdf.derive_kek(NFD, salt, FAST) == kdf.derive_kek(NFC, salt, FAST)
    assert bytes(kdf.derive_kek(NFD, salt, FAST)) == bytes(_derive_material(NFC, salt, FAST)[:32])


def test_a_new_vault_opens_with_either_form(tmp_path):
    Vault.create(tmp_path / "v", NFC, FAST).lock()
    vault = Vault(tmp_path / "v")
    vault.unlock(NFD)
    assert vault.verify_password(NFC) and vault.verify_password(NFD)
    vault.lock()


@pytest.fixture
def legacy_vault(tmp_path, monkeypatch):
    """A vault created before normalization, from a decomposed password."""
    with monkeypatch.context() as m:
        m.setattr(kdf, "canonical_password", lambda p: p, raising=False)
        Vault.create(tmp_path / "legacy", NFD, FAST).lock()
    return tmp_path / "legacy"


def test_a_vault_from_before_normalization_still_opens(legacy_vault):
    for typed in (NFD, NFC):
        vault = Vault(legacy_vault)
        vault.unlock(typed)
        vault.lock()
    vault = Vault(legacy_vault)
    vault.unlock(NFC)
    vault.change_password(NFC, "nove heslo")
    vault.lock()
    vault = Vault(legacy_vault)
    vault.unlock("nove heslo")
    vault.lock()
    with pytest.raises(ValueError, match="Wrong master password"):
        Vault(legacy_vault).unlock("Zlty kon")


def test_the_uploaded_proof_matches_the_form_that_opens_the_keypair(legacy_vault):
    from sezam.vault.onboarding import keypair_upload_body

    vault = Vault(legacy_vault)
    vault.unlock(NFC)
    try:
        body = keypair_upload_body(vault, NFC)
    finally:
        vault.lock()
    expected = _derive_material(NFD, bytes.fromhex(body["argon2_salt"]), FAST)[32:]
    assert body["auth_proof"] == bytes(expected).hex()


def test_recover_tries_the_other_forms_only_after_a_401():
    from sezam.vault.crud import recover_with_password
    from sezam.vault.sync_common import ServerError

    salt = bytes(16)
    legacy_proof = bytes(_derive_material(NFD, salt, FAST)[32:]).hex()
    sent = []

    def post(body):
        sent.append(body["auth_proof"])
        if body["auth_proof"] != legacy_proof:
            raise ServerError(401, "Invalid auth proof")
        return {"user_id": "U"}

    kek, resp = recover_with_password(post, "admin", NFC, salt, FAST)
    assert resp == {"user_id": "U"} and len(sent) == 2
    assert bytes(kek) == bytes(_derive_material(NFD, salt, FAST)[:32])

    sent.clear()

    def throttled(body):
        sent.append(body)
        raise ServerError(429, "Too many attempts")

    with pytest.raises(RuntimeError, match="429"):
        recover_with_password(throttled, "admin", NFC, salt, FAST)
    assert len(sent) == 1


def test_an_ascii_password_is_derived_once():
    assert kdf.password_forms("plain-ascii-1") == ["plain-ascii-1"]
    assert kdf.password_forms(NFD) == [NFC, NFD]


# ── web ──


def _function(src: str, name: str) -> str:
    match = re.search(rf"^(async )?function {name}\(", src, re.M)
    assert match, name
    end = re.search(r"^(async )?function |^// ── ", src[match.end():], re.M)
    return src[match.start(): match.end() + (end.start() if end else len(src))]


@requires_node
def test_web_derives_from_nfc_and_login_retries_the_legacy_form():
    src = APP_JS.read_text(encoding="utf-8")
    functions = "\n".join(
        _function(src, name)
        for name in (
            "canonicalPassword", "passwordForms", "normalizeKdfParams", "accountKdfParams",
            "deriveKEK", "openLoginKeypair", "deriveLoginKey", "recoverError",
        )
    )
    script = f"""
const ARGON2_HARD_FLOOR = {{ time: 2, mem: 65536, parallelism: 1 }};
const ARGON2_ACCOUNT_MAX = {{ time: 20, mem: 262144, parallelism: 8 }};
const derivedFrom = [];
// Stand-in KDF: 64 bytes that depend only on the exact password bytes.
async function deriveKEKViaWorker(password) {{
  derivedFrom.push(password);
  const bytes = new TextEncoder().encode(password);
  const out = new Uint8Array(64);
  bytes.forEach((b, i) => {{ out[i % 64] = (out[i % 64] * 31 + b) & 255; }});
  return out;
}}
const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const bytesToHex = hex;
const hexToBytes = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
const t = key => key;
function recoverFailureMessage(err) {{ return err.status === 401 ? 'error.wrong_password' : 'other'; }}
const NFD = {json.dumps(NFD)};
let legacyProof = null;
async function loadFromIndexedDB() {{ return null; }}
async function saveToIndexedDB() {{}}
async function apiFetch(path, options) {{
  if (options.body.auth_proof !== legacyProof) {{
    const e = new Error('Invalid auth proof'); e.status = 401; throw e;
  }}
  return {{ encrypted_keypair: 'aa', user_id: 'U1' }};
}}
function decryptLoginKeypair() {{ return {{ keypairBytes: new Uint8Array(96), confirmedGenesis: null }}; }}
const sodium = {{ memzero(b) {{ b.fill(0); }} }};
{functions}
(async () => {{
  const legacy = await deriveKEKViaWorker(NFD);
  legacyProof = hex(legacy.subarray(32, 64));
  derivedFrom.length = 0;
  const meta = {{ argon2_salt: '00'.repeat(16), argon2_params: {{ time_cost: 2, memory_cost: 65536, parallelism: 1 }} }};
  const out = {{ forms: passwordForms(NFD) }};
  await deriveKEK(NFD, new Uint8Array(16), null);
  out.canonicalInput = derivedFrom.pop();
  try {{
    await openLoginKeypair('admin', out.forms[0], meta, null, sodium);
  }} catch (e) {{
    out.firstWrongPassword = e.wrongPassword === true;
  }}
  const opened = await openLoginKeypair('admin', out.forms[1], meta, null, sodium);
  out.secondOpened = opened.keypairBytes.length === 96;
  out.inputs = derivedFrom;
  console.log(JSON.stringify(out));
}})().catch(e => {{ console.error(e); process.exit(1); }});
"""
    proc = subprocess.run(
        [node_cmd(), "-e", script], capture_output=True, text=True, encoding="utf-8", timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["canonicalInput"] == NFC
    assert out["forms"] == [NFC, NFD]
    assert out["firstWrongPassword"] is True
    assert out["secondOpened"] is True
    assert out["inputs"] == [NFC, NFD]

    assert "openLoginKeypairAnyForm(" in _function(src, "handleLogin")
    any_form = _function(src, "openLoginKeypairAnyForm")
    assert "passwordForms(password)" in any_form and "openErr.wrongPassword" in any_form


def _web_login_script(src: str, cached: bool, recover_status: int) -> str:
    """openLoginKeypairAnyForm for a pre-NFC (NFD) account; /recover answers
    ``recover_status`` to every proof but the legacy one."""
    functions = "\n".join(
        _function(src, name)
        for name in (
            "canonicalPassword", "passwordForms", "normalizeKdfParams", "accountKdfParams",
            "deriveKEK", "openLoginKeypair", "deriveLoginKey", "openLoginKeypairAnyForm",
            "recoverError",
        )
    )
    return f"""
const ARGON2_HARD_FLOOR = {{ time: 2, mem: 65536, parallelism: 1 }};
const ARGON2_ACCOUNT_MAX = {{ time: 20, mem: 262144, parallelism: 8 }};
const derivedFrom = [];
async function deriveKEKViaWorker(password) {{
  derivedFrom.push(password);
  const bytes = new TextEncoder().encode(password);
  const out = new Uint8Array(64);
  bytes.forEach((b, i) => {{ out[i % 64] = (out[i % 64] * 31 + b) & 255; }});
  return out;
}}
const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const bytesToHex = hex;
const hexToBytes = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
const t = key => key;
function recoverFailureMessage(err) {{ return 'status ' + err.status; }}
const NFD = {json.dumps(NFD)};
let legacyKek = null;
const recoverCalls = [];
async function loadFromIndexedDB() {{
  return {json.dumps(cached)} ? {{ encrypted_keypair: 'bb', user_id: 'U1' }} : null;
}}
async function saveToIndexedDB() {{}}
async function apiFetch(path, options) {{
  recoverCalls.push(options.body.auth_proof === hex(legacyKek.subarray(32, 64)) ? 'legacy' : 'other');
  if (recoverCalls[recoverCalls.length - 1] !== 'legacy') {{
    const e = new Error('refused'); e.status = {recover_status}; throw e;
  }}
  return {{ encrypted_keypair: 'aa', user_id: 'U1' }};
}}
// Both the cache and the server copy open only under the legacy form's KEK.
function decryptLoginKeypair(blob, kek) {{
  if (hex(kek) !== hex(legacyKek.subarray(0, 32))) throw new Error('bad tag');
  return {{ keypairBytes: new Uint8Array(96), confirmedGenesis: null }};
}}
const sodium = {{ memzero(b) {{ b.fill(0); }} }};
{functions}
(async () => {{
  legacyKek = await deriveKEKViaWorker(NFD);
  derivedFrom.length = 0;
  const meta = {{ argon2_salt: '00'.repeat(16), argon2_params: {{ time_cost: 2, memory_cost: 65536, parallelism: 1 }} }};
  const out = {{}};
  try {{
    const opened = await openLoginKeypairAnyForm('admin', NFD, meta, null, sodium);
    out.opened = opened.keypairBytes.length === 96;
    out.cachedKeypair = opened.cachedKeypair;
    out.keptKey = hex(opened.derivedKey) === hex(legacyKek);
  }} catch (e) {{
    out.error = e.message;
  }}
  out.recoverCalls = recoverCalls;
  out.derivations = derivedFrom.length;
  console.log(JSON.stringify(out));
}})().catch(e => {{ console.error(e); process.exit(1); }});
"""


@requires_node
@pytest.mark.parametrize("recover_status", [401, 423])
def test_web_pre_nfc_account_opens_the_cache_without_a_wrong_recover(recover_status):
    """Review 688edcb V3: with a cached keypair, the NFC form failed on the cache
    and went to /recover with a wrong proof before the typed form opened the
    cache. Every login added a failure and after ten the name was locked (423),
    which ended every later login. The forms are now tried on the cache first."""
    src = APP_JS.read_text(encoding="utf-8")
    proc = subprocess.run(
        [node_cmd(), "-e", _web_login_script(src, cached=True, recover_status=recover_status)],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out.get("error") is None
    assert out["opened"] is True and out["cachedKeypair"] is True and out["keptKey"] is True
    assert out["recoverCalls"] == []
    assert out["derivations"] == 2  # each form derived once


@requires_node
def test_web_pre_nfc_account_without_cache_still_reaches_the_legacy_form():
    src = APP_JS.read_text(encoding="utf-8")
    proc = subprocess.run(
        [node_cmd(), "-e", _web_login_script(src, cached=False, recover_status=401)],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["opened"] is True and out["cachedKeypair"] is False
    assert out["recoverCalls"] == ["other", "legacy"]  # a success resets the counters


@requires_node
def test_web_locked_name_ends_the_form_loop_with_the_lock_message():
    src = APP_JS.read_text(encoding="utf-8")
    proc = subprocess.run(
        [node_cmd(), "-e", _web_login_script(src, cached=False, recover_status=423)],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["error"] == "status 423"
    assert out["recoverCalls"] == ["other"]


@requires_node
def test_web_throttled_recover_is_not_retried_with_another_form():
    src = APP_JS.read_text(encoding="utf-8")
    script = (
        "function recoverFailureMessage() { return 'x'; }\n"
        + _function(src, "recoverError")
        + "\nconsole.log(JSON.stringify([401, 404, 429, 423, 500].map(s => recoverError({status: s}).wrongPassword)));"
    )
    proc = subprocess.run([node_cmd(), "-e", script], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == [True, True, False, False, False]
