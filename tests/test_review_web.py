"""Regressions for code review HEAD 2c7e809, web items 20-25."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
from pathlib import Path

from nacl.public import PrivateKey

from sezam.crypto.envelope_crypto import create_envelope
from tests.node_support import node_cmd, requires_node

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
VENDOR = ROOT / "web" / "static" / "js" / "vendor"
SYNC_CORE_JS = VENDOR / "sezam-sync-core.js"

pytestmark = requires_node


def _function(name: str) -> str:
    """Source of a top-level ``function name(`` / ``async function name(``."""
    start = APP.index(f"function {name}(")
    if APP[max(0, start - 6):start] == "async ":
        start -= 6
    depth = 0
    for index in range(APP.index("{", start), len(APP)):
        depth += {"{": 1, "}": -1}.get(APP[index], 0)
        if depth == 0:
            return APP[start:index + 1]
    raise AssertionError(name)


HARNESS = r"""
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const { webcrypto } = require('crypto');
const context = {
  crypto: webcrypto, console, Uint8Array, TextEncoder, TextDecoder, Buffer, WebAssembly, Promise,
  setTimeout, clearTimeout, AbortSignal, URLSearchParams,
  atob: value => Buffer.from(value, 'base64').toString('binary'),
  document: { addEventListener() {} },
};
context.window = context; context.self = context; context.globalThis = context;
context.base64ToBytes = value => Uint8Array.from(Buffer.from(value, 'base64'));
context.bytesToHex = value => Buffer.from(value).toString('hex');
vm.createContext(context);
for (const path of process.argv.slice(1, 4)) vm.runInContext(fs.readFileSync(path, 'utf8'), context);
const bundle = JSON.parse(fs.readFileSync(process.argv[4], 'utf8'));
vm.runInContext(bundle.helpers, context);
const input = bundle.input;
(async () => {
  await context.sodium.ready;
  await context.SezamSyncCore.ready;  // the shared sync core (core/build_web.py)
  context.state = { acceptedBases: {}, ...(input.state || {}) };
  const hex = value => Uint8Array.from(Buffer.from(value, 'hex'));
  const result = await vm.runInContext(input.script, Object.assign(context, { hex, assert }));
  console.log(JSON.stringify(result === undefined ? null : result));
})().catch(error => { console.error(error); process.exit(1); });
"""


# What saveWebDirtyState calls (review 8595ec1 #5: the stale-tab guard).
WEB_DIRTY_SAVE = ["webKekIsCurrent", "sealWebDirtyState", "webDirtyStateOpens", "loadFromIndexedDB"]


# Helpers the functions call since review c78fd19 (R13-5), added to any
# harness whose source calls one without defining it: the harnesses of single
# functions predate them.
HELPERS = [
    "openWebDirtyState", "withWebDirtyStateLock", "mergeWebKeyed", "mergeWebDirtyState", "replaceWebKeyed",
    "withLegacyWebBase", "webOwnEarlierPush", "rememberWebSent", "webPushOrder", "webPulledIsStale", "heldCopyKey",
    "teamLogMismatch", "webLocalTeamLogRefusal", "webInPersonalTree", "webIsAdmin", "webPinnedTeamGenesis",
    "rememberWebKdfState", "orgRecoveryKeys", "fetchOrgRecoveryBlob", "paddedSize", "bytesToHex",
    "authorityObjects", "sealingDekId",
]


def _with_helpers(source: str) -> str:
    while missing := [h for h in HELPERS if f"{h}(" in source and f"function {h}(" not in source]:
        source += "\n" + "\n".join(_function(h) for h in missing)
    return source


def _run(functions: list[str], script: str, state: dict | None = None):
    return _run_source("\n".join(_function(name) for name in functions), script, state)


def web_sync_lock() -> str:
    """The page's sync lock (review 7c10379 R7-H) for a harness of single functions."""
    return (
        "var webSyncTail = Promise.resolve();\nvar webSyncSharedRuns = new Set();\n"
        + _function("withWebSyncLock") + "\n" + _function("withWebSyncShared") + "\n"
    )


def _run_source(helpers: str, script: str, state: dict | None = None):
    helpers = web_sync_lock() + _with_helpers(helpers)
    # A file, not argv: Windows refuses command lines over 32 KB (WinError 206).
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as bundle:
        json.dump({"helpers": helpers, "input": {"script": script, "state": state or {}}}, bundle)
    try:
        out = subprocess.run(
            [
                node_cmd(), "-e", HARNESS,
                str(VENDOR / "libsodium-sumo.min.js"),
                str(VENDOR / "libsodium-wrappers.min.js"),
                str(SYNC_CORE_JS),
                bundle.name,
            ],
            capture_output=True, text=True, timeout=60,
        )
    finally:
        os.unlink(bundle.name)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


# ── 20: escapeHtml is safe inside quoted attributes ──


def test_escape_html_escapes_quotes_for_attributes():
    result = _run(["escapeHtml"], "escapeHtml(`ab\"cd'<x>&`)")
    assert result == "ab&quot;cd&#39;&lt;x&gt;&amp;"


# ── 21: refreshJWT obtains libsodium itself ──


def test_refresh_jwt_has_its_own_sodium_handle():
    body = _function("refreshJWT")
    assert body.index("const _sodium = await ensureSodium()") < body.index("signAuthChallenge(")


# ── 23: lock and failed login wipe the session and its DOM ──


def test_lock_and_failed_login_reset_session_and_dom():
    lock = _function("handleLock")
    login = _function("handleLogin")
    reset = _function("resetSession")
    dom = _function("clearSensitiveDom")

    assert "resetSession();" in lock
    catch_block = login.split("} catch (err) {", 1)[1].split("} finally {", 1)[0]
    assert "resetSession();" in catch_block
    assert login.index("resetSession();") < login.index("await ensureSodium()")
    for field in ("state.deks = {}", "state.entries = {}", "state.keypair = null", "state.userId = null"):
        assert field in reset
    assert "clearSensitiveDom();" in reset
    for needle in ("_totpTimers", ".modal-overlay", "entry-fields", "entry-form"):
        assert needle in dom


# ── 24: the iOS check never creates a store-less database ──


def test_ios_check_opens_through_upgrade_path():
    check = _function("checkiOSIndexedDB")
    assert "openDB()" in check
    assert "indexedDB.open(" not in check
    assert "indexedDB.open('sezam', 3)" in _function("openDB")


# ── 25: shared folder DEKs from envelopes, DEK choice by header / folder ──


def _keys():
    sender, recipient = PrivateKey.generate(), PrivateKey.generate()
    return sender, recipient


def test_web_opens_desktop_dek_envelope_from_trusted_sender():
    sender, recipient = _keys()
    dek = bytes(range(32))
    blob = create_envelope(dek, bytes(sender), bytes(recipient.public_key))
    script = """
      state.keypair = { encryptionSk: hex(state.recipientSk) };
      state.userEncryptionKeys = { ADMIN: [hex(state.otherPk), hex(state.senderPk)] };
      const env = { id: 'E', owner_id: 'ADMIN', payload: state.payload };
      const opened = Buffer.from(openDekEnvelope(env, sodium)).toString('hex');
      state.userEncryptionKeys = { ADMIN: [hex(state.otherPk)] };
      let rejected = false;
      try { openDekEnvelope(env, sodium); } catch { rejected = true; }
      ({ opened, rejected })
    """
    state = {
        "recipientSk": bytes(recipient).hex(),
        "senderPk": bytes(sender.public_key).hex(),
        "otherPk": bytes(PrivateKey.generate().public_key).hex(),
        "payload": base64.b64encode(blob).decode(),
    }

    result = _run(["openDekEnvelope"], script, state)

    assert result == {"opened": dek.hex(), "rejected": True}


def test_pull_opens_envelopes_addressed_to_current_user():
    pull = _function("pullAndBuildTreeLocked")
    step = pull.split("Step 1b", 1)[1].split("Step 2", 1)[0]
    assert "keyEnvelopesForUser(" in step
    assert "candidateSyncObjects, state.userId, teamLog, _sodium)" in step
    assert "envelope.target_user_id !== userId" in _function("keyEnvelopesForUser")
    assert "candidateDeks[envelope.parent_ref] = openDekEnvelope(envelope, _sodium)" in step


DEK_STATE = {
    "rootDekId": "ROOTDEK",
    "userId": "ADMIN",
    "deks": {"ROOTDEK": 1, "00SHAREDDEK000000000000000": 1, "OLDDEK": 1, "PERSONALDEK": 1},
    "nodes": {
        "ROOT": {"id": "ROOT", "parent_ref": None},
        "TEAM": {"id": "TEAM", "parent_ref": "ROOT"},
        "SUB": {"id": "SUB", "parent_ref": "TEAM"},
        "PLAIN": {"id": "PLAIN", "parent_ref": "ROOT"},
        "ME": {"id": "ME", "parent_ref": "ROOT", "personal": True, "dekId": "PERSONALDEK"},
    },
    "syncObjects": {
        "00SHAREDDEK000000000000000": {"id": "00SHAREDDEK000000000000000", "object_type": "dek", "parent_ref": "TEAM", "is_deleted": 0,
                                       "signer": "ADMIN"},
        "01G0NEDEK00000000000000000": {"id": "01G0NEDEK00000000000000000", "object_type": "dek", "parent_ref": "PLAIN", "is_deleted": 0,
                                       "signer": "ADMIN"},
        # Review 7c10379 H3: folder keys count from the admin (top-level folder signer).
        "ROOT": {"id": "ROOT", "object_type": "node", "parent_ref": None, "signer": "ADMIN"},
    },
}


def test_write_dek_follows_header_then_folder_then_root():
    script = """({
      newInShared: resolveWriteDekId('TEAM'),
      newInSubfolder: resolveWriteDekId('SUB'),
      newInPlainFolderWithoutHeldDek: resolveWriteDekId('PLAIN'),
      editKeepsHeaderDek: resolveWriteDekId('TEAM', { parent_ref: 'TEAM', dekId: 'OLDDEK' }),
      moveUsesDestination: resolveWriteDekId('PLAIN', { parent_ref: 'TEAM', dekId: '00SHAREDDEK000000000000000' }),
      personalWins: resolveWriteDekId('ME', { parent_ref: 'ME', dekId: 'ROOTDEK' }),
    })"""

    result = _run(
        ["resolveInheritedPersonalDekId", "nearestFolderDekId", "provenDekSuccessors",
         "finalDekSuccessor", "resolveWriteDekId", "keyAuthors", "folderTreeOwner", "ulidTimeMs"],
        script,
        DEK_STATE,
    )

    assert result == {
        "newInShared": "00SHAREDDEK000000000000000",
        "newInSubfolder": "00SHAREDDEK000000000000000",
        "newInPlainFolderWithoutHeldDek": "ROOTDEK",
        "editKeepsHeaderDek": "OLDDEK",
        "moveUsesDestination": "ROOTDEK",
        "personalWins": "PERSONALDEK",
    }


def test_edit_and_delete_use_resolve_write_dek():
    save = _function("handleModalSave")
    delete = _function("handleDeleteConfirm")
    assert "resolveWriteDekId(parentRef, existingEntry)" in save
    assert "resolveWriteDekId(parentRef, existingNode)" in save
    assert "resolveWriteDekId(entry.parent_ref, entry)" in delete
