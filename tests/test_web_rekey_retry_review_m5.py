"""Lockout review M5 (web): Retry must not send a pending re-key object by object.

pushWebRekeyBatch queued the re-key objects in state.outbox, and the
sync banner's Retry pushed every dirty object alone with atomic_batch:false.
A partly accepted re-key leaves folders whose entries are under the new DEK
while key envelopes are missing, or the other way round. Retry now sends a
pending re-key journal as its one atomic batch, before any other change, and
stops if the batch is refused.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from tests.node_support import node_cmd, requires_node

APP_JS = Path(__file__).resolve().parents[1] / "web" / "static" / "js" / "app.js"

pytestmark = requires_node


def _function(src: str, name: str) -> str:
    match = re.search(rf"^(async )?function {name}\(", src, re.M)
    assert match, name
    end = re.search(r"^(async )?function |^// ── ", src[match.end():], re.M)
    return src[match.start(): match.end() + (end.start() if end else len(src))]


def _run(batch_accepted: bool) -> dict:
    src = APP_JS.read_text(encoding="utf-8")
    functions = "\n".join(
        _function(src, name) for name in (
            "pushWebRekeyBatch", "retryAllWebDirtyObjects", "finishWebRevocation",
            "prepareWebRekeyJournal",
        )
    )
    script = f"""
const posts = [];
const singles = [];
let journal = {{
  revoked_user_id: 'GONE', phase: 'prepared',
  objects: [{{ id: 'R1', payload: 'p-r1' }}, {{ id: 'R2', payload: 'p-r2' }}],
}};
const state = {{
  userId: 'ME', keyEpoch: 3,
  // U1 is the user's own edit (S3: the re-key is an operation of the same queue).
  outbox: {{ U1: {{ id: 'U1', payload: 'p-u1' }} }},
  syncConflicts: {{}},
}};
async function ensureSodium() {{ return {{}}; }}
function assertSyncUnitFits() {{}}
function oversizedQueuedObjects() {{ return []; }}
function webPushOrder(objects) {{ return objects; }}
// One request, as postAtomicSyncBatch sends a batch this small.
function postAtomicSyncBatch(objects, fields) {{
  return apiFetch('/api/sync', {{ method: 'POST', body: {{ ...fields, objects, atomic_batch: true }} }});
}}
async function pendingWebRevocations() {{ return ['GONE']; }}
async function loadWebRekeyJournal(id) {{
  return id === 'GONE' ? JSON.parse(JSON.stringify(journal)) : null;
}}
async function saveWebRekeyJournal(value) {{ journal = JSON.parse(JSON.stringify(value)); }}
let cleared = false;
async function clearWebRekeyJournal() {{ cleared = true; }}
async function buildWebRekeyBatch() {{
  return {{ objects: [{{ id: 'R3', payload: 'p-r3' }}], folders_rekeyed: 1 }};
}}
const deletes = [];
async function saveWebDirtyState() {{}}
function withWebSyncLock(op) {{ return op(); }}
async function pullAndBuildTree() {{}}
async function pushEncryptedVaultObject(object) {{ singles.push(object.id); }}
async function resealUnderFolderSuccessor(object) {{ return object; }}
async function apiFetch(path, options) {{
  if (options.method === 'DELETE') {{ deletes.push(path); return {{}}; }}
  posts.push(options.body);
  const ids = options.body.objects.map(o => o.id);
  return {batch_accepted and "{ accepted: ids.map(id => ({ id })), conflicts: [] }"
          or "{ accepted: [], conflicts: [{ id: ids[0] }] }"};
}}
{functions}
(async () => {{
  let error = null;
  try {{ await retryAllWebDirtyObjects(); }} catch (err) {{ error = err.message; }}
  console.log(JSON.stringify({{
    posts, singles, error, phase: journal.phase, deletes, cleared,
    journalObjects: journal.objects.map(o => o.id),
    dirty: Object.keys(state.outbox).sort(),
  }}));
}})();
"""
    out = subprocess.run([node_cmd(), "-e", script], check=True, capture_output=True, text=True)
    return json.loads(out.stdout)


def test_retry_sends_pending_rekey_as_one_atomic_batch_first():
    observed = _run(batch_accepted=True)

    assert observed["error"] is None
    assert observed["posts"] == [
        {"objects": [{"id": "R1", "payload": "p-r1"}, {"id": "R2", "payload": "p-r2"}],
         "atomic_batch": True, "key_epoch": 3},
    ]
    # Re-key objects never go out alone; the user's edit does, afterwards.
    assert observed["singles"] == ["U1"]
    # Review 688edcb: Retry also finishes the revocation the journal belongs to.
    assert observed["deletes"] == ["/api/users/GONE"] and observed["cleared"] is True
    assert observed["dirty"] == ["U1"]


def test_refused_rekey_batch_is_rebuilt_once_then_retry_stops_and_keeps_journal():
    observed = _run(batch_accepted=False)

    assert observed["error"] == "Atomic re-key batch was not fully accepted"
    # Review 688edcb M5: the refused batch is rebuilt from the server's state,
    # not resent; a refused rebuild stops Retry, still never object by object.
    assert [[o["id"] for o in post["objects"]] for post in observed["posts"]] == [["R1", "R2"], ["R3"]]
    assert all(post["atomic_batch"] is True for post in observed["posts"])
    assert observed["singles"] == []
    assert observed["phase"] == "prepared" and observed["journalObjects"] == ["R3"]
    assert observed["deletes"] == [] and observed["cleared"] is False


def test_rekey_batch_is_not_queued_as_single_dirty_objects():
    src = APP_JS.read_text(encoding="utf-8")
    assert "state.outbox[" not in _function(src, "pushWebRekeyBatch")
