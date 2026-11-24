"""R16-Z SM16 (web): a re-key batch names the commit it was built on.

Two devices of one admin re-keyed one folder after the same revocation; the
server stored both new keys once GC had collected the folder's items. The
server now refuses a new folder key when the folder got another key after the
batch's checked commit (folder_key_moved). The browser sent its re-key batch
without check_seq/check_token, so that rule never applied to it. The journal
now keeps the commit of the pull it was built on, and its push names it; the
refused batch is rebuilt from a new pull, under that pull's commit.
"""

from __future__ import annotations

import json
import subprocess

from tests.node_support import node_cmd, requires_node
from tests.test_web_rekey_retry_review_m5 import APP_JS, _function

pytestmark = requires_node


def _run() -> dict:
    src = APP_JS.read_text(encoding="utf-8")
    functions = "\n".join(
        _function(src, name) for name in (
            "pushWebRekeyBatch", "sendWebTeamRecords", "noteWebTeamRecordsSent",
            "noteWebTeamRecordsTaken", "finishWebRevocation", "prepareWebRekeyJournal",
        )
    )
    script = f"""
const posts = [];
let journal = null;
let pulls = 0;
const state = {{ userId: 'ME', keyEpoch: 3, syncCheckpoint: null }};
function assertSyncUnitFits() {{}}
function postAtomicSyncBatch(objects, fields) {{
  return apiFetch('/api/sync', {{ method: 'POST', body: {{ ...fields, objects, atomic_batch: true }} }});
}}
async function loadWebRekeyJournal() {{ return journal && JSON.parse(JSON.stringify(journal)); }}
async function saveWebRekeyJournal(value) {{ journal = JSON.parse(JSON.stringify(value)); }}
async function clearWebRekeyJournal() {{ journal = null; }}
async function pullAndBuildTree() {{
  pulls += 1;
  state.syncCheckpoint = {{ last_sync_seq: 6 + pulls, commit_token: 'T' + (6 + pulls) }};
}}
async function buildWebRekeyBatch() {{
  return {{ objects: [{{ id: 'K' + pulls, payload: 'p' }}], folders_rekeyed: 1 }};
}}
async function apiFetch(path, options) {{
  if (options.method === 'DELETE') return {{}};
  posts.push(options.body);
  const ids = options.body.objects.map(o => o.id);
  // The first batch races a key another device of this account committed.
  return posts.length === 1
    ? {{ accepted: [], conflicts: [{{ id: ids[0], code: 'folder_key_moved' }}] }}
    : {{ accepted: ids.map(id => ({{ id }})), conflicts: [] }};
}}
{functions}
(async () => {{
  let error = null;
  try {{ await finishWebRevocation('GONE', {{}}); }} catch (err) {{ error = err.message; }}
  console.log(JSON.stringify({{ posts, error }}));
}})();
"""
    out = subprocess.run([node_cmd(), "-e", script], check=True, capture_output=True, text=True)
    return json.loads(out.stdout)


def test_web_rekey_batch_names_the_commit_it_was_built_on():
    observed = _run()

    assert observed["error"] is None
    checks = [(p.get("check_seq"), p.get("check_token")) for p in observed["posts"]]
    # Built after pull 1 (commit 7), refused; rebuilt after pull 2 (commit 8).
    assert checks == [(7, "T7"), (8, "T8")]
    assert [[o["id"] for o in p["objects"]] for p in observed["posts"]] == [["K1"], ["K2"]]
