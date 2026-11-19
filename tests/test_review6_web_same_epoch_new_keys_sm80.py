"""Stateful test finding SM80: a web session missed a key change at its own epoch.

The admin rotated their identity (epoch N+1) and the page signed in after it.
The server was then restored from a backup taken before the rotation (epoch N)
and an org recovery on the desktop moved it to N+1 again, with other key
material. The page compared only the epoch, saw no change and failed on
"Use the server's version" with "invalid Ed25519 signature" for the objects
the new keys signed. A running session now also ends when the server's
key_material_hash at the same epoch is not the one it last saw.
"""

from __future__ import annotations

import base64
import json
import subprocess

from tests.node_support import node_cmd, requires_node
from tests.test_review_web import SYNC_CORE_JS, _function

pytestmark = requires_node

HARNESS = r"""
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
context.apiFetch = async () => ({
  objects: [], key_epoch: input.serverEpoch, key_material_hash: input.serverHash, max_commit_seq: 3,
});
context.t = key => key;
context.endSessionForKeyEpochChange = () => { context.ended = true; };
(async () => {
  let error = null;
  try { await context.pullAndBuildTreeLocked(); } catch (err) { error = err.message; }
  console.log(JSON.stringify({ error, ended: !!context.ended }));
})();
"""

BASE = {"syncCheckpointLoaded": True, "outboxLoaded": True, "lastCommitSeq": 3, "keyEpoch": 2}
SEEN, OTHER = "aa" * 32, "bb" * 32


def _pull(state: dict, server_hash: str) -> dict:
    payload = json.dumps({"state": state, "serverEpoch": 2, "serverHash": server_hash})
    out = subprocess.run(
        [
            node_cmd(), "-e", HARNESS,
            base64.b64encode(payload.encode()).decode(),
            str(SYNC_CORE_JS),
        ],
        input=_function("pullAndBuildTreeLocked"), encoding="utf-8",
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_running_session_ends_on_other_key_material_at_the_same_epoch():
    running = {**BASE, "syncObjects": {}, "keyMaterialHash": SEEN}
    assert _pull(running, OTHER) == {"error": "error.key_epoch_changed", "ended": True}
    # "Use the server's version" pulls everything again (syncObjects = null).
    use_server = {**BASE, "syncObjects": None, "keyMaterialHash": SEEN}
    assert _pull(use_server, OTHER) == {"error": "error.key_epoch_changed", "ended": True}


def test_same_key_material_and_first_pull_go_on():
    unchanged = _pull({**BASE, "syncObjects": {}, "keyMaterialHash": SEEN}, SEEN)
    assert not unchanged["ended"] and unchanged["error"] != "error.key_epoch_changed"
    # The first pull of a login takes the key material it just opened.
    login = _pull({**BASE, "syncObjects": None, "keyMaterialHash": None}, OTHER)
    assert not login["ended"] and login["error"] != "error.key_epoch_changed"
