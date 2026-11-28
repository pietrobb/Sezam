"""Lockout review N1 (web): Argon2 params a browser cannot handle.

normalizeKdfParams had no upper bound, so whatever /api/meta sent was handed
to the WASM Argon2. When the Web Worker died of it (Mobile Safari OOM at
256 MiB, or the 60 s timeout at a high time cost), deriveKEK ran the same
derivation again on the main thread, which kills or freezes the tab instead
of telling the user what happened.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from server.app.models.schemas import AccountKdfParams
from tests.node_support import node_cmd, requires_node, with_sync_core

APP_JS = Path(__file__).resolve().parents[1] / "web" / "static" / "js" / "app.js"
I18N_JS = APP_JS.with_name("i18n.js")


def _function(src: str, name: str) -> str:
    match = re.search(rf"^(async )?function {name}\(", src, re.M)
    assert match, name
    end = re.search(r"^(async )?function |^// ── ", src[match.end():], re.M)
    return src[match.start(): match.end() + (end.start() if end else len(src))]


def _run(body: str) -> dict:
    src = APP_JS.read_text(encoding="utf-8")
    script = "\n".join([
        "const t = key => key;",
        "console.warn = () => {};",
        _function(src, "normalizeKdfParams"),
        _function(src, "deriveKEK"),
        _function(src, "deriveKEKViaWorker"),
        body,
    ])
    proc = subprocess.run(
        [node_cmd(), "-e", with_sync_core(script)], capture_output=True, text=True, encoding="utf-8", timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _server_takes(params: dict) -> bool:
    try:
        AccountKdfParams.model_validate(params)
    except ValueError:
        return False
    return True


pytestmark = requires_node


_EDGES = [
    {"time_cost": t, "memory_cost": m, "parallelism": n}
    for t in (1, 2, 20, 21) for m in (65535, 65536, 262144, 262145) for n in (0, 1, 8, 9)
]


def test_web_ceiling_is_the_server_account_ceiling():
    """One copy of the bounds (core/src/kdf.rs): the web takes what the server takes."""
    out = _run(f"""
const edges = {json.dumps(_EDGES)};
console.log(JSON.stringify(edges.map(p => {{ try {{ normalizeKdfParams(p); return true; }} catch (e) {{ return false; }} }})));
""")
    assert out == [_server_takes(p) for p in _EDGES]
    assert sum(out) == 8


def test_params_beyond_the_ceiling_are_refused():
    out = _run("""
const tryParams = p => { try { normalizeKdfParams(p); return 'ok'; } catch (e) { return e.message; } };
console.log(JSON.stringify({
  desktopDefault: tryParams({ time_cost: 3, memory_cost: 262144, parallelism: 4 }),
  ceiling: tryParams({ time_cost: 20, memory_cost: 262144, parallelism: 8 }),
  oneGiB: tryParams({ time_cost: 3, memory_cost: 1048576, parallelism: 4 }),
  slow: tryParams({ time_cost: 1000, memory_cost: 65536, parallelism: 1 }),
  lanes: tryParams({ time_cost: 3, memory_cost: 65536, parallelism: 64 }),
  fraction: tryParams({ time_cost: 3.5, memory_cost: 65536, parallelism: 1 }),
}));
""")
    assert out == {
        "desktopDefault": "ok",
        "ceiling": "ok",
        "oneGiB": "error.kdf_params_unsupported",
        "slow": "error.kdf_params_unsupported",
        "lanes": "error.kdf_params_unsupported",
        "fraction": "error.kdf_params_unsupported",
    }


_WORKER_STUB = """
const mainThread = [];
const argon2 = {
  ArgonType: { Argon2id: 2 },
  hash: async () => { mainThread.push(true); return { hash: new Uint8Array(64) }; },
};
const delays = [];
const realSetTimeout = setTimeout;
setTimeout = (fn, ms) => { delays.push(ms); return 0; };
clearTimeout = () => {};
"""


def test_a_worker_out_of_memory_is_not_retried_on_the_main_thread():
    out = _run(_WORKER_STUB + """
class Worker {
  postMessage() { realSetTimeout(() => this.onmessage({ data: { error: 'Out of memory' } }), 0); }
  terminate() {}
}
deriveKEK('pw', new Uint8Array(16), { time_cost: 3, memory_cost: 262144, parallelism: 4 })
  .then(() => 'derived', e => e.message)
  .then(result => console.log(JSON.stringify({ result, mainThread: mainThread.length })));
""")
    assert out == {"result": "error.kdf_failed", "mainThread": 0}


def test_a_browser_without_workers_still_derives_on_the_main_thread():
    out = _run(_WORKER_STUB + """
class Worker { constructor() { throw new Error('Worker is not supported'); } }
deriveKEK('pw', new Uint8Array(16), null)
  .then(() => 'derived', e => e.message)
  .then(result => console.log(JSON.stringify({ result, mainThread: mainThread.length })));
""")
    assert out == {"result": "derived", "mainThread": 1}


def test_the_worker_gets_more_time_for_a_high_time_cost():
    out = _run(_WORKER_STUB + """
class Worker {
  postMessage() { realSetTimeout(() => this.onmessage({ data: { kek: new Uint8Array(64) } }), 0); }
  terminate() {}
}
(async () => {
  await deriveKEK('pw', new Uint8Array(16), { time_cost: 3, memory_cost: 65536, parallelism: 1 });
  await deriveKEK('pw', new Uint8Array(16), { time_cost: 20, memory_cost: 65536, parallelism: 1 });
  console.log(JSON.stringify({ delays }));
})();
""")
    assert out == {"delays": [60000, 230000]}


def test_both_messages_are_translated():
    i18n = I18N_JS.read_text(encoding="utf-8")
    for key in ("error.kdf_params_unsupported", "error.kdf_failed"):
        assert i18n.count(f"'{key}':") == 2, key
