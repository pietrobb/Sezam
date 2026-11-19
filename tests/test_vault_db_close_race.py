"""VaultDB shares one SQLite connection across threads. Closing it (vault
lock from the idle watcher, 'sezam lock', ai_off) while another thread is
inside a statement (e.g. the remote AI policy poller) crashed the whole
process with an access violation. Statements and close() now take turns;
a statement after close raises a normal exception.

Runs in a child process: on the old code the crash takes the process down.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[1] / "src")

_CHILD = r"""
import sys, tempfile, threading
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from sezam.vault.db import VaultDB

db = VaultDB(Path(tempfile.mkdtemp()) / "t.db")
db.open()
db.create_schema()
db.close()
failures = []
for _ in range(200):
    db.open()
    stop = threading.Event()

    def hammer():
        i = 0
        while not stop.is_set():
            try:
                db.set_meta("k", str(i))
                db.get_meta("k")
                db.fetchall("SELECT key FROM vault_meta")
            except RuntimeError:
                pass  # closed: "Database not open"
            except Exception as exc:
                failures.append(repr(exc))
            i += 1

    threads = [threading.Thread(target=hammer) for _ in range(3)]
    for t in threads:
        t.start()
    db.get_meta("k")
    db.close()
    stop.set()
    for t in threads:
        t.join()
print("survived", failures[:3])
"""


_STATE_CHILD = r"""
import sys, tempfile, threading
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from sezam.crypto.kdf import Argon2Params
from sezam.vault import ai_access
from sezam.vault.crud import Vault

vault = Vault.create(Path(tempfile.mkdtemp()), "pw", Argon2Params(1, 8192, 1))
vault.lock()
wrong = []
for _ in range(50):
    vault.db.open()
    stop = threading.Event()

    def read():
        while not stop.is_set():
            if not ai_access.read_state(vault).enabled:
                wrong.append(1)

    threads = [threading.Thread(target=read) for _ in range(3)]
    for t in threads:
        t.start()
    ai_access.read_state(vault)
    vault.db.close()
    stop.set()
    for t in threads:
        t.join()
print("off by race:", len(wrong))
"""


def _run(code: str) -> str:
    result = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", code, SRC],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    return result.stdout.strip()


def test_close_while_other_threads_run_statements_does_not_crash():
    assert _run(_CHILD) == "survived []"


def test_ai_state_read_racing_a_lock_never_reads_as_off():
    """The kill switch state read while the vault locks in another thread
    must not come out 'unreadable, so off' (nor crash)."""
    assert _run(_STATE_CHILD) == "off by race: 0"
