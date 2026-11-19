"""Review 1141a20 H7, real Unix socket: silent peers flood the brake.

``python3 tests/wsl_brake_flood.py emfile`` lowers the file descriptor
limit so the flood pushes the broker into EMFILE (before the fix the accept
loop died there and the brake never answered again). ``cap`` keeps the
limit and floods with 300 silent peers, which only meet the endpoint's own
bound. Run with a Linux python (natively or inside WSL) from anywhere;
stdlib only. Prints one JSON line.
"""

from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

FLOOD = r"""
import socket, sys, time
path, count, hold = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
held = []
for _ in range(count):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(0.2)
    try:
        s.connect(path)
    except OSError:
        s.close()
        continue
    held.append(s)
print(len(held), flush=True)
time.sleep(hold)
"""


def main(mode: str) -> None:
    run = Path(tempfile.mkdtemp(prefix="sezam-h7-"))
    os.chmod(run, 0o700)
    os.environ["SEZAM_RUN_DIR"] = str(run)
    from sezam.mcp import control

    calls: list[str] = []

    def ai_off() -> dict:
        calls.append("ai_off")
        return {"status": "ok", "ai_access": "off", "persisted": True}

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if mode == "emfile":
        resource.setrlimit(resource.RLIMIT_NOFILE, (24, hard))
    server = control.ControlServer(
        {"ai_off": ai_off, "status": lambda: {"status": "ok"}}, control.endpoint()
    )
    server.start()
    try:
        flood = subprocess.Popen(
            [sys.executable, "-c", FLOOD, server.path, "120" if mode == "emfile" else "300", "3"],
            stdout=subprocess.PIPE, text=True,
            preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard)),
        )
        held = int(flood.stdout.readline() or 0)
        started = time.monotonic()
        during = control.send(server.path, "ai_off", timeout=6)
        during_seconds = round(time.monotonic() - started, 2)
        flood.wait(10)
        after = control.send(server.path, "ai_off", timeout=3)
        print(json.dumps({
            "held": held, "during": during, "during_seconds": during_seconds,
            "after": after, "calls": len(calls), "open": len(server._admission),
            "accept_alive": server._thread.is_alive(),
        }))
    finally:
        server.stop()
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "emfile")
