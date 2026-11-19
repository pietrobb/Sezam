"""The Node.js the web-client tests run app.js in.

The web client derives keys with crypto.argon2Sync, which Node has only from
24.7. With an older Node every such test failed with "argon2Sync is not a
function" deep in a harness; now it is skipped and says why.
"""

from __future__ import annotations

import functools
import re
import shutil
import socket
import subprocess

import pytest

MIN_NODE = (24, 7)


@functools.lru_cache(maxsize=1)
def node_problem() -> str | None:
    """None when a usable Node is on PATH, otherwise why the tests skip."""
    node = shutil.which("node")
    if node is None:
        return "node is not installed (the web tests need Node >= 24.7)"
    try:
        out = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return f"node --version failed: {exc}"
    match = re.match(r"v(\d+)\.(\d+)", out.strip())
    if match is None:
        return f"cannot read the Node version from {out.strip()!r}"
    if (int(match.group(1)), int(match.group(2))) < MIN_NODE:
        return f"Node {out.strip()} lacks crypto.argon2Sync; the web tests need Node >= 24.7"
    return None


def node_cmd() -> str:
    """The node executable; skips the calling test when Node is missing or too old."""
    problem = node_problem()
    if problem is not None:
        pytest.skip(problem)
    return shutil.which("node")


requires_node = pytest.mark.skipif(
    node_problem() is not None, reason=node_problem() or "",
)

# The Fetch standard's "bad ports": Node's fetch and the browsers refuse them
# ("fetch ... failed: bad port"). Windows can hand one out for port 0 (1723).
FETCH_BAD_PORTS = frozenset({
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79,
    87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137,
    139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532,
    540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723,
    2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669,
    6679, 6697, 10080,
})


def fetchable_socket() -> socket.socket:
    """A TCP socket bound to a free 127.0.0.1 port that fetch may connect to."""
    held = []
    try:
        while True:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            if sock.getsockname()[1] not in FETCH_BAD_PORTS:
                return sock
            held.append(sock)  # kept open so the next bind gets another port
    finally:
        for sock in held:
            sock.close()
