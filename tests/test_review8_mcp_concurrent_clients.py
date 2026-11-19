"""Review a159e97 (AI broker, medium): the MCP socket served one client at a time.

A client that connected and stayed silent held the Unix socket or the single
pipe instance, so every other client waited (or got 'pipe busy') until it
left. Each connection now has its own thread; requests still run one at a
time.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
import uuid

import pytest

from tests.test_review_cli_ipc import _bare_server


@pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipes")
def test_a_silent_pipe_client_does_not_hold_back_another():
    import win32file

    from tests.test_review_cli_ipc import _open_client

    name = rf"\\.\pipe\sezam_test_{uuid.uuid4().hex}"
    server = _bare_server()
    t = threading.Thread(target=server._run_named_pipe, args=(name,), daemon=True)
    t.start()
    silent = _open_client(name)
    try:
        other = _open_client(name)  # before: 'All pipe instances are busy'
        try:
            win32file.WriteFile(other, b'{"id": 3}\n')
            _, data = win32file.ReadFile(other, 65536)
            assert json.loads(data) == {"id": 3, "result": "pong"}
        finally:
            other.Close()
    finally:
        server._running = False
        silent.Close()
    t.join(5)
    assert not t.is_alive()


@pytest.mark.skipif(sys.platform == "win32", reason="Unix socket")
def test_a_silent_socket_client_does_not_hold_back_another(tmp_path):
    path = tmp_path / ".sezam" / "run" / "sezam_mcp.sock"
    server = _bare_server()
    server._server_socket = None
    t = threading.Thread(target=server._run_unix_socket, args=(str(path),), daemon=True)
    t.start()
    deadline = time.time() + 5
    while not path.exists() and time.time() < deadline:
        time.sleep(0.01)
    silent = socket.socket(socket.AF_UNIX)
    silent.connect(str(path))
    other = socket.socket(socket.AF_UNIX)
    other.settimeout(3)
    try:
        other.connect(str(path))
        other.sendall(b'{"id": 3}\n')
        assert json.loads(other.recv(65536)) == {"id": 3, "result": "pong"}  # before: timeout
    finally:
        other.close()
        silent.close()
        server._running = False
    t.join(5)
