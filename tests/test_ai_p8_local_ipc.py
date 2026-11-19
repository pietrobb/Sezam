"""P8: the MCP Unix socket lives in a private ~/.sezam/run (0700), never in
a shared directory such as /tmp, and is bound without a permissive window."""

import os
import socket
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from sezam.mcp.control import prepare_socket_path
from sezam.mcp.server import SezamMCPServer

posix_only = pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(socket, "AF_UNIX"),
    reason="Unix domain socket permissions",
)


def test_default_socket_is_in_private_run_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/tmp")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    path = SezamMCPServer.default_socket_path()
    assert Path(path) == tmp_path / ".sezam" / "run" / "sezam_mcp.sock"


def test_windows_default_is_the_named_pipe(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert SezamMCPServer.default_socket_path() == "\\\\.\\pipe\\sezam_mcp"


@posix_only
def test_run_dir_is_created_owner_only(tmp_path):
    path = tmp_path / ".sezam" / "run" / "sezam_mcp.sock"
    prepare_socket_path(path)
    assert stat.S_IMODE(os.lstat(path.parent).st_mode) == 0o700


@posix_only
def test_shared_directory_is_refused(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    with pytest.raises(PermissionError, match="writable by other users"):
        prepare_socket_path(shared / "sezam_mcp.sock")


@posix_only
def test_symlinked_run_dir_is_refused(tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir(mode=0o700)
    (tmp_path / "run").symlink_to(real, target_is_directory=True)
    with pytest.raises(PermissionError, match="not a directory"):
        prepare_socket_path(tmp_path / "run" / "sezam_mcp.sock")


@posix_only
def test_non_socket_at_the_path_is_not_deleted(tmp_path):
    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    victim = run / "sezam_mcp.sock"
    victim.write_text("keep me")
    with pytest.raises(PermissionError, match="not a socket"):
        prepare_socket_path(victim)
    assert victim.read_text() == "keep me"


@posix_only
def test_stale_socket_is_replaced(tmp_path):
    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    path = run / "s.sock"
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(path))
    stale.close()
    prepare_socket_path(path)
    assert not path.exists()


@posix_only
def test_bound_socket_is_owner_only(tmp_path, monkeypatch):
    path = tmp_path / ".sezam" / "run" / "sezam_mcp.sock"
    modes = []
    real_bind = socket.socket.bind

    def bind(self, address):
        real_bind(self, address)
        modes.append(stat.S_IMODE(os.lstat(address).st_mode))

    monkeypatch.setattr(socket.socket, "bind", bind)
    server = SezamMCPServer.__new__(SezamMCPServer)
    server._server_socket = None
    server._running = False
    thread = threading.Thread(target=server._run_unix_socket, args=(str(path),), daemon=True)
    thread.start()
    deadline = time.time() + 5
    while not modes and time.time() < deadline:
        time.sleep(0.01)
    server._running = False
    thread.join(5)
    assert modes and modes[0] & 0o077 == 0
