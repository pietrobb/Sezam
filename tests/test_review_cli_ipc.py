"""Regressions for code review HEAD 2c7e809 items C3 (Windows MCP pipe access
control + busy loop) and C4 (password lockout tracker in the shared temp dir)."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid

import pytest

from sezam import cli

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipes")


# ── C4: lockout tracker ──


@pytest.fixture
def vault_dir(tmp_path, monkeypatch):
    vault = tmp_path / "vault"
    vault.mkdir()
    shared = tmp_path / "shared_tmp"
    shared.mkdir()
    monkeypatch.setenv("SEZAM_VAULT", str(vault))
    monkeypatch.setattr(cli.tempfile, "gettempdir", lambda: str(shared))
    return vault, shared


def test_planted_file_in_shared_temp_does_not_lock_out(vault_dir):
    _, shared = vault_dir
    (shared / "sezam_auth_attempts.json").write_text(
        json.dumps({"attempts": [time.time()] * 10})
    )
    cli._check_rate_limit()  # must not sys.exit


def test_tracker_lives_in_vault_dir_and_locks_after_five(vault_dir):
    vault, shared = vault_dir
    for _ in range(cli._MAX_ATTEMPTS):
        cli._record_failed_attempt()
    tracker = vault / "auth_attempts.json"
    assert tracker.is_file()
    assert not list(shared.iterdir())
    assert not [p for p in vault.iterdir() if p.name.startswith(".auth_attempts.")]
    if os.name == "posix":
        assert (tracker.stat().st_mode & 0o777) == 0o600
    with pytest.raises(SystemExit):
        cli._check_rate_limit()
    cli._clear_failed_attempts()
    assert not tracker.exists()
    cli._check_rate_limit()


def test_non_regular_tracker_is_ignored(vault_dir):
    vault, _ = vault_dir
    (vault / "auth_attempts.json").mkdir()
    cli._check_rate_limit()
    cli._record_failed_attempt()  # cannot replace a directory: logged, no crash


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership")
def test_tracker_owned_by_other_user_is_ignored(vault_dir, monkeypatch):
    vault, _ = vault_dir
    (vault / "auth_attempts.json").write_text(json.dumps({"attempts": [time.time()] * 10}))
    real_uid = os.getuid()
    monkeypatch.setattr(cli.os, "getuid", lambda: real_uid + 1)
    cli._check_rate_limit()


# ── C3: Windows named pipe ──


def _bare_server():
    from sezam.mcp.server import SezamMCPServer

    server = SezamMCPServer.__new__(SezamMCPServer)
    server._running = False
    server._dispatch_request = lambda req: {"id": req.get("id"), "result": "pong"}
    return server


def _open_client(name: str):
    import pywintypes
    import win32con
    import win32file
    import win32pipe

    deadline = time.time() + 5
    while True:
        try:
            win32pipe.WaitNamedPipe(name, 200)
            return win32file.CreateFile(
                name,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE | win32con.READ_CONTROL,
                0, None, win32file.OPEN_EXISTING, 0, None,
            )
        except pywintypes.error:
            if time.time() > deadline:
                raise
            time.sleep(0.05)


@windows_only
def test_pipe_dacl_grants_only_current_user_and_serves_requests():
    pytest.importorskip("win32security")
    import win32file
    import win32security

    from sezam.mcp import winpipe

    name = rf"\\.\pipe\sezam_test_{uuid.uuid4().hex}"
    server = _bare_server()
    t = threading.Thread(target=server._run_named_pipe, args=(name,), daemon=True)
    t.start()
    client = _open_client(name)
    try:
        sd = win32security.GetSecurityInfo(
            client, win32security.SE_KERNEL_OBJECT, win32security.DACL_SECURITY_INFORMATION
        )
        dacl = sd.GetSecurityDescriptorDacl()
        me = win32security.ConvertStringSidToSid(winpipe.current_user_sid())
        aces = [dacl.GetAce(i) for i in range(dacl.GetAceCount())]
        assert len(aces) == 1
        assert aces[0][2] == me
        assert sd.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED

        win32file.WriteFile(client, b'{"id": 7}\n')
        _, data = win32file.ReadFile(client, 65536)
        assert json.loads(data) == {"id": 7, "result": "pong"}
    finally:
        server._running = False
        client.Close()
    t.join(5)
    assert not t.is_alive()


@windows_only
def test_pipe_refuses_name_already_held_by_another_instance():
    import win32pipe

    name = rf"\\.\pipe\sezam_test_{uuid.uuid4().hex}"
    squatter = win32pipe.CreateNamedPipe(
        name, win32pipe.PIPE_ACCESS_DUPLEX, 0, win32pipe.PIPE_UNLIMITED_INSTANCES,
        4096, 4096, 0, None,
    )
    try:
        server = _bare_server()
        t = threading.Thread(target=server._run_named_pipe, args=(name,), daemon=True)
        t.start()
        t.join(5)
        assert not t.is_alive(), "server must refuse a squatted pipe name, not serve it"
    finally:
        squatter.Close()


@windows_only
def test_repeated_connect_failures_back_off_and_stop(monkeypatch):
    import ctypes

    from sezam.mcp import winpipe

    calls = {"create": 0, "close": 0}

    class FakeKernel32:
        def CreateNamedPipeW(self, *args):
            calls["create"] += 1
            return 1234

        def ConnectNamedPipe(self, handle, overlapped):
            return 0

        def CloseHandle(self, handle):
            calls["close"] += 1

    class FakeSecurity:
        attributes = winpipe.SECURITY_ATTRIBUTES()

        def __init__(self, group=None):
            calls["group"] = group

        def close(self):
            calls["security_closed"] = True

    sleeps: list[float] = []
    monkeypatch.setattr(winpipe, "load_kernel32", FakeKernel32)
    monkeypatch.setattr(winpipe, "OwnerOnlySecurity", FakeSecurity)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5)
    monkeypatch.setattr(time, "sleep", sleeps.append)

    server = _bare_server()
    server._run_named_pipe("sezam_test_fail")

    limit = server._MAX_PIPE_CONNECT_FAILURES
    assert calls["create"] == limit and calls["close"] == limit
    assert calls["security_closed"]
    assert len(sleeps) == limit - 1
    assert sleeps == sorted(sleeps) and sleeps[0] > 0 and max(sleeps) <= 5.0
