"""Review c78fd19 R13-11: on a Windows group pipe the connecting user is
read from the pipe itself, and a client whose user cannot be told is
refused instead of escaping the per-user limit."""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid

import pytest

from sezam.mcp import winpipe
from sezam.mcp.control import UNIDENTIFIED, Admission
from tests.test_review_cli_ipc import _bare_server, _open_client

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipes")

USERS = "S-1-5-32-545"  # BUILTIN\Users: the test user is a member


def _ask_pong(name: str) -> dict:
    import win32file

    client = _open_client(name)
    try:
        win32file.WriteFile(client, b'{"id": 7}\n')
        _, data = win32file.ReadFile(client, 65536)
        return json.loads(data)
    finally:
        client.Close()


def _serve(group):
    name = rf"\\.\pipe\sezam_test_{uuid.uuid4().hex}"
    server = _bare_server()
    t = threading.Thread(target=server._run_named_pipe, args=(name, group), daemon=True)
    t.start()
    time.sleep(0.2)
    return name, server, t


def _stop(server, t):
    server._running = False
    server._wake_pipe()
    t.join(5)


@windows_only
def test_group_pipe_tells_the_user_without_opening_the_client_process(monkeypatch):
    import ctypes
    import ctypes.wintypes as wt

    a = ctypes.WinDLL("advapi32", use_last_error=True)
    a.OpenThreadToken.argtypes = [wt.HANDLE, wt.DWORD, wt.BOOL, ctypes.POINTER(wt.HANDLE)]
    k = winpipe.load_kernel32()
    k.GetCurrentThread.restype = wt.HANDLE

    seen = []
    real = winpipe.pipe_client_sid

    def observed(handle):
        sid = real(handle)
        # The accept thread is back under its own identity (no thread token).
        token = wt.HANDLE()
        seen.append((sid, bool(a.OpenThreadToken(k.GetCurrentThread(), 0x0008, True,
                                                 ctypes.byref(token)))))
        return sid

    monkeypatch.setattr(
        winpipe, "_client_process_sid", lambda handle: pytest.fail("PID fallback used")
    )
    monkeypatch.setattr(winpipe, "pipe_client_sid", observed)
    name, server, t = _serve(USERS)
    try:
        assert _ask_pong(name) == {"id": 7, "result": "pong"}
    finally:
        _stop(server, t)
    assert seen[0] == (winpipe.current_user_sid(), False)


@windows_only
def test_group_pipe_refuses_a_client_of_unknown_user(monkeypatch):
    import pywintypes
    import win32file

    monkeypatch.setattr(winpipe, "pipe_client_sid", lambda handle: None)
    name, server, t = _serve(USERS)
    try:
        client = _open_client(name)
        try:
            with pytest.raises(pywintypes.error):
                win32file.WriteFile(client, b'{"id": 7}\n')
                win32file.ReadFile(client, 65536)
        finally:
            client.Close()
    finally:
        _stop(server, t)


@windows_only
def test_owner_only_pipe_needs_no_peer_identity(monkeypatch):
    monkeypatch.setattr(winpipe, "pipe_client_sid", lambda handle: None)
    name, server, t = _serve(None)
    try:
        assert _ask_pong(name) == {"id": 7, "result": "pong"}
    finally:
        _stop(server, t)


def test_unidentified_connections_share_one_users_bound():
    admission = Admission(total=10, per_peer=2, evict=False)
    a = admission.admit(UNIDENTIFIED, lambda: None)
    b = admission.admit(UNIDENTIFIED, lambda: None)
    assert admission.admit(UNIDENTIFIED, lambda: None) is None  # a silent flood stops here
    assert admission.identify(a, "S-1-5-21-1")
    assert admission.admit(UNIDENTIFIED, lambda: None) is not None  # room again
    assert not admission.identify(b, None)  # user cannot be told: refused


def test_identify_applies_the_per_user_bound():
    refuse = Admission(total=10, per_peer=1, evict=False)
    first = refuse.admit(UNIDENTIFIED, lambda: None)
    assert refuse.identify(first, "S-1-5-21-1")
    second = refuse.admit(UNIDENTIFIED, lambda: None)
    assert not refuse.identify(second, "S-1-5-21-1")
    assert refuse.identify(second, "S-1-5-21-2")

    cut = []
    evict = Admission(total=10, per_peer=1, evict=True)
    old = evict.admit(UNIDENTIFIED, lambda: cut.append("old"))
    assert evict.identify(old, "S-1-5-21-1")
    new = evict.admit(UNIDENTIFIED, lambda: cut.append("new"))
    assert evict.identify(new, "S-1-5-21-1") and cut == ["old"]
    assert not evict.identify(old, "S-1-5-21-1")  # already cut
