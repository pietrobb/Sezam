"""Review 1141a20 (AI broker, the A5-A11 remainder): 'ai off' saved by another process did not stop a request already connecting.

Review 7c10379 had HTTP and FTP read the switch once the connection
stands, but that check read only this broker's in-memory flag. When the
brake reaches the vault without reaching the broker (the control channel
busy or down: 'sezam ai off' then writes the switch itself), a request in
its connect phase went out; only the kill switch backstop, up to two seconds
later, would have cut it. The check after connecting now reads the saved
switch as well.
"""

# ruff: noqa: F811  (pytest fixtures imported from the F2/H1 tests)
from __future__ import annotations

import socket

import pytest

pytest.importorskip("OpenSSL")
pytest.importorskip("pyftpdlib")

from sezam.vault import ai_access  # noqa: E402
from tests.test_ai_f2_ftp import cert, explicit, transfers  # noqa: E402,F401,F811  (fixtures)
from tests.test_ai_f3_ftp_tool import _Env as _FTPEnv  # noqa: E402
from tests.test_ai_h1_http import https  # noqa: E402,F401,F811  (fixture)
from tests.test_ai_h2_http_tool import _Env as _HTTPEnv  # noqa: E402
from tests.test_review7_kill_switch_during_connect import _outcome  # noqa: E402


def _saved_off_while_connecting(monkeypatch, vault) -> list:
    """The first connect writes 'off' to the vault, as another process would."""
    real = socket.create_connection
    fired: list = []

    def wrapper(*args, **kwargs):
        sock = real(*args, **kwargs)
        if not fired:
            fired.append(True)
            ai_access.disable(vault, "cli")
        return sock

    monkeypatch.setattr(socket, "create_connection", wrapper)
    return fired


def test_http_request_connecting_when_another_process_saves_off(tmp_path, https, monkeypatch):
    env = _HTTPEnv(tmp_path, https)
    fired = _saved_off_while_connecting(monkeypatch, env.vault)

    code = _outcome(lambda: env.broker.http_request("Sites/blog", "POST", "/wp/v2/echo", body="x", agent_name="claude"))

    assert fired
    assert code in ("cut_off", "ai_disabled"), code
    assert https.seen == []


def test_ftp_operation_connecting_when_another_process_saves_off(tmp_path, transfers, explicit, cert, monkeypatch):
    env = _FTPEnv(tmp_path, transfers, explicit, ca=cert[1])
    fired = _saved_off_while_connecting(monkeypatch, env.vault)

    code = _outcome(lambda: env.broker.ftp("Hosting/web", "mkdir", "/new", agent_name="claude"))

    assert fired
    assert code in ("cut_off", "ai_disabled"), code
    assert not explicit.saw("PASS") and not explicit.saw("MKD")
