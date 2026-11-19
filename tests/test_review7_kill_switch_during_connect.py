"""Review 7c10379 (AI broker, medium): 'ai off' during connection setup let the request go out.

close_all() cuts the connections it knows of. One still connecting had no
socket yet, so the cut only set a flag nobody read after the connect, and one
not yet registered (between the policy check and the connect) was not cut at
all: the reviewer's DELETE reached the server 2 s after 'ai off'. Both HTTP
and FTP now check the switch once the connection stands (FTP before the
password is sent and again before the operation).
"""

# ruff: noqa: F811  (pytest fixtures imported from the F2/H1 tests)
from __future__ import annotations

import socket

import pytest

pytest.importorskip("OpenSSL")
pytest.importorskip("pyftpdlib")

from sezam.mcp import ftp as ftp_mod  # noqa: E402
from sezam.mcp import http_api  # noqa: E402
from sezam.mcp.broker import MCPError  # noqa: E402
from tests.test_ai_f2_ftp import cert, explicit, transfers  # noqa: E402,F401,F811  (fixtures)
from tests.test_ai_f3_ftp_tool import _Env as _FTPEnv  # noqa: E402
from tests.test_ai_h1_http import https  # noqa: E402,F401,F811  (fixture)
from tests.test_ai_h2_http_tool import _Env as _HTTPEnv  # noqa: E402


def _outcome(call) -> str:
    """The error code the agent gets, whether returned or raised."""
    try:
        result = call()
    except MCPError as exc:
        return exc.code
    return result.get("code", result["status"])


def _switch_off_once(monkeypatch, module, name: str, broker, *, after: bool = True) -> list:
    """Wrap ``module.name`` so its first call turns AI off (after or before it runs)."""
    real = getattr(module, name)
    fired: list = []

    def wrapper(*args, **kwargs):
        if not fired and not after:
            fired.append(True)
            broker.disable_ai("test")
        result = real(*args, **kwargs)
        if not fired and after:
            fired.append(True)
            broker.disable_ai("test")
        return result

    monkeypatch.setattr(module, name, wrapper)
    return fired


def test_http_ai_off_while_the_socket_connects(tmp_path, https, monkeypatch):
    env = _HTTPEnv(tmp_path, https)
    fired = _switch_off_once(monkeypatch, socket, "create_connection", env.broker)

    code = _outcome(lambda: env.broker.http_request("Sites/blog", "POST", "/wp/v2/echo", body="x", agent_name="claude"))

    assert fired
    assert code in ("cut_off", "ai_disabled"), code
    assert https.seen == []


def test_http_ai_off_before_the_connection_is_registered(tmp_path, https, monkeypatch):
    env = _HTTPEnv(tmp_path, https)
    fired = _switch_off_once(monkeypatch, http_api, "_tls_context", env.broker)

    code = _outcome(lambda: env.broker.http_request("Sites/blog", "POST", "/wp/v2/echo", body="x", agent_name="claude"))

    assert fired
    assert code in ("cut_off", "ai_disabled"), code
    assert https.seen == []


def test_ftp_ai_off_while_the_socket_connects(tmp_path, transfers, explicit, cert, monkeypatch):
    env = _FTPEnv(tmp_path, transfers, explicit, ca=cert[1])
    fired = _switch_off_once(monkeypatch, socket, "create_connection", env.broker)

    code = _outcome(lambda: env.broker.ftp("Hosting/web", "mkdir", "/new", agent_name="claude"))

    assert fired
    assert code in ("cut_off", "ai_disabled"), code
    assert not explicit.saw("PASS") and not explicit.saw("MKD")


def test_ftp_ai_off_before_the_connection_is_registered(tmp_path, transfers, explicit, cert, monkeypatch):
    env = _FTPEnv(tmp_path, transfers, explicit, ca=cert[1])
    fired = _switch_off_once(monkeypatch, ftp_mod, "_tls_context", env.broker)

    code = _outcome(lambda: env.broker.ftp("Hosting/web", "mkdir", "/new", agent_name="claude"))

    assert fired
    assert code in ("cut_off", "ai_disabled"), code
    assert not explicit.saw("PASS") and not explicit.saw("MKD")


def test_ssh_ai_off_before_the_operation_reads_its_generation(monkeypatch):
    """SSH counted cuts from the start of the operation; one that came
    between the policy check and that start was not seen."""
    from sezam.mcp import ssh as ssh_mod

    class _Client:
        def close(self):
            pass

    manager = ssh_mod.SSHManager()
    monkeypatch.setattr(ssh_mod.SSHCredentials, "from_entry", classmethod(lambda cls, entry: None))
    monkeypatch.setattr(manager, "_connect", lambda credentials: _Client())
    manager.cut_check = lambda: True

    with pytest.raises(ssh_mod.SSHBrokerError) as err:
        with manager._running_client({}):
            pytest.fail("the operation ran after ai off")
    assert err.value.code == "cut_off"

    manager.cut_check = lambda: False
    with manager._running_client({}):
        pass


def test_requests_without_ai_off_still_go_through(tmp_path, https, transfers, explicit, cert):
    http_env = _HTTPEnv(tmp_path / "h", https)
    assert http_env.broker.http_request("Sites/blog", "GET", "/wp/v2/echo", agent_name="claude")["status"] == "ok"
    ftp_env = _FTPEnv(tmp_path / "f", transfers, explicit, ca=cert[1])
    assert ftp_env.broker.ftp("Hosting/web", "mkdir", "/new", agent_name="claude")["status"] == "ok"
