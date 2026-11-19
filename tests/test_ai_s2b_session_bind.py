"""AI broker TODO section 2 (S2b): session-bind@openssh.com.

The agent verifies the server host key's signature over the session id and
signs an entry's key only for that session and the entry's own host (a
pinned key exactly, otherwise known_hosts for host:port), refuses forwarded
agents unless the entry allows it, and without a binding refuses every entry
unless it allows ``ssh_agent_unbound`` and no other entry pins that key.
Bindings belong to one client connection.
"""

from __future__ import annotations

import io
import os

import paramiko
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from sezam.mcp import ssh_agent
from sezam.mcp.ssh_agent import (
    SESSION_BIND,
    SSH_AGENT_FAILURE,
    SSH_AGENT_SUCCESS,
    AgentConnection,
    host_key_fingerprint,
)
from tests.test_ai_s2a_ssh_agent import (  # noqa: F401  (fixtures)
    _Client,
    _audit,
    _openssh,
    _pkey,
    _s,
    _sign_request,
    _signature,
    _ssh_entry,
    _userauth,
    _verify,
    agent_server,
    approvals,
    keys,
    paramiko_login,
    service,
    vault,
)

FAILURE = bytes([SSH_AGENT_FAILURE])
SUCCESS = bytes([SSH_AGENT_SUCCESS])


@pytest.fixture(scope="module")
def hosts():
    return {
        "web": paramiko.Ed25519Key.from_private_key(
            io.StringIO(_openssh(ed25519.Ed25519PrivateKey.generate()))
        ),
        "other": paramiko.Ed25519Key.from_private_key(
            io.StringIO(_openssh(ed25519.Ed25519PrivateKey.generate()))
        ),
        "rsa": paramiko.RSAKey(key=rsa.generate_private_key(65537, 2048)),
    }


@pytest.fixture(scope="module")
def user_keys():
    return {
        name: _openssh(ed25519.Ed25519PrivateKey.generate())
        for name in ("pin", "unb", "fwd", "rsahost", "loose")
    }


def _pin(host: paramiko.PKey) -> dict:
    return {"key": "host_key_sha256", "value": host_key_fingerprint(host.asbytes())}


def _known(name: str, host_key: paramiko.PKey, *, hashed=False) -> None:
    """Add a known_hosts line (the test's file, see conftest)."""
    if hashed:
        name = paramiko.HostKeys.hash_host(name)
    with open(ssh_agent.known_hosts_path(), "a") as f:
        f.write(f"{name} {host_key.get_name()} {host_key.get_base64()}\n")


@pytest.fixture
def bound_vault(vault, hosts, user_keys):  # noqa: F811
    folder = vault.resolve_path("Servers")[0]
    _ssh_entry(vault, folder, "Pinned", user_keys["pin"], username="ai-web", extra=[_pin(hosts["web"])])
    _ssh_entry(
        vault, folder, "Unbound", user_keys["unb"], username="ai-web",
        actions=("ssh_agent", "ssh_agent_unbound"), extra=[_pin(hosts["web"])],
    )
    _ssh_entry(
        vault, folder, "Forward", user_keys["fwd"], username="ai-web",
        actions=("ssh_agent", "ssh_agent_forwarding"), extra=[_pin(hosts["web"])],
    )
    _ssh_entry(vault, folder, "RsaHost", user_keys["rsahost"], username="ai-web", extra=[_pin(hosts["rsa"])])
    return vault


def _bind(host: paramiko.PKey, session_id: bytes, *, forwarding=False, signed_by=None, algorithm=None) -> bytes:
    signature = (signed_by or host).sign_ssh_data(session_id, algorithm)
    return (
        bytes([27]) + _s(SESSION_BIND) + _s(host.asbytes()) + _s(session_id)
        + _s(signature.asbytes()) + bytes([1 if forwarding else 0])
    )


def _userauth_for(session_id: bytes, key: paramiko.PKey, username="ai-web", **kw) -> bytes:
    data = _userauth(username, "ssh-ed25519", key.asbytes(), **kw)
    # Replace the random session id _userauth put first.
    first = 4 + int.from_bytes(data[:4], "big")
    return _s(session_id) + data[first:]


def _try(service, connection, key, session_id, **kw):  # noqa: F811
    data = _userauth_for(session_id, key, **kw)
    return data, service.handle(_sign_request(key.asbytes(), data), connection)


def _reasons(records):
    return [r.get("reason") for r in records if r["operation"] == "agent_sign_denied"]


def test_pinned_entry_signs_only_for_its_bound_host(bound_vault, service, hosts, user_keys, monkeypatch):  # noqa: F811
    records = _audit(bound_vault, monkeypatch)
    key = _pkey(user_keys["pin"])
    sid = os.urandom(32)
    connection = AgentConnection()
    assert service.handle(_bind(hosts["web"], sid), connection) == SUCCESS
    data, reply = _try(service, connection, key, sid)
    assert _verify(key, data, _signature(reply))
    assert records[-1]["operation"] == "agent_sign"
    assert records[-1]["bound_host_key"] == host_key_fingerprint(hosts["web"].asbytes())
    assert records[-1]["forwarded"] is False

    other = AgentConnection()
    sid2 = os.urandom(32)
    assert service.handle(_bind(hosts["other"], sid2), other) == SUCCESS
    assert _try(service, other, key, sid2)[1] == FAILURE
    assert _reasons(records) == ["host_key_mismatch"]


def test_rsa_host_key_binding_verifies(bound_vault, service, hosts, user_keys):
    key = _pkey(user_keys["rsahost"])
    sid = os.urandom(32)
    connection = AgentConnection()
    assert service.handle(_bind(hosts["rsa"], sid, algorithm="rsa-sha2-512"), connection) == SUCCESS
    data, reply = _try(service, connection, key, sid)
    assert _verify(key, data, _signature(reply))


def test_pinned_entry_without_session_bind_is_refused_unless_allowed(bound_vault, service, user_keys, monkeypatch):
    records = _audit(bound_vault, monkeypatch)
    assert _try(service, AgentConnection(), _pkey(user_keys["pin"]), os.urandom(32))[1] == FAILURE
    assert _reasons(records) == ["session_not_bound"]

    key = _pkey(user_keys["unb"])
    data, reply = _try(service, AgentConnection(), key, os.urandom(32))
    assert _verify(key, data, _signature(reply))
    assert records[-1]["bound_host_key"] is None


def _bound(service, host):
    sid, connection = os.urandom(32), AgentConnection()
    assert service.handle(_bind(host, sid), connection) == SUCCESS
    return connection, sid


@pytest.mark.parametrize("port", [22, 2222])
@pytest.mark.parametrize("hashed", [False, True])
def test_unpinned_entry_signs_only_for_its_known_host(bound_vault, service, hosts, user_keys, monkeypatch, port, hashed):
    """As the MCP broker connects it: only to its host:port, whose host key
    must be in known_hosts. The AI cannot widen that by skipping session-bind."""
    folder = bound_vault.resolve_path("Servers")[0]
    _ssh_entry(
        bound_vault, folder, "Loose", user_keys["loose"], username="ai-web",
        extra=[{"key": "port", "value": str(port)}],
    )
    records = _audit(bound_vault, monkeypatch)
    key = _pkey(user_keys["loose"])

    assert _try(service, AgentConnection(), key, os.urandom(32))[1] == FAILURE
    connection, sid = _bound(service, hosts["web"])
    assert _try(service, connection, key, sid)[1] == FAILURE  # nothing in known_hosts

    name = "loose.example.test" if port == 22 else f"[loose.example.test]:{port}"
    _known(name, hosts["web"], hashed=hashed)
    _known("other.example.test", hosts["other"])
    connection, sid = _bound(service, hosts["other"])
    assert _try(service, connection, key, sid)[1] == FAILURE  # another server
    assert _reasons(records) == ["session_not_bound", "host_key_unknown", "host_key_mismatch"]

    connection, sid = _bound(service, hosts["web"])
    data, reply = _try(service, connection, key, sid)
    assert _verify(key, data, _signature(reply))
    assert records[-1]["bound_host_key"] == host_key_fingerprint(hosts["web"].asbytes())


@pytest.mark.parametrize("how", ["wrong_signer", "wrong_session", "garbage", "bad_flag"])
def test_unverifiable_binding_is_refused_and_binds_nothing(bound_vault, service, hosts, user_keys, how):
    sid = os.urandom(32)
    if how == "wrong_signer":
        message = _bind(hosts["web"], sid, signed_by=hosts["other"])
    elif how == "wrong_session":
        message = _bind(hosts["web"], sid)
        message = message.replace(sid, os.urandom(32))
    elif how == "garbage":
        message = bytes([27]) + _s(SESSION_BIND) + _s(hosts["web"].asbytes()) + _s(sid) + _s(b"x") + b"\x00"
    else:
        message = _bind(hosts["web"], sid)[:-1] + b"\x02"
    connection = AgentConnection()
    assert service.handle(message, connection) == FAILURE
    assert connection.bindings == []
    assert _try(service, connection, _pkey(user_keys["pin"]), sid)[1] == FAILURE


def test_signature_for_another_session_than_the_binding_is_refused(bound_vault, service, hosts, user_keys, keys, monkeypatch):
    records = _audit(bound_vault, monkeypatch)
    sid = os.urandom(32)
    connection = AgentConnection()
    assert service.handle(_bind(hosts["web"], sid), connection) == SUCCESS
    pinned = _pkey(user_keys["pin"])
    assert _try(service, connection, pinned, os.urandom(32))[1] == FAILURE
    # Host-bound userauth naming another host key than the verified one.
    assert _try(
        service, connection, pinned, sid,
        method="publickey-hostbound-v00@openssh.com", host_key=hosts["other"].asbytes(),
    )[1] == FAILURE
    # Also for an unpinned entry: the session is bound.
    assert _try(service, connection, _pkey(keys["ed"]), os.urandom(32))[1] == FAILURE
    assert _reasons(records) == ["session_mismatch"] * 3

    data, reply = _try(
        service, connection, pinned, sid,
        method="publickey-hostbound-v00@openssh.com", host_key=hosts["web"].asbytes(),
    )
    assert _verify(pinned, data, _signature(reply))


def test_forwarded_agent_signs_only_for_entries_that_allow_it(bound_vault, service, hosts, user_keys, keys, monkeypatch):
    records = _audit(bound_vault, monkeypatch)
    connection = AgentConnection()
    # Hop 1: the local ssh forwards the agent to 'other'; hop 2: from there to 'web'.
    assert service.handle(_bind(hosts["other"], os.urandom(32), forwarding=True), connection) == SUCCESS
    sid = os.urandom(32)
    assert service.handle(_bind(hosts["web"], sid), connection) == SUCCESS

    assert _try(service, connection, _pkey(user_keys["pin"]), sid)[1] == FAILURE
    assert _try(service, connection, _pkey(keys["ed"]), sid)[1] == FAILURE
    assert _reasons(records) == ["forwarding_refused", "forwarding_refused"]

    key = _pkey(user_keys["fwd"])
    data, reply = _try(service, connection, key, sid)
    assert _verify(key, data, _signature(reply))
    assert records[-1]["forwarded"] is True


def test_connection_bound_for_authentication_cannot_be_rebound(bound_vault, service, hosts):
    sid = os.urandom(32)
    connection = AgentConnection()
    assert service.handle(_bind(hosts["web"], sid), connection) == SUCCESS
    assert service.handle(_bind(hosts["web"], sid), connection) == SUCCESS  # the same again
    assert service.handle(_bind(hosts["other"], os.urandom(32)), connection) == FAILURE
    assert [b.host_key for b in connection.bindings] == [hosts["web"].asbytes()]


def test_at_most_16_bindings(bound_vault, service, hosts):
    connection = AgentConnection()
    for _ in range(16):
        assert service.handle(_bind(hosts["other"], os.urandom(32), forwarding=True), connection) == SUCCESS
    assert service.handle(_bind(hosts["web"], os.urandom(32)), connection) == FAILURE


def test_shared_key_resolves_to_the_entry_pinned_to_the_bound_host(vault, service, hosts, user_keys, monkeypatch):  # noqa: F811
    folder = vault.resolve_path("Servers")[0]
    pem = user_keys["pin"]
    _ssh_entry(vault, folder, "SharedPinned", pem, username="ai-web", extra=[_pin(hosts["web"])])
    # Even allowing an unbound agent, the looser entry must not undo the pin.
    _ssh_entry(vault, folder, "SharedLoose", pem, username="ai-web", actions=("ssh_agent", "ssh_agent_unbound"))
    _known("sharedloose.example.test", hosts["other"])
    ids = {e["name"]: e["id"] for e in vault.list_entries(folder)}
    records = _audit(vault, monkeypatch)
    key = _pkey(pem)

    connection, sid = _bound(service, hosts["web"])
    data, reply = _try(service, connection, key, sid)
    assert _verify(key, data, _signature(reply))
    assert records[-1]["entry_id"] == ids["SharedPinned"]

    # Unbound the signature would work on the pinned host too: refused.
    assert _try(service, AgentConnection(), key, os.urandom(32))[1] == FAILURE
    assert _reasons(records) == ["session_not_bound", "session_not_bound"]

    # The looser entry's own (known) host is fine.
    connection, sid = _bound(service, hosts["other"])
    data, reply = _try(service, connection, key, sid)
    assert _verify(key, data, _signature(reply))
    assert records[-1]["entry_id"] == ids["SharedLoose"]


def test_unbound_paramiko_login_cannot_use_a_pinned_key_through_a_looser_entry(vault, agent_server, hosts, user_keys):  # noqa: F811
    """End to end: paramiko sends no session-bind; the pinned host accepts
    the key, a second entry holds it without a pin. No login."""
    folder = vault.resolve_path("Servers")[0]
    pem = user_keys["pin"]
    _ssh_entry(vault, folder, "SharedPinned", pem, username="ai-web", extra=[_pin(hosts["web"])])
    _ssh_entry(vault, folder, "SharedLoose", pem, username="ai-web", actions=("ssh_agent", "ssh_agent_unbound"))
    assert not paramiko_login(agent_server.path, _pkey(pem), "ai-web", hosts["web"])

    # Not even through an unpinned entry of its own without ssh_agent_unbound.
    _ssh_entry(vault, folder, "Loose", user_keys["loose"], username="ai-web")
    assert not paramiko_login(agent_server.path, _pkey(user_keys["loose"]), "ai-web", hosts["web"])


def test_bindings_belong_to_one_connection(bound_vault, agent_server, hosts, user_keys):  # noqa: F811
    key = _pkey(user_keys["pin"])
    sid = os.urandom(32)
    first, second = _Client(agent_server.path), _Client(agent_server.path)
    try:
        assert first.request(_bind(hosts["web"], sid)) == SUCCESS
        data = _userauth_for(sid, key)
        assert second.request(_sign_request(key.asbytes(), data)) == FAILURE
        assert _verify(key, data, _signature(first.request(_sign_request(key.asbytes(), data))))
    finally:
        first.close()
        second.close()


def test_mcp_policy_accepts_the_agent_policy_actions():
    from sezam import cli

    option = next(p for p in cli.mcp_policy.params if p.name == "allow_action")
    assert {"ssh_agent_forwarding", "ssh_agent_unbound"} <= set(option.type.choices)
