"""AI broker TODO section 2 (S2a): ``sezam ssh-agent`` core.

The agent offers only keys of visible entries that allow ``ssh_agent``,
signs only a publickey userauth request for that key as the entry's
username (Ed25519, RSA SHA-2), refuses SHA-1 and every other message,
honours the kill switch and the lock, asks the owner for tier 1 and
audits every signature and refusal. Keys never touch the disk.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
from pathlib import Path

import paramiko
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from sezam import cli
from sezam.mcp import control
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.ssh_agent import (
    MAX_MESSAGE,
    SSH_AGENT_FAILURE,
    SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENT_SIGN_RESPONSE,
    SSHAgentServer,
    SSHAgentService,
    default_endpoint,
    parse_userauth_request,
)
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_mcp_ssh import FAST_PARAMS

RSA_PASSPHRASE = "rsa-key-passphrase"


def _openssh(private, passphrase: str | None = None) -> str:
    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    return private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, encryption
    ).decode()


def _pkey(pem: str, passphrase: str | None = None) -> paramiko.PKey:
    import io

    for kind in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return kind.from_private_key(io.StringIO(pem), password=passphrase)
        except (paramiko.SSHException, ValueError):
            continue
    raise AssertionError("test key does not load")


def _ssh_entry(vault, folder, name, pem, *, username, tier=0, actions=("ssh_agent",), extra=(), host=None):
    fields = [
        {"key": "host", "value": host or f"{name.lower()}.example.test"},
        {"key": "username", "value": username},
        {"key": "private_key", "value": pem, "sensitive": True},
        *extra,
    ]
    vault.create_entry(folder, name, fields, tier=tier, allowed_actions=list(actions))


@pytest.fixture(scope="module")
def keys():
    return {
        "ed": _openssh(ed25519.Ed25519PrivateKey.generate()),
        "rsa": _openssh(rsa.generate_private_key(65537, 2048), RSA_PASSPHRASE),
        "ecdsa": _openssh(ec.generate_private_key(ec.SECP256R1())),
        "other": _openssh(ed25519.Ed25519PrivateKey.generate()),
        "hidden": _openssh(ed25519.Ed25519PrivateKey.generate()),
        "tier1": _openssh(ed25519.Ed25519PrivateKey.generate()),
    }


@pytest.fixture
def vault(tmp_path, keys):
    vault = Vault.create(tmp_path / "vault", "test", FAST_PARAMS)
    servers = vault.create_node("Servers")
    # The protocol tests sign without session-bind (S2b), which an entry
    # must allow explicitly.
    unbound = ("ssh_agent", "ssh_agent_unbound")
    _ssh_entry(vault, servers, "Ed", keys["ed"], username="ai-web", actions=unbound)
    _ssh_entry(
        vault, servers, "Rsa", keys["rsa"], username="deploy", actions=unbound,
        extra=[{"key": "passphrase", "value": RSA_PASSPHRASE, "sensitive": True}],
    )
    _ssh_entry(vault, servers, "Ecdsa", keys["ecdsa"], username="ai-web", actions=unbound)
    _ssh_entry(vault, servers, "NoAgent", keys["other"], username="ai-web", actions=("ssh_execute",))
    _ssh_entry(vault, servers, "Hidden", keys["hidden"], username="ai-web", tier=2, actions=unbound)
    _ssh_entry(vault, servers, "Ask", keys["tier1"], username="ops", tier=1, actions=unbound)
    vault.create_entry(
        servers, "PasswordOnly",
        [
            {"key": "host", "value": "pw.example.test"},
            {"key": "username", "value": "ai-web"},
            {"key": "password", "value": "pw-secret", "sensitive": True},
        ],
        tier=0, allowed_actions=["ssh_agent"],
    )
    yield vault
    vault.lock()


@pytest.fixture
def approvals():
    return ApprovalManager()


@pytest.fixture
def service(vault, approvals):
    return SSHAgentService(MCPBroker(vault, approvals))


# ── wire helpers ──


def _s(value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode()
    return len(value).to_bytes(4, "big") + value


def _userauth(username: str, algorithm: str, blob: bytes, *, method="publickey", host_key=None) -> bytes:
    data = (
        _s(os.urandom(32)) + bytes([50]) + _s(username) + _s("ssh-connection")
        + _s(method) + b"\x01" + _s(algorithm) + _s(blob)
    )
    if host_key is not None:
        data += _s(host_key)
    return data


def _sign_request(blob: bytes, data: bytes, flags: int = 0) -> bytes:
    return bytes([13]) + _s(blob) + _s(data) + flags.to_bytes(4, "big")


def _identities(service) -> list[tuple[bytes, str]]:
    reply = service.handle(bytes([11]))
    assert reply[0] == SSH_AGENT_IDENTITIES_ANSWER
    count = int.from_bytes(reply[1:5], "big")
    pos, out = 5, []
    for _ in range(count):
        n = int.from_bytes(reply[pos:pos + 4], "big")
        blob = reply[pos + 4:pos + 4 + n]
        pos += 4 + n
        n = int.from_bytes(reply[pos:pos + 4], "big")
        out.append((blob, reply[pos + 4:pos + 4 + n].decode()))
        pos += 4 + n
    assert pos == len(reply)
    return out


def _signature(reply: bytes) -> paramiko.Message:
    assert reply[0] == SSH_AGENT_SIGN_RESPONSE, reply
    n = int.from_bytes(reply[1:5], "big")
    assert 5 + n == len(reply)
    return paramiko.Message(reply[5:])


def _sign(service, key: paramiko.PKey, username: str, algorithm: str, flags: int = 0, **kw):
    data = _userauth(username, algorithm, key.asbytes(), **kw)
    return data, service.handle(_sign_request(key.asbytes(), data, flags))


def _verify(key, data, signature) -> bool:
    # A key loaded from a private PEM cannot verify in paramiko; use its public half.
    return type(key)(data=key.asbytes()).verify_ssh_sig(data, signature)


def _audit(vault, monkeypatch) -> list[dict]:
    records: list[dict] = []
    original = vault._audit_log

    def spy(action, detail=None, *, strict=False):
        if action == "mcp_ssh":
            records.append(json.loads(detail))
        return original(action, detail, strict=strict)

    monkeypatch.setattr(vault, "_audit_log", spy)
    return records


# ── identities ──


def test_lists_only_visible_ed25519_and_rsa_keys_that_allow_ssh_agent(service, keys):
    listed = _identities(service)
    by_comment = {comment: blob for blob, comment in listed}
    assert set(by_comment) == {"sezam:Servers/Ed", "sezam:Servers/Rsa", "sezam:Servers/Ask"}
    assert by_comment["sezam:Servers/Ed"] == _pkey(keys["ed"]).asbytes()
    assert by_comment["sezam:Servers/Rsa"] == _pkey(keys["rsa"], RSA_PASSPHRASE).asbytes()
    blobs = {blob for blob, _ in listed}
    for hidden in ("ecdsa", "other", "hidden"):
        assert _pkey(keys[hidden]).asbytes() not in blobs


def test_kill_switch_and_lock_hide_every_key_and_refuse_signing(vault, service, keys):
    key = _pkey(keys["ed"])
    data = _userauth("ai-web", "ssh-ed25519", key.asbytes())
    ai_access.disable(vault, "test")
    assert _identities(service) == []
    assert service.handle(_sign_request(key.asbytes(), data)) == bytes([SSH_AGENT_FAILURE])

    ai_access.enable(vault, "test")
    assert _identities(service)
    vault.lock()
    assert _identities(service) == []
    assert service.handle(_sign_request(key.asbytes(), data)) == bytes([SSH_AGENT_FAILURE])


# ── signing ──


def test_signs_ed25519_userauth_and_audits_it(vault, service, keys, monkeypatch):
    records = _audit(vault, monkeypatch)
    key = _pkey(keys["ed"])
    data, reply = _sign(service, key, "ai-web", "ssh-ed25519")
    signature = _signature(reply)
    assert _verify(key, data, signature)

    assert [r["operation"] for r in records] == ["agent_sign_start", "agent_sign"]
    done = records[-1]
    assert done["host"] == "ed.example.test"
    assert done["username"] == "ai-web"
    assert done["algorithm"] == "ssh-ed25519"
    assert done["approval"] == "auto"
    assert keys["ed"] not in json.dumps(records)


@pytest.mark.parametrize("flags, algorithm", [(2, "rsa-sha2-256"), (4, "rsa-sha2-512")])
def test_signs_rsa_with_sha2_only(service, keys, flags, algorithm):
    key = _pkey(keys["rsa"], RSA_PASSPHRASE)
    data, reply = _sign(service, key, "deploy", algorithm, flags)
    signature = _signature(reply)
    assert signature.get_text() == algorithm
    signature.rewind()
    assert _verify(key, data, signature)


@pytest.mark.parametrize(
    "key_name, algorithm, flags",
    [
        ("rsa", "ssh-rsa", 0),  # SHA-1
        ("rsa", "rsa-sha2-256", 2 | 8),  # unknown flag bit
        ("ed", "ssh-ed25519", 2),
    ],
)
def test_sha1_and_unknown_flags_are_refused(vault, service, keys, monkeypatch, key_name, algorithm, flags):
    records = _audit(vault, monkeypatch)
    key = _pkey(keys[key_name], RSA_PASSPHRASE if key_name == "rsa" else None)
    user = "deploy" if key_name == "rsa" else "ai-web"
    _, reply = _sign(service, key, user, algorithm, flags)
    assert reply == bytes([SSH_AGENT_FAILURE])
    assert [r["reason"] for r in records] == ["algorithm_refused"]


def test_username_must_match_the_entry(vault, service, keys, monkeypatch):
    records = _audit(vault, monkeypatch)
    key = _pkey(keys["ed"])
    _, reply = _sign(service, key, "root", "ssh-ed25519")
    assert reply == bytes([SSH_AGENT_FAILURE])
    assert records == [
        {
            "entry_id": records[0]["entry_id"],
            "operation": "agent_sign_denied",
            "host": "ed.example.test",
            "port": 22,
            "username": "ai-web",
            "requested_username": "root",
            "agent": "ssh-agent",
            "reason": "username_mismatch",
        }
    ]


def test_only_userauth_requests_for_that_key_are_signed(vault, service, keys, monkeypatch):
    records = _audit(vault, monkeypatch)
    key = _pkey(keys["ed"])
    other = _pkey(keys["tier1"]).asbytes()
    sshsig = b"SSHSIG" + _s("git") + _s(b"") + _s("sha512") + _s(os.urandom(64))
    bad = [
        sshsig,
        _userauth("ai-web", "ssh-ed25519", key.asbytes()) + b"x",
        _userauth("ai-web", "ssh-ed25519", key.asbytes(), method="password"),
        _userauth("ai-web", "ssh-ed25519", other),  # another key inside
        _userauth("ai-web", "rsa-sha2-256", key.asbytes()),  # algorithm mismatch
        os.urandom(16),
    ]
    for data in bad:
        assert service.handle(_sign_request(key.asbytes(), data)) == bytes([SSH_AGENT_FAILURE])
    assert [r["reason"] for r in records] == [
        "not_userauth", "not_userauth", "not_userauth",
        "request_mismatch", "request_mismatch", "not_userauth",
    ]
    assert all(r["operation"] == "agent_sign_denied" for r in records)


def test_host_bound_userauth_is_signed_and_host_key_recorded(vault, service, keys, monkeypatch):
    records = _audit(vault, monkeypatch)
    key = _pkey(keys["ed"])
    host_key = _pkey(keys["other"]).asbytes()
    data, reply = _sign(
        service, key, "ai-web", "ssh-ed25519",
        method="publickey-hostbound-v00@openssh.com", host_key=host_key,
    )
    assert _verify(key, data, _signature(reply))
    import hashlib

    assert records[-1]["server_host_key_sha256"] == hashlib.sha256(host_key).hexdigest()
    assert parse_userauth_request(data).server_host_key == host_key


@pytest.mark.parametrize("key_name", ["other", "hidden", "ecdsa"])
def test_keys_the_agent_does_not_offer_are_never_used(service, keys, key_name):
    key = _pkey(keys[key_name])
    algorithm = "ecdsa-sha2-nistp256" if key_name == "ecdsa" else "ssh-ed25519"
    _, reply = _sign(service, key, "ai-web", algorithm)
    assert reply == bytes([SSH_AGENT_FAILURE])


@pytest.mark.parametrize(
    "message",
    [
        bytes([17]) + _s("ssh-ed25519"),  # ADD_IDENTITY
        bytes([18]) + _s(b"blob"),  # REMOVE_IDENTITY
        bytes([19]),  # REMOVE_ALL_IDENTITIES
        bytes([20]) + _s("/usr/lib/pkcs11.so") + _s("pin"),  # ADD_SMARTCARD_KEY
        bytes([22]) + _s("passphrase"),  # LOCK
        bytes([23]) + _s("passphrase"),  # UNLOCK
        bytes([25]) + _s("ssh-ed25519"),  # ADD_ID_CONSTRAINED
        bytes([27]) + _s("session-bind@openssh.com"),  # EXTENSION (S2b)
        bytes([1]),  # SSH1 request
        bytes([11, 0]),  # identities with trailing data
        b"",
    ],
)
def test_every_other_message_fails_and_changes_nothing(service, message):
    before = _identities(service)
    assert service.handle(message) == bytes([SSH_AGENT_FAILURE])
    assert _identities(service) == before


def test_signature_is_refused_when_it_cannot_be_audited(vault, service, keys, monkeypatch):
    def broken(action, detail=None, *, strict=False):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(vault, "_audit_log", broken)
    signed = []
    monkeypatch.setattr(
        paramiko.Ed25519Key, "sign_ssh_data", lambda *a, **k: signed.append(1)
    )
    _, reply = _sign(service, _pkey(keys["ed"]), "ai-web", "ssh-ed25519")
    assert reply == bytes([SSH_AGENT_FAILURE])
    assert signed == []


# ── tier 1 ──


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_tier1_asks_the_owner(vault, service, approvals, keys, monkeypatch, decision):
    records = _audit(vault, monkeypatch)
    seen = []

    def answer(request):
        seen.append(request)
        getattr(approvals, decision)(request.request_id)

    approvals.set_on_request(answer)
    key = _pkey(keys["tier1"])
    data, reply = _sign(service, key, "ops", "ssh-ed25519")

    assert len(seen) == 1
    assert seen[0].target == {
        "entry": "Ask", "host": "ask.example.test", "port": 22, "username": "ops",
        "host_key": None,
        "host_unverified": "NOT verified (the client sent no session-bind; "
                           "the signature would work on any server)",
        "forwarded": None,
    }
    if decision == "approve":
        assert _verify(key, data, _signature(reply))
        assert records[-1]["operation"] == "agent_sign"
        assert records[-1]["approval"] == "owner"
    else:
        assert reply == bytes([SSH_AGENT_FAILURE])
        assert [(r["operation"], r["reason"]) for r in records] == [
            ("agent_sign_denied", "denied")
        ]


def test_tier1_refused_when_ai_is_turned_off_during_the_dialog(vault, service, approvals, keys, monkeypatch):
    records = _audit(vault, monkeypatch)

    def answer(request):
        ai_access.disable(vault, "test")
        approvals.approve(request.request_id)

    approvals.set_on_request(answer)
    _, reply = _sign(service, _pkey(keys["tier1"]), "ops", "ssh-ed25519")
    assert reply == bytes([SSH_AGENT_FAILURE])
    assert records[-1]["reason"] == "ai_disabled"


# ── endpoint ──


class _Client:
    """Raw agent connection (Unix socket or Windows pipe)."""

    def __init__(self, path: str):
        if sys.platform == "win32":
            import time

            deadline = time.monotonic() + 5
            while True:
                try:
                    self._pipe = open(path, "r+b", buffering=0)
                    break
                except OSError:  # busy until the server's next instance is up
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.02)
            self.send, self._read = self._pipe.write, self._pipe.read
        else:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.settimeout(5)
            self._sock.connect(path)
            self.send, self._read = self._sock.sendall, self._sock.recv

    def recv(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self._read(size - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def request(self, message: bytes) -> bytes:
        self.send(_s(message))
        length = int.from_bytes(self.recv(4), "big")
        return self.recv(length)

    def close(self):
        (self._pipe if sys.platform == "win32" else self._sock).close()


@pytest.fixture
def agent_server(service):
    server = SSHAgentServer(service, default_endpoint())
    server.start()
    yield server
    server.stop()


def test_endpoint_is_private_and_serves_many_requests_per_connection(agent_server, keys):
    if sys.platform != "win32":
        path = Path(agent_server.path)
        assert path.parent == control.run_dir()
        assert (path.stat().st_mode & 0o777) == 0o600
    client = _Client(agent_server.path)
    try:
        for _ in range(3):
            assert client.request(bytes([11]))[0] == SSH_AGENT_IDENTITIES_ANSWER
        key = _pkey(keys["ed"])
        data = _userauth("ai-web", "ssh-ed25519", key.asbytes())
        reply = client.request(_sign_request(key.asbytes(), data))
        assert _verify(key, data, _signature(reply))
    finally:
        client.close()


@pytest.mark.parametrize("length", [0, MAX_MESSAGE + 1])
def test_bad_frame_length_drops_the_connection(agent_server, length):
    client = _Client(agent_server.path)
    try:
        client.send(length.to_bytes(4, "big"))
        assert client.recv(4) == b""
    except OSError:
        pass
    finally:
        client.close()


def test_second_agent_on_the_same_endpoint_refuses_to_start(agent_server, service):
    with pytest.raises(OSError):
        SSHAgentServer(service, agent_server.path).start()


def test_paramiko_login_through_the_agent(agent_server, keys):
    """A real SSH handshake: paramiko's agent client talks to the endpoint
    and a paramiko server verifies the publickey signature."""
    key = _pkey(keys["rsa"], RSA_PASSPHRASE)
    host_key = paramiko.Ed25519Key.from_private_key(__import__("io").StringIO(keys["other"]))
    assert paramiko_login(agent_server.path, key, "deploy", host_key)


def paramiko_login(agent_path, key, username, host_key) -> bool:
    """Log in to a paramiko server (host_key, accepting key for username)
    with paramiko's agent client, which sends no session-bind."""

    class _Server(paramiko.ServerInterface):
        def get_allowed_auths(self, username):
            return "publickey"

        def check_auth_publickey(self, offered_user, offered):
            ok = offered_user == username and offered.asbytes() == key.asbytes()
            return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve():
        conn, _ = listener.accept()
        transport = paramiko.Transport(conn)
        transport.add_server_key(host_key)
        transport.start_server(server=_Server())
        transport.accept(5)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()

    client = _Client(agent_path)
    agent = paramiko.agent.AgentSSH()
    agent._connect(client)
    try:
        offered = {k.asbytes(): k for k in agent.get_keys()}
        assert key.asbytes() in offered
        transport = paramiko.Transport(("127.0.0.1", listener.getsockname()[1]))
        transport.start_client(timeout=5)
        try:
            transport.auth_publickey(username, offered[key.asbytes()])
        except paramiko.SSHException:
            return False
        finally:
            authenticated = transport.is_authenticated()
            transport.close()
        return authenticated
    finally:
        client.close()
        listener.close()


def test_private_key_is_never_written_to_disk(tmp_path, agent_server, keys):
    client = _Client(agent_server.path)
    try:
        key = _pkey(keys["ed"])
        data = _userauth("ai-web", "ssh-ed25519", key.asbytes())
        _signature(client.request(_sign_request(key.asbytes(), data)))
    finally:
        client.close()
    # Line 3 of an OpenSSH PEM already carries private key material.
    needles = [k.split("\n")[3].encode() for k in keys.values()]
    for root in (tmp_path, control.run_dir()):
        for path in Path(root).rglob("*"):
            if path.is_file():
                content = path.read_bytes()
                assert not any(n in content for n in needles), path


# ── CLI ──


def test_mcp_policy_accepts_the_ssh_agent_action():
    option = next(p for p in cli.mcp_policy.params if p.name == "allow_action")
    assert "ssh_agent" in option.type.choices


def test_ssh_agent_command_refuses_to_start_while_ai_is_off(tmp_path, monkeypatch):
    Vault.create(tmp_path, "pw", FAST_PARAMS).lock()
    monkeypatch.setenv("SEZAM_VAULT", str(tmp_path))
    ai_access.disable(Vault(tmp_path), "test")
    result = CliRunner().invoke(cli.main, ["ssh-agent"])
    assert result.exit_code != 0
    assert "AI access is turned off" in result.output
