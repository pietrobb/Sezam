"""AI broker TODO section 3 (S3a): Sezam as an SSH CA.

An "AI SSH CA" entry (field ``ssh_ca``) holds an Ed25519 CA key that
``sezam ssh-agent`` never offers or uses as a login key. It lists a
short-lived ``ssh-ed25519-cert-v01@openssh.com`` certificate for an
ephemeral in-memory key instead (principal = the entry's username, TTL 10
minutes or ``cert_ttl_minutes`` up to 60, only ``permit-pty``, optional
``source-address``, key id ``sezam-ai:<entry>:<epoch>:<nonce>``) and signs
with that key. Lock and AI off drop the certificate; a new AI epoch gets a
new one. Golden tests: ``ssh-keygen -L`` reads the certificate and a real
``sshd`` with ``TrustedUserCAKeys`` and ``AuthorizedKeysFile none`` accepts
it (Linux, where sshd is installed).
"""

from __future__ import annotations

import base64
import getpass
import io
import os
import re
import shutil
import socket
import subprocess
import sys
import time

import paramiko
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from sezam.mcp import ssh_agent, ssh_cert
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.ssh import SSHBrokerError, SSHCredentials, SSHManager
from sezam.mcp.ssh_agent import (
    SSH_AGENT_FAILURE,
    SSHAgentServer,
    SSHAgentService,
    default_endpoint,
    host_key_fingerprint,
)
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_ai_s2a_ssh_agent import (
    _audit,
    _identities,
    _openssh,
    _s,
    _sign_request,
    _signature,
    _ssh_entry,
)
from tests.test_mcp_ssh import FAST_PARAMS

CERT = "ssh-ed25519-cert-v01@openssh.com"
FAILURE = bytes([SSH_AGENT_FAILURE])
UNBOUND = ("ssh_agent", "ssh_agent_unbound")  # protocol tests sign without session-bind


def _ca_fields(**extra) -> list[dict]:
    return [{"key": "ssh_ca", "value": "yes"}] + [
        {"key": key, "value": value} for key, value in extra.items()
    ]


@pytest.fixture(scope="module")
def ca_pem():
    return _openssh(ed25519.Ed25519PrivateKey.generate())


@pytest.fixture
def vault(tmp_path, ca_pem):
    vault = Vault.create(tmp_path / "vault", "test", FAST_PARAMS)
    folder = vault.create_node("Servers")
    _ssh_entry(vault, folder, "CA", ca_pem, username="ai-web", actions=UNBOUND, extra=_ca_fields())
    yield vault
    vault.lock()


@pytest.fixture
def service(vault):
    return SSHAgentService(MCPBroker(vault, ApprovalManager()))


def _entry_id(vault, name="CA") -> str:
    folder = vault.resolve_path("Servers")[0]
    return next(e["id"] for e in vault.list_entries(folder) if e["name"] == name)


# ── certificate parsing (independent of the implementation) ──


class _R:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        out = self.data[self.pos:self.pos + n]
        assert len(out) == n
        self.pos += n
        return out

    def u32(self):
        return int.from_bytes(self.take(4), "big")

    def u64(self):
        return int.from_bytes(self.take(8), "big")

    def s(self):
        return self.take(self.u32())

    def strings(self):
        r, out = _R(self.s()), []
        while r.pos < len(r.data):
            out.append(r.s())
        return out


def _parse(blob: bytes) -> dict:
    r = _R(blob)
    cert = {"type_name": r.s().decode(), "nonce": r.s(), "pk": r.s(), "serial": r.u64(), "type": r.u32()}
    cert["key_id"] = r.s().decode()
    cert["principals"] = [p.decode() for p in r.strings()]
    cert["valid_after"], cert["valid_before"] = r.u64(), r.u64()
    options = r.strings()
    cert["critical"] = {options[i].decode(): options[i + 1] for i in range(0, len(options), 2)}
    extensions = r.strings()
    cert["extensions"] = {extensions[i].decode(): extensions[i + 1] for i in range(0, len(extensions), 2)}
    cert["reserved"] = r.s()
    cert["ca"] = r.s()
    signed = blob[:r.pos]
    sig = _R(r.s())
    cert["sig_type"], cert["sig"] = sig.s().decode(), sig.s()
    assert r.pos == len(blob)
    ca = _R(cert["ca"])
    assert ca.s() == b"ssh-ed25519"
    ed25519.Ed25519PublicKey.from_public_bytes(ca.s()).verify(cert["sig"], signed)  # raises if forged
    return cert


def _cert_userauth(blob: bytes, username="ai-web", algorithm=CERT, session_id=None) -> bytes:
    return (
        _s(session_id or os.urandom(32)) + bytes([50]) + _s(username) + _s("ssh-connection")
        + _s("publickey") + b"\x01" + _s(algorithm) + _s(blob)
    )


def _certs(service) -> list[tuple[bytes, str]]:
    return [(blob, c) for blob, c in _identities(service) if blob.startswith(_s(CERT))]


# ── identities and the certificate ──


def test_ca_entry_lists_a_certificate_never_the_ca_key(service, ca_pem):
    listed = _identities(service)
    ca_blob = paramiko.Ed25519Key.from_private_key(io.StringIO(ca_pem)).asbytes()
    assert ca_blob not in [blob for blob, _ in listed]
    assert [c for _, c in listed] == ["sezam-cert:Servers/CA"]
    assert listed[0][0].startswith(_s(CERT))


def test_certificate_is_short_lived_minimal_and_signed_by_the_ca(vault, service, ca_pem):
    before = int(time.time())
    cert = _parse(_certs(service)[0][0])
    ca_key = paramiko.Ed25519Key.from_private_key(io.StringIO(ca_pem))
    assert cert["type_name"] == CERT and cert["type"] == 1  # user certificate
    assert cert["ca"] == ca_key.asbytes() and cert["sig_type"] == "ssh-ed25519"
    assert cert["principals"] == ["ai-web"]
    assert cert["critical"] == {}
    assert cert["extensions"] == {"permit-pty": b""}
    assert cert["reserved"] == b"" and len(cert["nonce"]) == 32 and len(cert["pk"]) == 32
    assert cert["pk"] != ca_key.asbytes()[-32:]  # an ephemeral key, not the CA
    epoch = ai_access.read_state(vault).epoch
    assert re.fullmatch(rf"sezam-ai:{_entry_id(vault)}:{epoch}:[0-9a-f]{{16}}", cert["key_id"])
    assert before + 600 <= cert["valid_before"] <= int(time.time()) + 600
    assert cert["valid_before"] - cert["valid_after"] == 600 + ssh_cert.CLOCK_SKEW


def test_ttl_and_source_address_come_from_the_entry(vault, ca_pem):
    folder = vault.resolve_path("Servers")[0]
    _ssh_entry(
        vault, folder, "Long", ca_pem, username="ops", actions=UNBOUND,
        extra=_ca_fields(cert_ttl_minutes="60", source_address="10.0.0.1, 192.168.1.7/24"),
    )
    by_comment = {c: _parse(b) for b, c in _certs(SSHAgentService(MCPBroker(vault, ApprovalManager())))}
    cert = by_comment["sezam-cert:Servers/Long"]
    assert cert["valid_before"] - cert["valid_after"] == 3600 + ssh_cert.CLOCK_SKEW
    assert cert["principals"] == ["ops"]
    assert cert["critical"] == {"source-address": _s("10.0.0.1/32,192.168.1.0/24")}
    assert cert["extensions"] == {"permit-pty": b""}


@pytest.mark.parametrize("extra", [
    {"cert_ttl_minutes": "61"},
    {"cert_ttl_minutes": "0"},
    {"cert_ttl_minutes": "ten"},
    {"source_address": "10.0.0.1, example.com"},
])
def test_invalid_certificate_settings_are_not_served(tmp_path, ca_pem, extra):
    vault = Vault.create(tmp_path / "v", "test", FAST_PARAMS)
    folder = vault.create_node("Servers")
    _ssh_entry(vault, folder, "Bad", ca_pem, username="ai-web", actions=UNBOUND, extra=_ca_fields(**extra))
    assert _identities(SSHAgentService(MCPBroker(vault, ApprovalManager()))) == []
    vault.lock()


def test_non_ed25519_ca_key_is_not_served(tmp_path):
    vault = Vault.create(tmp_path / "v", "test", FAST_PARAMS)
    folder = vault.create_node("Servers")
    pem = _openssh(rsa.generate_private_key(65537, 2048))
    _ssh_entry(vault, folder, "RsaCA", pem, username="ai-web", actions=UNBOUND, extra=_ca_fields())
    assert _identities(SSHAgentService(MCPBroker(vault, ApprovalManager()))) == []
    vault.lock()


# ── signing ──


def test_signs_with_the_ephemeral_key_and_audits_the_key_id(vault, service, monkeypatch):
    records = _audit(vault, monkeypatch)
    blob = _certs(service)[0][0]
    cert = _parse(blob)
    data = _cert_userauth(blob)
    signature = _signature(service.handle(_sign_request(blob, data)))
    assert signature.get_text() == "ssh-ed25519"
    ed25519.Ed25519PublicKey.from_public_bytes(cert["pk"]).verify(signature.get_binary(), data)
    signed = [r for r in records if r["operation"] == "agent_sign"]
    assert signed[-1]["cert_key_id"] == cert["key_id"]
    assert signed[-1]["cert_serial"] == cert["serial"]
    assert signed[-1]["username"] == "ai-web"


@pytest.mark.parametrize("change", [
    {"flags": 2},
    {"algorithm": "ssh-ed25519"},
    {"username": "root"},
])
def test_refuses_other_algorithms_and_principals(service, change):
    blob = _certs(service)[0][0]
    data = _cert_userauth(blob, change.get("username", "ai-web"), change.get("algorithm", CERT))
    assert service.handle(_sign_request(blob, data, change.get("flags", 0))) == FAILURE


def test_ca_key_itself_never_signs(service, ca_pem):
    ca_key = paramiko.Ed25519Key.from_private_key(io.StringIO(ca_pem))
    data = _cert_userauth(ca_key.asbytes(), algorithm="ssh-ed25519")
    assert service.handle(_sign_request(ca_key.asbytes(), data)) == FAILURE


def test_certificate_is_reused_then_renewed_before_it_expires(service, monkeypatch):
    first = _certs(service)[0][0]
    assert _certs(service)[0][0] == first
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now + 600 - ssh_agent.CERT_RENEW_SECONDS + 1)
    # Still valid: a client that listed it may finish signing with it ...
    assert service.handle(_sign_request(first, _cert_userauth(first)))[0] != SSH_AGENT_FAILURE
    # ... but a new listing gets a fresh certificate.
    second = _certs(service)[0][0]
    assert second != first and _parse(second)["key_id"] != _parse(first)["key_id"]
    monkeypatch.setattr(time, "time", lambda: now + 601)
    assert service.handle(_sign_request(first, _cert_userauth(first))) == FAILURE


def test_kill_switch_and_lock_drop_the_certificate(vault, service):
    first = _certs(service)[0][0]
    ai_access.disable(vault, "test")
    assert _identities(service) == []
    assert service.handle(_sign_request(first, _cert_userauth(first))) == FAILURE
    ai_access.enable(vault, "test")
    # A new epoch: the old certificate is gone, the new one names the epoch.
    assert service.handle(_sign_request(first, _cert_userauth(first))) == FAILURE
    second = _certs(service)[0][0]
    assert second != first
    assert _parse(second)["key_id"].split(":")[2] == str(ai_access.read_state(vault).epoch)
    service.clear_grants()  # what 'sezam ssh-agent' does on lock
    assert service.handle(_sign_request(second, _cert_userauth(second))) == FAILURE
    vault.lock()
    assert _identities(service) == []


def test_tier1_dialog_names_the_certificate(tmp_path, ca_pem):
    vault = Vault.create(tmp_path / "v", "test", FAST_PARAMS)
    folder = vault.create_node("Servers")
    _ssh_entry(vault, folder, "CA", ca_pem, username="ai-web", tier=1, actions=UNBOUND, extra=_ca_fields())
    approvals = ApprovalManager()
    seen = []

    def answer(request):
        seen.append(request)
        approvals.approve(request.request_id)

    approvals.set_on_request(answer)
    service = SSHAgentService(MCPBroker(vault, approvals))
    blob = _certs(service)[0][0]
    assert service.handle(_sign_request(blob, _cert_userauth(blob)))[0] != SSH_AGENT_FAILURE
    assert seen[0].target["username"] == "ai-web"
    assert seen[0].target["certificate"].startswith("Sezam SSH CA, valid until ")
    vault.lock()


def test_unbound_signing_needs_the_explicit_action(tmp_path, ca_pem):
    vault = Vault.create(tmp_path / "v", "test", FAST_PARAMS)
    folder = vault.create_node("Servers")
    _ssh_entry(vault, folder, "CA", ca_pem, username="ai-web", actions=("ssh_agent",), extra=_ca_fields())
    service = SSHAgentService(MCPBroker(vault, ApprovalManager()))
    blob = _certs(service)[0][0]
    assert service.handle(_sign_request(blob, _cert_userauth(blob))) == FAILURE
    vault.lock()


def test_mcp_broker_never_logs_in_with_a_ca_key(vault):
    credentials = SSHCredentials.from_entry(vault.read_entry(_entry_id(vault)))
    assert credentials.ssh_ca
    with pytest.raises(SSHBrokerError) as exc:
        SSHManager()._connect(credentials)
    assert exc.value.code == "invalid_entry"


# ── golden: OpenSSH reads and accepts the certificate ──

SSH_KEYGEN = shutil.which("ssh-keygen")


@pytest.mark.skipif(not SSH_KEYGEN, reason="needs ssh-keygen")
def test_ssh_keygen_reads_the_certificate(tmp_path, vault, ca_pem):
    folder = vault.resolve_path("Servers")[0]
    _ssh_entry(
        vault, folder, "Src", ca_pem, username="ops", actions=UNBOUND,
        extra=_ca_fields(source_address="10.0.0.1"),
    )
    service = SSHAgentService(MCPBroker(vault, ApprovalManager()))
    blob = dict((c, b) for b, c in _certs(service))["sezam-cert:Servers/Src"]
    cert = _parse(blob)
    path = tmp_path / "cert.pub"
    path.write_text(f"{CERT} {base64.b64encode(blob).decode()} test\n")
    out = subprocess.run(
        [SSH_KEYGEN, "-L", "-f", str(path)], capture_output=True, text=True, timeout=30
    )
    assert out.returncode == 0, out.stderr
    text = re.sub(r"\s+", " ", out.stdout)
    ca_fp = host_key_fingerprint(paramiko.Ed25519Key.from_private_key(io.StringIO(ca_pem)).asbytes())
    pk_fp = host_key_fingerprint(_s("ssh-ed25519") + _s(cert["pk"]))
    assert f"Type: {CERT} user certificate" in text
    assert f"Public key: ED25519-CERT {pk_fp}" in text
    assert f"Signing CA: ED25519 {ca_fp}" in text
    assert f'Key ID: "{cert["key_id"]}"' in text
    assert f"Serial: {cert['serial']}" in text
    assert "Principals: ops Critical Options: source-address 10.0.0.1/32 Extensions: permit-pty" in text


SSHD = shutil.which("sshd") or next(
    (p for p in ("/usr/sbin/sshd", "/usr/local/sbin/sshd") if os.path.exists(p)), None
)
SSH = shutil.which("ssh")


@pytest.fixture
def sshd(tmp_path, ca_pem):
    """A real sshd trusting only the CA (no authorized keys at all)."""
    if not (sys.platform.startswith("linux") and SSHD and SSH):
        pytest.skip("needs a Linux sshd and ssh client")
    user = getpass.getuser()
    host_pem = _openssh(ed25519.Ed25519PrivateKey.generate())
    host_key = tmp_path / "host_ed25519"
    host_key.write_text(host_pem)
    host_key.chmod(0o600)
    ca = paramiko.Ed25519Key.from_private_key(io.StringIO(ca_pem))
    (tmp_path / "ca.pub").write_text(f"ssh-ed25519 {ca.get_base64()}\n")
    (tmp_path / "principals").mkdir()
    (tmp_path / "principals" / user).write_text(user + "\n")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    config = tmp_path / "sshd_config"
    config.write_text("\n".join([
        f"Port {port}",
        "ListenAddress 127.0.0.1",
        f"HostKey {host_key}",
        f"PidFile {tmp_path / 'sshd.pid'}",
        "UsePAM no",
        "StrictModes no",
        "PermitRootLogin prohibit-password",
        "PubkeyAuthentication yes",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        f"TrustedUserCAKeys {tmp_path / 'ca.pub'}",
        "AuthorizedKeysFile none",
        f"AuthorizedPrincipalsFile {tmp_path / 'principals'}/%u",
        "AllowAgentForwarding no",
        "AllowTcpForwarding no",
        "X11Forwarding no",
        "PermitTunnel no",
        "LogLevel VERBOSE",
        "",
    ]))
    if os.geteuid() == 0:
        os.makedirs("/run/sshd", exist_ok=True)
    log = open(tmp_path / "sshd.log", "w")
    proc = subprocess.Popen([SSHD, "-D", "-e", "-f", str(config)], stderr=log, stdout=log)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            if proc.poll() is not None:
                break
            time.sleep(0.1)
    if proc.poll() is not None:
        log.close()
        pytest.fail("sshd did not start: " + (tmp_path / "sshd.log").read_text())
    host = paramiko.Ed25519Key.from_private_key(io.StringIO(host_pem))
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(f"[127.0.0.1]:{port} ssh-ed25519 {host.get_base64()}\n")
    yield type("Sshd", (), dict(
        port=port, user=user, known_hosts=known_hosts, log=tmp_path / "sshd.log",
        fingerprint=host_key_fingerprint(host.asbytes()),
    ))
    proc.terminate()
    proc.wait(10)
    log.close()


def _agent_env(tmp_path, ca_pem, sshd, **extra):
    vault = Vault.create(tmp_path / "vault", "test", FAST_PARAMS)
    folder = vault.create_node("Servers")
    _ssh_entry(
        vault, folder, "CA", ca_pem, username=sshd.user, host="127.0.0.1",
        extra=_ca_fields(port=str(sshd.port), host_key_sha256=sshd.fingerprint, **extra),
    )
    agent = SSHAgentServer(SSHAgentService(MCPBroker(vault, ApprovalManager())), default_endpoint())
    agent.start()
    (tmp_path / "ssh_config").write_text("")

    def ssh():
        return subprocess.run(
            [
                SSH, "-F", str(tmp_path / "ssh_config"), "-p", str(sshd.port),
                "-o", f"UserKnownHostsFile={sshd.known_hosts}",
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "BatchMode=yes",
                "-o", "PreferredAuthentications=publickey",
                "-o", "IdentityFile=" + str(tmp_path / "no_such_key"),
                "-o", "ConnectTimeout=10",
                f"{sshd.user}@127.0.0.1", "echo sezam-ok",
            ],
            env={**os.environ, "SSH_AUTH_SOCK": agent.path},
            capture_output=True, text=True, timeout=60,
        )

    return vault, agent, ssh


def _no_file_holds(root, secret: str) -> None:
    body = "".join(line for line in secret.splitlines() if "PRIVATE KEY" not in line)
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            try:
                data = open(os.path.join(dirpath, name), "rb").read()
            except OSError:
                continue
            assert body.encode() not in data, name


def test_real_sshd_accepts_the_certificate_and_logs_its_key_id(tmp_path, ca_pem, sshd, monkeypatch):
    vault, agent, ssh = _agent_env(tmp_path, ca_pem, sshd)
    records = _audit(vault, monkeypatch)
    try:
        result = ssh()
        assert result.returncode == 0, result.stderr + sshd.log.read_text()
        assert result.stdout.strip() == "sezam-ok"
        key_id = [r for r in records if r["operation"] == "agent_sign"][-1]["cert_key_id"]
        assert key_id.startswith(f"sezam-ai:{_entry_id(vault)}:")
        time.sleep(0.5)
        assert f'ID {key_id}' in sshd.log.read_text()

        ai_access.disable(vault, "test")
        assert ssh().returncode != 0
        _no_file_holds(tmp_path, ca_pem)
    finally:
        agent.stop()
        vault.lock()


def test_real_sshd_enforces_source_address(tmp_path, ca_pem, sshd):
    vault, agent, ssh = _agent_env(tmp_path, ca_pem, sshd, source_address="192.0.2.1")
    try:
        result = ssh()
        assert result.returncode != 0
        time.sleep(0.5)
        assert "permitted source address" in sshd.log.read_text()
    finally:
        agent.stop()
        vault.lock()
