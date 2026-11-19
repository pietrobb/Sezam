"""``sezam ssh-agent``: an OpenSSH agent whose keys never leave the vault
(AI broker TODO, section 2).

A minimal ``PROTOCOL.agent`` (draft-miller-ssh-agent) server:

* ``REQUEST_IDENTITIES`` lists the public keys of the entries an AI agent
  can see (tier 0/1) whose policy explicitly allows the ``ssh_agent``
  action; tier 2 entries and hidden folders never appear.
* ``SIGN_REQUEST`` signs only an SSH ``publickey`` userauth request for
  that very key, as the entry's own username, with Ed25519 or RSA
  SHA-2 (256/512). SHA-1 RSA, other key types and anything that is not a
  userauth request get ``SSH_AGENT_FAILURE``.
* ``session-bind@openssh.com`` (OpenSSH >= 8.9) binds the connection to
  the server host key that signed the session identifier (verified). An
  entry's key then signs only for that session and only for the entry's
  own host, as the MCP broker would connect it: a pinned
  ``host_key_sha256`` must equal the bound host key, otherwise the bound
  host key must be in known_hosts for the entry's host:port. Without a
  binding nothing signs unless the entry's policy also allows
  ``ssh_agent_unbound`` (and no other entry holding that key is pinned
  without it). A forwarded agent signs only for entries that allow
  ``ssh_agent_forwarding``.
* An "AI SSH CA" entry (field ``ssh_ca``; section 3) is never offered with
  its own key: the agent lists a short-lived ``ssh-ed25519-cert-v01``
  certificate the CA key signs for an ephemeral in-memory Ed25519 key
  (principal = the entry's username, ``cert_ttl_minutes`` default 10, max
  60, only ``permit-pty``, optional ``source-address``, key id
  ``sezam-ai:<entry>:<ai epoch>:<nonce>``) and signs with that key, under
  the same binding, approval and audit rules. Lock and AI off drop it.
* Every other message (add/remove identities, lock/unlock, smartcards,
  other extensions) gets ``SSH_AGENT_FAILURE``: keys come only from the
  vault.

Tier 0 signs at once, tier 1 asks the owner first ("An AI agent wants to
log in as X on Y"); the owner may also allow that entry, host and user for
N minutes (a separate question, default No). With AI access turned
off or the vault locked the agent lists no keys and signs nothing. Every
signature (and every refusal for a vault key) is audited with the entry,
host and username. Private keys are parsed in memory per request and are
never written anywhere.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import logging
import os
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

import paramiko

from ..vault import ai_access
from . import control, ssh_cert
from .broker import MCPError, _allowed_actions
from .ssh import SSHBrokerError, SSHCredentials, _load_private_key
from .ssh_cert import CERT_ALGORITHM, EphemeralKey, UserCertificate

logger = logging.getLogger(__name__)

SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
SSH_AGENT_RSA_SHA2_256 = 2
SSH_AGENT_RSA_SHA2_512 = 4
SSH_AGENTC_EXTENSION = 27
SESSION_BIND = "session-bind@openssh.com"
MAX_BINDINGS = 16  # as OpenSSH's agent

SSH_MSG_USERAUTH_REQUEST = 50
USERAUTH_METHODS = ("publickey", "publickey-hostbound-v00@openssh.com")

ACTION = "ssh_agent"
# Further explicit policy, also in the entry's allowed_actions:
FORWARDING_ACTION = "ssh_agent_forwarding"  # sign through a forwarded agent
UNBOUND_ACTION = "ssh_agent_unbound"  # sign without session-bind (host unverified)
MAX_MESSAGE = 256 * 1024  # OpenSSH's own agent limit
CERT_RENEW_SECONDS = 60  # a listed certificate has at least this long left
SOCKET_NAME = "agent.sock"
PIPE_PREFIX = "sezam-ssh-agent-"
_FAILURE = bytes([SSH_AGENT_FAILURE])


class _Malformed(Exception):
    pass


class _Reader:
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self._pos + size > len(self._data):
            raise _Malformed("truncated")
        chunk = self._data[self._pos:self._pos + size]
        self._pos += size
        return chunk

    def byte(self) -> int:
        return self.take(1)[0]

    def uint32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def string(self) -> bytes:
        return self.take(self.uint32())

    def text(self) -> str:
        try:
            return self.string().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _Malformed("not utf-8") from exc

    def end(self) -> None:
        if self._pos != len(self._data):
            raise _Malformed("trailing data")


def _string(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


@dataclass(frozen=True)
class UserauthRequest:
    session_id: bytes
    username: str
    algorithm: str
    key_blob: bytes
    server_host_key: Optional[bytes]  # publickey-hostbound-v00 only


def parse_userauth_request(data: bytes) -> UserauthRequest:
    """The data an SSH client asks to sign for publickey authentication
    (RFC 4252 section 7, or OpenSSH's host-bound variant). Anything else,
    e.g. an SSHSIG file signature, raises ``_Malformed``."""
    r = _Reader(data)
    session_id = r.string()
    if not session_id:
        raise _Malformed("empty session id")
    if r.byte() != SSH_MSG_USERAUTH_REQUEST:
        raise _Malformed("not a userauth request")
    username = r.text()
    if r.text() != "ssh-connection":
        raise _Malformed("unexpected service")
    method = r.text()
    if method not in USERAUTH_METHODS:
        raise _Malformed("unexpected method")
    if r.byte() != 1:
        raise _Malformed("not a signature request")
    algorithm = r.text()
    key_blob = r.string()
    host_key = r.string() if method == USERAUTH_METHODS[1] else None
    r.end()
    return UserauthRequest(session_id, username, algorithm, key_blob, host_key)


@dataclass(frozen=True)
class SessionBinding:
    """A verified ``session-bind@openssh.com``: the server host key that
    signed the session identifier, and whether the agent is forwarded."""

    host_key: bytes
    session_id: bytes
    forwarding: bool


class AgentConnection:
    """State of one client connection: its session bindings in order (a
    forwarded agent gets one per hop, the last is the current target)."""

    def __init__(self) -> None:
        self.bindings: list[SessionBinding] = []

    @property
    def target(self) -> Optional[SessionBinding]:
        return self.bindings[-1] if self.bindings else None

    @property
    def forwarded(self) -> bool:
        return any(binding.forwarding for binding in self.bindings)


def known_hosts_path() -> str:
    """The user's known_hosts, the file the MCP broker's
    ``load_system_host_keys()`` reads."""
    return os.path.expanduser(os.path.join("~", ".ssh", "known_hosts"))


def known_host_keys(host: str, port: int) -> list[bytes]:
    """Host key blobs known_hosts lists for host:port (hashed names
    included), looked up under the name paramiko's client uses."""
    name = host if port == 22 else f"[{host}]:{port}"
    try:
        keys = paramiko.HostKeys(known_hosts_path()).lookup(name)
    except (OSError, paramiko.SSHException, ValueError):
        return []
    return [key.asbytes() for key in (keys or {}).values()]


def host_key_fingerprint(blob: bytes) -> str:
    """OpenSSH SHA256 fingerprint, the format of an entry's host_key_sha256."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _public_key(blob: bytes) -> Optional[paramiko.PKey]:
    try:
        return paramiko.PKey.from_type_string(_Reader(blob).text(), blob)
    except Exception:
        return None


def parse_session_bind(r: _Reader) -> SessionBinding:
    """Parse the rest of a session-bind extension and verify the host
    key's signature over the session identifier; raises ``_Malformed``."""
    host_key, session_id, signature = r.string(), r.string(), r.string()
    forwarding = r.byte()
    r.end()
    if forwarding not in (0, 1) or not 0 < len(session_id) <= 128:
        raise _Malformed("bad session-bind")
    key = _public_key(host_key)
    try:
        valid = key is not None and key.verify_ssh_sig(session_id, paramiko.Message(signature))
    except Exception:
        valid = False
    if not valid:
        raise _Malformed("session-bind signature does not verify")
    return SessionBinding(host_key, session_id, forwarding == 1)


def signature_algorithm(key: paramiko.PKey, flags: int) -> Optional[str]:
    """Algorithm for ``key`` and the request flags; None means refuse
    (SHA-1 RSA, unknown flags, other key types)."""
    if isinstance(key, paramiko.Ed25519Key):
        return "ssh-ed25519" if flags == 0 else None
    if isinstance(key, paramiko.RSAKey):
        if flags & ~(SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512):
            return None
        if flags & SSH_AGENT_RSA_SHA2_256:
            return "rsa-sha2-256"
        if flags & SSH_AGENT_RSA_SHA2_512:
            return "rsa-sha2-512"
    return None


@dataclass
class _Identity:
    path: str
    entry: dict
    tier: int
    credentials: SSHCredentials
    key: paramiko.PKey | EphemeralKey
    blob: bytes
    certificate: Optional[UserCertificate] = None  # AI SSH CA entries


class SSHAgentService:
    """Agent message handling on top of the broker's policy, kill switch,
    approval and audit."""

    def __init__(
        self,
        broker,
        *,
        agent_name: str = "ssh-agent",
        on_activity: Optional[Callable[[], None]] = None,
        grant_minutes: int = 0,
    ):
        self._broker = broker
        self._vault = broker._vault
        self._agent_name = agent_name
        # Tier 1 approval may be extended to "this entry, host and user for
        # N minutes" (offered in the dialog, never assumed). In memory only;
        # gone on lock, on AI off and when the switch epoch changes.
        self._grant_minutes = grant_minutes
        self._grants: dict[tuple, tuple[float, int]] = {}
        # AI SSH CA entries: entry id -> (settings, ephemeral key, certificate),
        # in memory only; dropped with the grants.
        self._certs: dict[str, tuple[tuple, EphemeralKey, UserCertificate]] = {}
        self._on_activity = on_activity
        # One request at a time: the vault and the approval dialog are shared.
        self._lock = threading.Lock()

    def handle(self, message: bytes, connection: Optional[AgentConnection] = None) -> bytes:
        """One agent request payload in, one response payload out.
        ``connection`` carries the session bindings of the client connection."""
        if connection is None:
            connection = AgentConnection()
        with self._lock:
            try:
                r = _Reader(message)
                kind = r.byte()
                if kind == SSH_AGENTC_REQUEST_IDENTITIES:
                    r.end()
                    return self._identities_answer()
                if kind == SSH_AGENTC_SIGN_REQUEST:
                    if self._on_activity is not None:
                        self._on_activity()
                    blob, data, flags = r.string(), r.string(), r.uint32()
                    r.end()
                    return self._sign(blob, data, flags, connection)
                if kind == SSH_AGENTC_EXTENSION and r.text() == SESSION_BIND:
                    return self._session_bind(r, connection)
            except _Malformed:
                pass
            except Exception:
                logger.exception("ssh-agent request failed")
            return _FAILURE

    # ── identities ──

    def _identities(self, issue: bool = True) -> list[_Identity]:
        """Keys of the visible entries that allow ``ssh_agent``; none at
        all while AI access is off or the vault is locked. An AI SSH CA
        entry is offered only as a short-lived certificate for an ephemeral
        key, never its CA key; ``issue=False`` (signing) only reuses a
        certificate already listed and still valid."""
        try:
            self._broker._require_access()
        except MCPError:
            self.clear_grants()
            return []
        found: list[_Identity] = []
        for path, policy, tier in self._broker._visible_entries():
            if ACTION not in _allowed_actions(policy):
                continue
            try:
                entry = self._vault.read_entry(policy["id"])
                credentials = SSHCredentials.from_entry(entry)
                key = _load_private_key(credentials.private_key, credentials.passphrase)
            except (SSHBrokerError, KeyError, ValueError):
                logger.warning("ssh-agent: entry %s has no usable SSH key", policy["id"])
                continue
            if credentials.ssh_ca:
                identity = self._certificate_identity(path, entry, tier, credentials, key, issue)
                if identity is not None:
                    found.append(identity)
                continue
            if not isinstance(key, (paramiko.Ed25519Key, paramiko.RSAKey)):
                continue
            found.append(_Identity(path, entry, tier, credentials, key, key.asbytes()))
        return found

    def _certificate_identity(
        self, path: str, entry: dict, tier: int, credentials: SSHCredentials, ca_key, issue: bool
    ) -> Optional[_Identity]:
        """The ephemeral key and its certificate for an AI SSH CA entry:
        principal = the entry's username, valid ``cert_ttl_minutes`` (10,
        max 60), only ``permit-pty``, ``source-address`` if set, key id
        ``sezam-ai:<entry>:<ai epoch>:<nonce>``. Reissued when expiring,
        when the CA settings change and with every new AI access epoch."""
        if not isinstance(ca_key, paramiko.Ed25519Key):
            logger.warning("ssh-agent: SSH CA entry %s needs an Ed25519 key", entry["id"])
            return None
        try:
            ttl = ssh_cert.ttl_minutes(credentials.cert_ttl_minutes)
            source = ssh_cert.source_addresses(credentials.source_address)
        except ssh_cert.CertificateConfigError as exc:
            logger.warning("ssh-agent: SSH CA entry %s: %s", entry["id"], exc)
            return None
        epoch = ai_access.read_state(self._vault).epoch
        settings = (ca_key.asbytes(), credentials.username, ttl, source, epoch)
        now = int(time.time())
        cached = self._certs.get(entry["id"])
        if cached is not None and cached[0] == settings and (
            cached[2].valid_before - now > (0 if not issue else CERT_RENEW_SECONDS)
        ):
            _settings, ephemeral, certificate = cached
        elif not issue:
            return None
        else:
            ephemeral = EphemeralKey()
            certificate = ssh_cert.sign_user_certificate(
                ca_key,
                ephemeral.public,
                principals=[credentials.username],
                key_id=f"sezam-ai:{entry['id']}:{epoch}:{os.urandom(8).hex()}",
                valid_after=now - ssh_cert.CLOCK_SKEW,
                valid_before=now + ttl * 60,
                source_address=source,
            )
            self._certs[entry["id"]] = (settings, ephemeral, certificate)
        return _Identity(path, entry, tier, credentials, ephemeral, certificate.blob, certificate)

    def _identities_answer(self) -> bytes:
        listed: dict[bytes, str] = {}
        for identity in self._identities():
            prefix = "sezam" if identity.certificate is None else "sezam-cert"
            listed.setdefault(identity.blob, f"{prefix}:{identity.path}")
        body = b"".join(_string(blob) + _string(c.encode("utf-8")) for blob, c in listed.items())
        return bytes([SSH_AGENT_IDENTITIES_ANSWER]) + len(listed).to_bytes(4, "big") + body

    # ── session binding ──

    @staticmethod
    def _session_bind(r: _Reader, connection: AgentConnection) -> bytes:
        binding = parse_session_bind(r)
        if binding in connection.bindings:
            return bytes([SSH_AGENT_SUCCESS])
        # As OpenSSH: once bound for an authentication (not forwarding) the
        # connection cannot be re-bound to another host.
        target = connection.target
        if target is not None and not target.forwarding:
            return _FAILURE
        if len(connection.bindings) >= MAX_BINDINGS:
            return _FAILURE
        connection.bindings.append(binding)
        return bytes([SSH_AGENT_SUCCESS])

    @staticmethod
    def _binding_refusal(identity: _Identity, connection: AgentConnection) -> Optional[str]:
        """Why this entry's key may not sign on this connection, or None.

        A forwarded agent signs only for entries that allow forwarding.
        Otherwise the key signs only on a connection bound (and verified) to
        the entry's own host, checked as the MCP broker checks it before
        connecting: a pinned host key must equal the bound one, an unpinned
        entry's host:port must have the bound key in known_hosts. Without
        session-bind the host is unknown, so only if the entry explicitly
        allows an unbound agent.
        """
        actions = _allowed_actions(identity.entry)
        if connection.forwarded and FORWARDING_ACTION not in actions:
            return "forwarding_refused"
        target = connection.target
        if target is None:
            return None if UNBOUND_ACTION in actions else "session_not_bound"
        credentials = identity.credentials
        pin = credentials.host_key_sha256
        if pin is not None:
            if not hmac.compare_digest(host_key_fingerprint(target.host_key), pin):
                return "host_key_mismatch"
            return None
        known = known_host_keys(credentials.host, credentials.port)
        if not known:
            return "host_key_unknown"
        if not any(hmac.compare_digest(blob, target.host_key) for blob in known):
            return "host_key_mismatch"
        return None

    # ── signing ──

    def _sign(self, blob: bytes, data: bytes, flags: int, connection: AgentConnection) -> bytes:
        candidates = [i for i in self._identities(issue=False) if i.blob == blob]
        if not candidates:
            return _FAILURE
        try:
            request = parse_userauth_request(data)
        except _Malformed:
            self._deny(candidates, "not_userauth")
            return _FAILURE
        if candidates[0].certificate is not None:
            algorithm = CERT_ALGORITHM if flags == 0 else None
        else:
            algorithm = signature_algorithm(candidates[0].key, flags)
        if algorithm is None:
            self._deny(candidates, "algorithm_refused", flags=flags)
            return _FAILURE
        if request.algorithm != algorithm or request.key_blob != blob:
            self._deny(candidates, "request_mismatch")
            return _FAILURE
        matching = [i for i in candidates if i.credentials.username == request.username]
        if not matching:
            self._deny(candidates, "username_mismatch", requested_username=request.username)
            return _FAILURE
        target = connection.target
        if target is not None and (
            request.session_id != target.session_id
            or (request.server_host_key is not None and request.server_host_key != target.host_key)
        ):
            # Signing for another session than the verified binding.
            self._deny(matching, "session_mismatch")
            return _FAILURE
        if target is None and any(
            i.credentials.host_key_sha256 is not None
            and UNBOUND_ACTION not in _allowed_actions(i.entry)
            for i in candidates
        ):
            # The key is pinned to a host by some entry: an unbound signature
            # (valid for any server) through a looser entry would undo the pin.
            self._deny(matching, "session_not_bound", **self._binding_details(connection))
            return _FAILURE
        refusals = [self._binding_refusal(i, connection) for i in matching]
        eligible = [i for i, refusal in zip(matching, refusals) if refusal is None]
        if not eligible:
            for identity, refusal in zip(matching, refusals):
                self._deny([identity], refusal, **self._binding_details(connection))
            return _FAILURE
        if len(eligible) > 1 and target is not None:
            # The entry pinned to the bound host is the one meant.
            pinned = [i for i in eligible if i.credentials.host_key_sha256 is not None]
            eligible = pinned or eligible
        if len(eligible) > 1:
            # Which entry's host and policy apply cannot be told apart.
            self._deny(eligible, "ambiguous_key")
            return _FAILURE
        identity = eligible[0]
        details = {
            **self._details(identity, request, algorithm),
            **self._binding_details(connection),
        }

        approval = "auto"
        grant_key = (
            identity.entry["id"],
            details["bound_host_key"] or f"{identity.credentials.host}:{identity.credentials.port}",
            identity.credentials.username,
            connection.forwarded,
        )
        if identity.tier >= 1 and self._grant_valid(grant_key):
            approval = "grant"
        elif identity.tier >= 1:
            target = {
                "entry": identity.entry.get("name"),
                "host": identity.credentials.host,
                "port": identity.credentials.port,
                "username": identity.credentials.username,
                "host_key": details["bound_host_key"],
                "host_unverified": None if details["bound_host_key"] else (
                    "NOT verified (the client sent no session-bind; "
                    "the signature would work on any server)"
                ),
                "forwarded": "yes" if connection.forwarded else None,
            }
            if identity.certificate is not None:
                target["certificate"] = "Sezam SSH CA, valid until " + time.strftime(
                    "%H:%M:%S", time.localtime(identity.certificate.valid_before)
                )
            result, granted = self._broker._await_approval(
                identity.path, ACTION, self._agent_name, {"algorithm": algorithm}, target,
                grant_minutes=self._grant_minutes,
            )
            if result != "approved":
                self._deny([identity], result, **details)
                return _FAILURE
            approval = "owner"
            if granted:
                approval = "owner_grant"
                self._grants[grant_key] = (
                    time.monotonic() + self._grant_minutes * 60,
                    ai_access.read_state(self._vault).epoch,
                )
            # The switch may have been turned off while the dialog was open.
            try:
                self._broker._require_access()
            except MCPError as exc:
                self._deny([identity], exc.code, **details)
                return _FAILURE

        with self._broker._audited_ssh(
            identity.entry, "agent_sign", approval=approval, agent=self._agent_name, **details
        ):
            signature = identity.key.sign_ssh_data(data, algorithm)
        return bytes([SSH_AGENT_SIGN_RESPONSE]) + _string(signature.asbytes())

    def clear_grants(self) -> None:
        """Forget the N-minute grants and the issued certificates (lock, AI off)."""
        self._grants.clear()
        self._certs.clear()

    def _grant_valid(self, key: tuple) -> bool:
        grant = self._grants.get(key)
        if grant is None:
            return False
        expires, epoch = grant
        if time.monotonic() < expires and ai_access.read_state(self._vault).epoch == epoch:
            return True
        self._grants.pop(key, None)
        return False

    @staticmethod
    def _details(identity: _Identity, request: UserauthRequest, algorithm: str) -> dict:
        details = {
            "host": identity.credentials.host,
            "port": identity.credentials.port,
            "username": identity.credentials.username,
            "algorithm": algorithm,
        }
        if request.server_host_key is not None:
            details["server_host_key_sha256"] = hashlib.sha256(
                request.server_host_key
            ).hexdigest()
        if identity.certificate is not None:
            details["cert_key_id"] = identity.certificate.key_id
            details["cert_serial"] = identity.certificate.serial
            details["cert_valid_before"] = identity.certificate.valid_before
        return details

    @staticmethod
    def _binding_details(connection: AgentConnection) -> dict:
        target = connection.target
        return {
            "bound_host_key": None if target is None else host_key_fingerprint(target.host_key),
            "forwarded": connection.forwarded,
        }

    def _deny(self, identities: list[_Identity], reason: str, **details) -> None:
        for identity in identities:
            payload = {
                "host": identity.credentials.host,
                "port": identity.credentials.port,
                "username": identity.credentials.username,
                **details,
                "agent": self._agent_name,
                "reason": reason,
            }
            try:
                self._broker._audit_ssh(identity.entry, "agent_sign_denied", **payload)
            except Exception:
                logger.warning("ssh-agent: could not audit a refused signature")


_SAFE_CONFIG_VALUE = re.compile(r"[A-Za-z0-9._@:\[\]-]+")

AUTHORIZED_KEYS_LIMITATION = (
    "Once logged in, the AI has a shell there and could add its own key to\n"
    "~/.ssh/authorized_keys, bypassing Sezam from then on. Give it a dedicated\n"
    "account and, where that matters, 'AuthorizedKeysFile none' with Sezam SSH\n"
    "certificates (an AI SSH CA entry and 'sezam ai-host-setup')."
)


def client_config(broker, endpoint: Optional[str] = None) -> str:
    """ssh_config blocks for every entry the agent would serve (the same
    rules as REQUEST_IDENTITIES, ignoring the kill switch). Needs an
    unlocked vault; prints no secrets."""
    endpoint = endpoint or default_endpoint()
    agent = endpoint.replace("\\", "\\\\")  # ssh_config unescapes backslashes
    comment = "\n".join(f"# {line}" for line in AUTHORIZED_KEYS_LIMITATION.splitlines())
    out = [
        "# Sezam SSH agent ('sezam ssh-agent'): keys stay in the vault.",
        "# IdentitiesOnly is not set: without an IdentityFile for the public key",
        "# it would make ssh ignore the agent's keys.",
        comment,
        "",
    ]
    for path, policy, _tier in broker._visible_entries():
        if ACTION not in _allowed_actions(policy):
            continue
        alias = "sezam-" + re.sub(r"[^a-z0-9_.]+", "-", path.lower()).strip("-")
        try:
            entry = broker._vault.read_entry(policy["id"])
            credentials = SSHCredentials.from_entry(entry)
            key = _load_private_key(credentials.private_key, credentials.passphrase)
        except (SSHBrokerError, KeyError, ValueError):
            out += [f"# {alias}: skipped, no usable SSH key", ""]
            continue
        if credentials.ssh_ca and not isinstance(key, paramiko.Ed25519Key):
            out += [f"# {alias}: skipped, an SSH CA key must be Ed25519", ""]
            continue
        if not isinstance(key, (paramiko.Ed25519Key, paramiko.RSAKey)):
            out += [f"# {alias}: skipped, only Ed25519 and RSA keys are served", ""]
            continue
        if not (
            _SAFE_CONFIG_VALUE.fullmatch(credentials.host)
            and _SAFE_CONFIG_VALUE.fullmatch(credentials.username)
        ):
            out += [f"# {alias}: skipped, host or user has unsafe characters", ""]
            continue
        out += [
            f"Host {alias}",
            f"    HostName {credentials.host}",
            f"    Port {credentials.port}",
            f"    User {credentials.username}",
            f'    IdentityAgent "{agent}"',
            "    ForwardAgent no",
        ]
        if credentials.host_key_sha256:
            out.append(f"    # host key pinned in Sezam: {credentials.host_key_sha256}")
        if credentials.ssh_ca:
            out.append("    # short-lived certificate from the Sezam SSH CA (server: 'sezam ai-host-setup')")
        out.append("")
    return "\n".join(out) + "\n"


def default_endpoint() -> str:
    if sys.platform == "win32":
        user = re.sub(r"[^A-Za-z0-9_.-]", "_", getpass.getuser())
        return f"\\\\.\\pipe\\{PIPE_PREFIX}{user}"
    return str(control.run_dir() / SOCKET_NAME)


class SSHAgentServer(control.OwnerOnlyServer):
    """The agent endpoint: length-prefixed agent messages, many per
    connection (an ssh client keeps it open for its whole session)."""

    thread_name = "sezam-ssh-agent"
    buffer_size = 64 * 1024
    io_timeout = None
    # An ssh client holds its connection for its whole session (H7 bounds).
    max_connections = 64
    max_peer_connections = 32

    def __init__(
        self, service: SSHAgentService, path: Optional[str] = None, group: Optional[str] = None
    ):
        self._service = service
        super().__init__(path or default_endpoint(), group)

    def start(self) -> None:
        if sys.platform != "win32" and _socket_answers(self.path):
            raise OSError(f"Another agent is already running on {self.path}")
        super().start()

    def _serve_connection(
        self, read: Callable[[int], bytes], write: Callable[[bytes], None]
    ) -> None:
        pending = bytearray()
        connection = AgentConnection()

        def take(size: int) -> Optional[bytes]:
            while len(pending) < size:
                chunk = read(min(self.buffer_size, size - len(pending)))
                if not chunk:
                    return None
                pending.extend(chunk)
            data = bytes(pending[:size])
            del pending[:size]
            return data

        while self._running:
            header = take(4)
            if header is None:
                return
            length = int.from_bytes(header, "big")
            if not 0 < length <= MAX_MESSAGE:
                return
            message = take(length)
            if message is None:
                return
            reply = self._service.handle(message, connection)
            write(_string(reply))


def _socket_answers(path: str) -> bool:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    with sock:
        try:
            sock.connect(path)
        except OSError:
            return False
    return True
