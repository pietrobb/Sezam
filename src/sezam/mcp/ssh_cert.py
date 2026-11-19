"""Short-lived OpenSSH user certificates signed by a vault CA key
(AI broker TODO, section 3).

``ssh-ed25519-cert-v01@openssh.com`` built directly after OpenSSH's
``PROTOCOL.certkeys`` and signed in memory with the entry's Ed25519 CA key;
``ssh-keygen -s`` (which needs the CA key in a file) is never used. The
certified key is an ephemeral Ed25519 key that lives only in the agent's
memory.
"""

from __future__ import annotations

import base64
import ipaddress
import os
from dataclasses import dataclass
from typing import Optional

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

CERT_ALGORITHM = "ssh-ed25519-cert-v01@openssh.com"
SSH_CERT_TYPE_USER = 1
EXTENSIONS = ("permit-pty",)  # nothing else: no forwarding, no X11, no user rc
DEFAULT_TTL_MINUTES = 10
MAX_TTL_MINUTES = 60
CLOCK_SKEW = 60  # valid_after is backdated by this many seconds


class CertificateConfigError(ValueError):
    """The CA entry's certificate settings are invalid (no secrets inside)."""


def _string(value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return len(value).to_bytes(4, "big") + value


def _uint64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def ttl_minutes(value: Optional[str]) -> int:
    """Certificate lifetime from the entry field; default 10, 1..60 minutes."""
    if value is None or not value.strip():
        return DEFAULT_TTL_MINUTES
    try:
        minutes = int(value.strip())
    except ValueError as exc:
        raise CertificateConfigError("cert_ttl_minutes must be a number.") from exc
    if not 1 <= minutes <= MAX_TTL_MINUTES:
        raise CertificateConfigError(f"cert_ttl_minutes must be between 1 and {MAX_TTL_MINUTES}.")
    return minutes


def source_addresses(value: Optional[str]) -> Optional[str]:
    """The ``source-address`` critical option from the entry field: a comma
    separated list of addresses/CIDR blocks, normalised; None if unset."""
    if value is None or not value.strip():
        return None
    blocks = []
    for item in value.split(","):
        item = item.strip()
        try:
            blocks.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError as exc:
            raise CertificateConfigError("source_address must list IP addresses or CIDR blocks.") from exc
    return ",".join(blocks)


@dataclass(frozen=True)
class UserCertificate:
    blob: bytes
    key_id: str
    serial: int
    valid_after: int
    valid_before: int
    principals: tuple[str, ...]
    source_address: Optional[str]

    def openssh_line(self, comment: str = "") -> str:
        line = f"{CERT_ALGORITHM} {base64.b64encode(self.blob).decode()}"
        return f"{line} {comment}" if comment else line


class EphemeralKey:
    """An Ed25519 key generated in memory, never serialised."""

    def __init__(self) -> None:
        self._key = ed25519.Ed25519PrivateKey.generate()
        self.public = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign_ssh_data(self, data: bytes, algorithm: Optional[str] = None) -> paramiko.Message:
        # A certificate's signatures use the plain key's format.
        return paramiko.Message(_string("ssh-ed25519") + _string(self._key.sign(data)))


def sign_user_certificate(
    ca_key: paramiko.PKey,
    public_key: bytes,
    *,
    principals: list[str],
    key_id: str,
    valid_after: int,
    valid_before: int,
    source_address: Optional[str] = None,
    serial: Optional[int] = None,
) -> UserCertificate:
    """A user certificate for the raw Ed25519 ``public_key``, signed by the
    Ed25519 ``ca_key``. Only ``permit-pty``; ``source-address`` if given."""
    if not isinstance(ca_key, paramiko.Ed25519Key):
        raise CertificateConfigError("The SSH CA key must be Ed25519.")
    if len(public_key) != 32 or not principals or not valid_after < valid_before:
        raise CertificateConfigError("Invalid certificate request.")
    if serial is None:
        serial = int.from_bytes(os.urandom(8), "big")
    options = b""
    if source_address:
        options += _string("source-address") + _string(_string(source_address))
    extensions = b"".join(_string(name) + _string(b"") for name in sorted(EXTENSIONS))
    body = b"".join([
        _string(CERT_ALGORITHM),
        _string(os.urandom(32)),  # nonce
        _string(public_key),
        _uint64(serial),
        SSH_CERT_TYPE_USER.to_bytes(4, "big"),
        _string(key_id),
        _string(b"".join(_string(p) for p in principals)),
        _uint64(valid_after),
        _uint64(valid_before),
        _string(options),
        _string(extensions),
        _string(b""),  # reserved
        _string(ca_key.asbytes()),
    ])
    signature = ca_key.sign_ssh_data(body).asbytes()
    return UserCertificate(
        blob=body + _string(signature),
        key_id=key_id,
        serial=serial,
        valid_after=valid_after,
        valid_before=valid_before,
        principals=tuple(principals),
        source_address=source_address,
    )
