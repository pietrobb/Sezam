"""TOTP generator (RFC 6238).

Spec 10.2: TOTP seed stored as field_type="totp" in encrypted_data.
Generates 6-digit codes with 30s period.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs, urlparse

_ALGORITHMS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}


@dataclass(frozen=True)
class TotpParams:
    key: bytes
    period: int = 30
    digits: int = 6
    algorithm: str = "sha1"


def _decode_base32(secret: str) -> bytes:
    cleaned = "".join(secret.split()).replace("-", "").upper().rstrip("=")
    if not cleaned:
        raise ValueError("Empty TOTP secret")
    # Authenticator apps usually show seeds without "=" padding.
    padded = cleaned + "=" * (-len(cleaned) % 8)
    return base64.b32decode(padded)


def parse_totp(secret: str) -> TotpParams:
    """Parse a raw base32 seed or an ``otpauth://totp/...`` URI."""
    text = secret.strip()
    if not text.lower().startswith("otpauth://"):
        return TotpParams(key=_decode_base32(text))

    uri = urlparse(text)
    if uri.netloc.lower() != "totp":
        raise ValueError("Only otpauth://totp URIs are supported")
    query = {k.lower(): v[-1] for k, v in parse_qs(uri.query).items()}
    if "secret" not in query:
        raise ValueError("otpauth URI has no secret")
    algorithm = query.get("algorithm", "sha1").lower()
    if algorithm not in _ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    period = int(query.get("period", "30"))
    digits = int(query.get("digits", "6"))
    if not 1 <= period <= 3600 or not 6 <= digits <= 10:
        raise ValueError("otpauth URI has an invalid period or digit count")
    return TotpParams(
        key=_decode_base32(query["secret"]),
        period=period,
        digits=digits,
        algorithm=algorithm,
    )


def generate_totp(
    secret: str,
    period: Optional[int] = None,
    digits: Optional[int] = None,
    algorithm: Optional[str] = None,
    at: Optional[float] = None,
) -> str:
    """Generate a TOTP code from a base32 seed or an otpauth:// URI.

    Explicit ``period``/``digits``/``algorithm`` override the URI values;
    otherwise the URI (or the RFC defaults 30 s / 6 digits / SHA-1) applies.
    """
    params = parse_totp(secret)
    period = period or params.period
    digits = digits or params.digits
    algorithm = (algorithm or params.algorithm).lower()
    if algorithm not in _ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    counter = int(time.time() if at is None else at) // period
    h = hmac.new(params.key, struct.pack(">Q", counter), _ALGORITHMS[algorithm]).digest()

    # Dynamic truncation
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def time_remaining(period: int = 30) -> int:
    """Seconds remaining in current TOTP period."""
    return period - (int(time.time()) % period)
