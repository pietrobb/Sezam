"""Redaction of an entry's secrets in command output (AI broker TODO,
section 7).

Before ``ssh_execute`` / ``ssh_session_read`` return output to the agent,
every occurrence of the entry's sensitive values (fields marked
``sensitive``, the password, the passphrase, the private key and each of
its lines) becomes ``[REDACTED]``, also base64 (at any alignment, standard
and URL-safe alphabet) and URL-encoded. A stream keeps back only a tail
that could still become a secret, so a secret split across two reads is
redacted too; output that cannot start a secret (a shell prompt) is
returned at once.
"""

from __future__ import annotations

import base64
import re
from typing import Iterable
from urllib.parse import quote, quote_plus

REDACTED = b"[REDACTED]"
MIN_SECRET = 4  # shorter values would mangle ordinary output
MIN_ENCODED = 8  # base64 fragments shorter than this match too much
MIN_LINE = 16  # lines of a multi-line secret (a PEM key) redacted on their own

SECRET_FIELDS = {
    "password", "ssh_password", "passphrase", "key_passphrase",
    "private_key", "privatekey", "ssh_private_key", "ssh_key",
}


def _normalise(key: str) -> str:
    return key.strip().lower().replace("-", "_").replace(" ", "_")


def entry_secrets(entry: dict) -> list[bytes]:
    """The values to redact for ``entry`` (its decrypted fields)."""
    out: list[bytes] = []
    for field in entry.get("fields", []):
        value = str(field.get("value") or "")
        if value and (field.get("sensitive") or _normalise(str(field.get("key", ""))) in SECRET_FIELDS):
            out.append(value.encode("utf-8"))
            lines = [line.strip() for line in value.splitlines()]
            if len(lines) > 1:
                out += [line.encode("utf-8") for line in lines if len(line) >= MIN_LINE]
    return out


def _base64_fragments(secret: bytes) -> set[bytes]:
    """The base64 characters fixed by ``secret`` alone, for each of the
    three alignments it can have inside a longer encoded stream."""
    out = set()
    for offset in range(3):
        bits = 8 * offset
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            encoded = encode(b"\x00" * offset + secret)
            start = -(-bits // 6)
            end = (bits + 8 * len(secret)) // 6
            out.add(encoded[start:end])
    return {f for f in out if len(f) >= MIN_ENCODED}


def _variants(secret: bytes) -> set[bytes]:
    out = {secret} | _base64_fragments(secret)
    text = secret.decode("utf-8", errors="ignore")
    # Review 1141a20 M-AI1: http.client sends a header value as latin-1, so a
    # server echoes a non-ASCII secret in those bytes.
    try:
        latin = text.encode("latin-1")
    except UnicodeEncodeError:
        pass
    else:
        if latin != secret:
            out |= {latin} | _base64_fragments(latin)
    out.add(quote(text, safe="").encode("ascii"))
    out.add(quote_plus(text, safe="").encode("ascii"))
    # Review d615826: the one-call encodings a script the agent placed on the
    # server reaches for (bin2hex, strrev). Not a boundary, see the docs.
    out |= {secret.hex().encode("ascii"), secret.hex().upper().encode("ascii"), secret[::-1]}
    return out


class Redactor:
    def __init__(self, secrets: Iterable[bytes]):
        variants: set[bytes] = set()
        for secret in secrets:
            if len(secret) >= MIN_SECRET:
                variants |= _variants(secret)
        self._patterns = sorted((v for v in variants if len(v) >= MIN_SECRET), key=len, reverse=True)
        self._by_first: dict[int, list[bytes]] = {}
        for pattern in self._patterns:
            self._by_first.setdefault(pattern[0], []).append(pattern)
        self._regex = (
            re.compile(b"|".join(re.escape(p) for p in self._patterns)) if self._patterns else None
        )

    @classmethod
    def for_entry(cls, entry: dict) -> "Redactor":
        return cls(entry_secrets(entry))

    def redact(self, data: bytes, *, truncated: bool = False) -> bytes:
        """Every complete occurrence replaced; with ``truncated`` also a
        secret cut off at the end of the data."""
        if self._regex is None:
            return data
        data = self._regex.sub(REDACTED, data)
        if truncated:
            held = self.partial_suffix(data)
            if held:
                data = data[:-held] + REDACTED
        return data

    def partial_suffix(self, data: bytes) -> int:
        """Length of the longest tail of ``data`` that is the start (not the
        whole) of a secret pattern; 0 if none."""
        if not self._patterns:
            return 0
        longest = len(self._patterns[0])
        for start in range(max(0, len(data) - longest + 1), len(data)):
            candidates = self._by_first.get(data[start])
            if candidates:
                tail = data[start:]
                if any(len(p) > len(tail) and p.startswith(tail) for p in candidates):
                    return len(data) - start
        return 0

    def match_spans(self, data: bytes) -> list[tuple[int, int]]:
        if self._regex is None:
            return []
        return [m.span() for m in self._regex.finditer(data)]


AUDIT_TEXT_MAX = 500


def audit_text(entry: dict, text: str) -> str:
    """``text`` (a command) as the audit log keeps it: the entry's secrets
    redacted, at most AUDIT_TEXT_MAX bytes."""
    data = Redactor.for_entry(entry).redact(text.encode("utf-8"))
    if len(data) <= AUDIT_TEXT_MAX:
        return data.decode("utf-8", errors="replace")
    return data[:AUDIT_TEXT_MAX].decode("utf-8", errors="ignore") + "…"


class RedactingStream:
    """Redaction over successive reads of one output stream.

    A tail that could still grow into a secret is held back until the next
    read: the longest tail that starts a secret pattern, and a complete
    match reaching into it (a shorter secret can be the start of a longer
    one). Nothing else is held, so a shell prompt is returned at once.
    """

    def __init__(self, redactor: Redactor):
        self._redactor = redactor
        self._pending = b""

    def feed(self, data: bytes, *, final: bool = False) -> bytes:
        buf = self._pending + data
        if final:
            self._pending = b""
            return self._redactor.redact(buf)
        cut = len(buf) - self._redactor.partial_suffix(buf)
        for start, end in self._redactor.match_spans(buf):
            if start < cut < end:
                cut = start
        self._pending = buf[cut:]
        return self._redactor.redact(buf[:cut])
