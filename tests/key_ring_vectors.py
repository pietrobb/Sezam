"""Builds tests/vectors/key_ring.json - which archived signing keys of
``GET /api/users/{id}/keys`` an account's key ring trusts (capability review
716, core/src/keyring.rs).

Run ``python -m tests.key_ring_vectors`` once to write the file. Each case
names its answer here, by hand: the trusted (signing, encryption) keys in
chain order, current first, or "error" when the whole response is refused.
The desktop (tests/test_key_ring_vectors.py), the web and the phone
(mobile/test/key_ring_vectors_test.dart) must give these answers.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from nacl.public import PrivateKey
from nacl.signing import SigningKey

from sezam.vault.sync_common import key_rotation_message

VECTORS_PATH = Path(__file__).parent / "vectors" / "key_ring.json"

USER = "01JACC0000000000000000000K"
OTHER_USER = "01JACC0000000000000000000L"


def _seed(name: str) -> bytes:
    return hashlib.sha256(b"sezam-key-ring-vector:" + name.encode()).digest()


class Identity:
    def __init__(self, name: str):
        self.signer = SigningKey(_seed("sign:" + name))
        self.signing_pk = bytes(self.signer.verify_key)
        self.encryption_pk = bytes(PrivateKey(_seed("box:" + name)).public_key)

    def pair(self) -> dict:
        return {"signing_pk": self.signing_pk.hex(), "encryption_pk": self.encryption_pk.hex()}


def _fingerprint(signing_pk: bytes, encryption_pk: bytes) -> str:
    return hashlib.sha256(signing_pk + encryption_pk).hexdigest()


def archive(old: Identity, new: Identity, user: str = USER, authorize: bool = True, **override) -> dict:
    """The server's archive of ``old`` after rotating to ``new``."""
    message = key_rotation_message(user, old.signing_pk, old.encryption_pk, new.signing_pk, new.encryption_pk)
    out = {
        "signing_pk": old.signing_pk.hex(),
        "encryption_pk": old.encryption_pk.hex(),
        "key_fingerprint": _fingerprint(old.signing_pk, old.encryption_pk),
        "successor_signing_pk": new.signing_pk.hex(),
        "rotation_signature": new.signer.sign(message).signature.hex(),
        "authorization_signature": old.signer.sign(message).signature.hex() if authorize else None,
        "retired_seq": 7,
    }
    out.update(override)
    return {k: v for k, v in out.items() if v is not _DROP}


_DROP = object()
CURRENT, A, B, C, STRANGER = (Identity(n) for n in ("current", "a", "b", "c", "stranger"))


def _chain(length: int) -> tuple[list[Identity], list[dict]]:
    keys = [CURRENT] + [Identity(f"old{n}") for n in range(length)]
    return keys, [archive(keys[n + 1], keys[n]) for n in range(length)]


def build() -> dict:
    a_by_current = archive(A, CURRENT)
    b_by_a = archive(B, A)
    c_by_b = archive(C, B)
    full_chain, full_archives = _chain(64)
    _, too_many = _chain(65)
    wrong_signer = {**a_by_current, "rotation_signature": archive(A, STRANGER)["rotation_signature"]}
    bad_authorization = {**a_by_current, "authorization_signature": archive(A, CURRENT, user=OTHER_USER)[
        "authorization_signature"]}
    forged_copy = {
        **a_by_current, "encryption_pk": STRANGER.encryption_pk.hex(),
        "key_fingerprint": _fingerprint(A.signing_pk, STRANGER.encryption_pk),
    }
    ok = lambda *ids: [i.pair() for i in (CURRENT, *ids)]  # noqa: E731
    cases = [
        ("no archives", [], ok()),
        ("no archived_keys field", None, ok()),
        ("an archive certified by the current key", [a_by_current], ok(A)),
        ("a chain served oldest first", [c_by_b, b_by_a, a_by_current], ok(A, B, C)),
        ("a chain served newest first", [a_by_current, b_by_a, c_by_b], ok(A, B, C)),
        ("an archive without its old key's authorization", [archive(A, CURRENT, authorize=False)], ok(A)),
        ("an empty authorization counts as none", [archive(A, CURRENT, authorization_signature="")], ok(A)),
        ("a legacy archive without a certificate", [archive(A, CURRENT, rotation_signature=_DROP,
                                                            successor_signing_pk=_DROP)], ok()),
        ("a legacy archive with null certificate fields", [archive(A, CURRENT, rotation_signature=None,
                                                                   successor_signing_pk=None)], ok()),
        ("a legacy archive does not stop the chain after it", [archive(B, CURRENT, rotation_signature=None),
                                                               a_by_current], ok(A)),
        ("a certificate signed by another key", [wrong_signer], ok()),
        ("an authorization over another account's rotation", [bad_authorization], ok()),
        ("a rotation certified for another account", [archive(A, CURRENT, user=OTHER_USER)], ok()),
        ("a successor nobody trusts", [archive(A, STRANGER)], ok()),
        ("a gap in the chain", [c_by_b, a_by_current], ok(A)),
        ("a short certificate", [archive(A, CURRENT, rotation_signature="00" * 63)], ok()),
        ("a short authorization", [archive(A, CURRENT, authorization_signature="00" * 63)], ok()),
        ("the current key archived again", [archive(CURRENT, A), a_by_current], ok(A)),
        ("a second copy of a trusted key with another encryption key", [a_by_current, forged_copy, b_by_a],
         ok(A, B)),
        ("upper-case hex", [{**a_by_current, "successor_signing_pk": CURRENT.signing_pk.hex().upper()}], ok(A)),
        ("64 archives, as many as the server serves", full_archives, [i.pair() for i in full_chain]),
        # Capability review 716: web and phone refused, the desktop trusted all.
        ("65 archives", too_many, "error"),
        # Capability review 716: the desktop skipped it, web and phone refused.
        ("a certified archive without key_fingerprint", [archive(A, CURRENT, key_fingerprint=_DROP)], "error"),
        ("a fingerprint that does not match", [archive(A, CURRENT, key_fingerprint="00" * 32)], "error"),
        ("an archived key of 31 bytes", [archive(A, CURRENT, signing_pk=A.signing_pk.hex()[:62])], "error"),
        ("an archived key that is not hex", [archive(A, CURRENT, encryption_pk="zz" * 32)], "error"),
        ("a successor key of 31 bytes", [archive(A, CURRENT, successor_signing_pk="00" * 31)], "error"),
        ("a certificate field that is not a string", [archive(A, CURRENT, rotation_signature=7)], "error"),
        ("an authorization that is not a string", [archive(A, CURRENT, authorization_signature=[1])], "error"),
        ("an archive that is not an object", ["x"], "error"),
        ("archived_keys that is not a list", {"0": a_by_current}, "error"),
    ]
    return {
        "_comment": (
            "Key ring vectors (capability review 716): which archived keys of GET /api/users/{id}/keys are "
            "trusted, built by tests/key_ring_vectors.py with hand-written answers. The desktop, the web and the "
            "phone read this file; never regenerate it to make a client pass."
        ),
        "user_id": USER,
        "current": CURRENT.pair(),
        "cases": [
            {"name": name, **({} if served is None else {"archived_keys": served}), "trusted": answer}
            for name, served, answer in cases
        ],
    }


def main() -> None:
    VECTORS_PATH.write_text(json.dumps(build(), indent=1) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
