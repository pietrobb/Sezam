"""Builds tests/vectors/key_vouchers.json - the key voucher vectors (goal #443).

Run ``python -m tests.key_vouchers_vectors`` once to write the file. Never
regenerate it to make a client pass: web and mobile must reproduce the
messages and answers of the Python reference (src/sezam/key_vouchers.py).
tests/test_key_vouchers_vectors.py checks that this builder still produces the
stored file byte for byte.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from nacl.signing import SigningKey

from sezam import key_vouchers as kv

VECTORS_PATH = Path(__file__).parent / "vectors" / "key_vouchers.json"

USER = "01JACC0000000000000000000F"
OTHER_USER = "01JACC0000000000000000000G"
OBJ = ["01JOBJ000000000000000000" + f"{n:02d}" for n in range(1, 6)]


def _key(name: str) -> SigningKey:
    return SigningKey(hashlib.sha256(b"sezam-key-voucher-vector:" + name.encode()).digest())


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


CURRENT, RETIRED, OLDER = _key("current"), _key("retired"), _key("older")
E1, E2, E3 = [OBJ[0], 3, _hash("a")], [OBJ[1], 1, _hash("b")], [OBJ[2], 2 ** 40, _hash("c")]


def _pk(key: SigningKey) -> str:
    return bytes(key.verify_key).hex()


def build() -> dict:
    by_current = kv.sign_vouchers(USER, CURRENT, [E2, E1, E1])
    second = kv.sign_vouchers(USER, CURRENT, [E3])
    by_retired = kv.sign_vouchers(USER, RETIRED, [E3])
    other_user = kv.sign_vouchers(OTHER_USER, CURRENT, [E3])
    tampered = {**by_current, "entries": [E1, E2, E3]}
    renamed = {**second, "signing_pk": _pk(RETIRED)}
    empty = kv.sign_vouchers(USER, CURRENT, [])
    cases = [
        ("listed by the current key", [by_current], E1, True),
        ("a second list by the current key adds", [by_current, second], E3, True),
        ("not listed", [by_current], E3, False),
        ("another version of a listed object", [by_current], [E1[0], 4, E1[2]], False),
        ("another payload of a listed version", [by_current], [E1[0], E1[1], _hash("x")], False),
        ("listed only by a retired key", [by_retired], E3, False),
        ("a list for another account", [other_user], E3, False),
        ("a list with an entry added after signing", [tampered], E3, False),
        ("a list claiming another signer", [renamed], E3, False),
        ("an empty list", [empty], E1, False),
        ("no list", [], E1, False),
    ]
    return {
        "_comment": (
            "Key voucher vectors (review e443cbc, goal #443), produced by "
            "tests/key_vouchers_vectors.py from src/sezam/key_vouchers.py. Web and "
            "mobile must reproduce them; never regenerate this file to make a client pass."
        ),
        "user_id": USER,
        "current_signing_pk": _pk(CURRENT),
        "retired_signing_pk": _pk(RETIRED),
        "messages": [
            {
                "user_id": user, "signing_pk": _pk(key), "entries": [list(e) for e in kv.canonical_entries(entries)],
                "message_hex": kv.voucher_message(user, bytes(key.verify_key), entries).hex(),
            }
            for user, key, entries in (
                (USER, CURRENT, [E2, E1, E1]), (USER, CURRENT, []), (OTHER_USER, OLDER, [E3, E1]),
            )
        ],
        "malformed_entries": [
            [OBJ[0][:25] + "-", 1, _hash("a")], [OBJ[0], -1, _hash("a")], [OBJ[0], True, _hash("a")],
            [OBJ[0], 1, _hash("a").upper()], [OBJ[0], 1], [OBJ[0][:25], 1, _hash("a")],
        ],
        "cases": [
            {"name": name, "lists": lists, "entry": list(entry), "vouched": answer}
            for name, lists, entry, answer in cases
        ],
    }


def main() -> None:
    VECTORS_PATH.write_text(json.dumps(build(), indent=1) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
