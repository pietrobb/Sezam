"""Capability review 716: which archived keys of GET /api/users/{id}/keys an
account's key ring trusts is the core's rule (core/src/keyring.rs). The
desktop and the web give every answer of tests/vectors/key_ring.json; the
phone runs the same file (mobile/test/key_ring_vectors_test.dart).

Before, three copies disagreed on the same response: with 65 certified
archives the desktop trusted all, the web and the phone refused; a certified
archive without key_fingerprint was skipped by the desktop and refused by both.
"""

from __future__ import annotations

import json

import pytest

from sezam.vault.sync_client import SyncClient
from tests.key_ring_vectors import VECTORS_PATH, build
from tests.test_review_web import _run

VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
CURRENT = VECTORS["current"]


def _answer(trusted) -> object:
    return trusted if trusted == "error" else [pair["signing_pk"] for pair in trusted]


def test_the_builder_still_produces_the_stored_vectors():
    assert build() == VECTORS


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_the_desktop_trusts_what_the_vectors_name(case):
    response = {"archived_keys": case["archived_keys"]} if "archived_keys" in case else {}
    try:
        ring = [pk.hex() for pk in SyncClient._key_ring_from_response(
            VECTORS["user_id"], bytes.fromhex(CURRENT["signing_pk"]), bytes.fromhex(CURRENT["encryption_pk"]),
            response,
        )]
    except ValueError:
        ring = "error"
    assert ring == _answer(case["trusted"])


def test_the_web_trusts_what_the_vectors_name():
    result = _run(["hexToBytes", "keyRing"], f"""(() => {{
        const v = {json.dumps(VECTORS)};
        return v.cases.map(c => {{
            try {{
                return keyRing(v.user_id, hexToBytes(v.current.signing_pk), hexToBytes(v.current.encryption_pk),
                    c.archived_keys, globalThis.sodium).map(p => ({{
                        signing_pk: bytesToHex(p.signingPk), encryption_pk: bytesToHex(p.encryptionPk),
                    }}));
            }} catch {{
                return 'error';
            }}
        }});
    }})()""")
    assert dict(zip([c["name"] for c in VECTORS["cases"]], result)) == {
        c["name"]: c["trusted"] for c in VECTORS["cases"]
    }
