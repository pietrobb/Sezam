"""Idea #8: a login answer signs only AUTH context || a 40-byte challenge.

Before, every client signed the server's challenge bytes bare, so a malicious
server could send any bytes (a canonical sync object, an AI policy, an audit
record) as a "challenge" and get the identity key's signature on them.
"""

from __future__ import annotations

import re
import time

import pytest
from nacl.exceptions import BadSignatureError

from sezam.crypto.keys import generate_keypair
from sezam.vault.sync_client import SyncClient
from server.app import auth as server_auth
from server.app.auth import generate_challenge, verify_challenge_signature
from tests.test_review_web import APP, ROOT, _run
from tests.test_review_web import pytestmark as _node_mark

CONTEXT = b"sezam-auth-challenge-signature-v1"


def _client(replies: list[dict]):
    client = SyncClient.__new__(SyncClient)
    client._keypair = generate_keypair()
    client._token = None
    client._get_username = lambda: "alice"
    client._report_legacy_kdf_params = lambda: None
    client._pending_old_keypair = lambda: None
    sent: list[tuple[str, dict]] = []

    def request(method, path, body=None, auth=False):
        sent.append((path, body))
        return replies.pop(0)

    client._request = request
    return client, sent


def test_every_side_takes_the_message_from_the_core():
    # docs/CORE_UNIFICATION.md U6c: one builder, the core's; the context is
    # nowhere else. tests/test_signed_messages_vectors.py checks the bytes.
    challenge = bytes(range(40))
    assert server_auth.auth_challenge_message(challenge) == CONTEXT + challenge
    dart = (ROOT / "mobile" / "lib" / "services" / "crypto_service.dart").read_text(encoding="utf-8")
    for source in (APP, dart):
        assert "'auth_challenge_message'" in source
        assert CONTEXT.decode() not in source


def test_server_accepts_the_domain_separated_login_signature():
    kp = generate_keypair()
    challenge, _ = generate_challenge()
    sk = kp.to_nacl_signing_key()
    pk = bytes(sk.verify_key)
    assert verify_challenge_signature(challenge, sk.sign(CONTEXT + challenge).signature, pk)
    # A signature made for another purpose over the same bytes is no login.
    assert not verify_challenge_signature(
        challenge, sk.sign(b"sezam-reseed-v1" + challenge).signature, pk
    )


def test_bare_signature_is_logged_and_has_an_end_date(monkeypatch, caplog):
    kp = generate_keypair()
    sk = kp.to_nacl_signing_key()
    pk = bytes(sk.verify_key)
    challenge, _ = generate_challenge()
    bare = sk.sign(challenge).signature

    monkeypatch.setenv("SEZAM_LEGACY_BARE_SIGNATURE_UNTIL", "2999-01-01")
    with caplog.at_level("WARNING", logger="server.app.auth"):
        assert verify_challenge_signature(challenge, bare, pk)
    assert "bare challenge signature" in caplog.text
    assert "2999-01-01" in caplog.text
    caplog.clear()

    # After the end date the old form is refused as an outdated client (426,
    # review e4cd15a) and the refusal logged.
    monkeypatch.setenv("SEZAM_LEGACY_BARE_SIGNATURE_UNTIL", "2020-01-01")
    with caplog.at_level("WARNING", logger="server.app.auth"):
        with pytest.raises(server_auth.OutdatedClientSignature):
            verify_challenge_signature(challenge, bare, pk)
    assert "Refused a bare challenge signature" in caplog.text
    # The current form is unaffected.
    assert verify_challenge_signature(challenge, sk.sign(CONTEXT + challenge).signature, pk)


def test_bare_signature_default_end_date_is_set(monkeypatch):
    monkeypatch.delenv("SEZAM_LEGACY_BARE_SIGNATURE_UNTIL", raising=False)
    assert server_auth.legacy_bare_signature_until().isoformat() == "2027-05-01"


def test_desktop_login_signs_context_and_challenge_not_the_bare_bytes():
    challenge, _ = generate_challenge()
    client, sent = _client([{"challenge": challenge.hex()}, {"token": "jwt"}])
    assert client.authenticate() == "jwt"
    signature = bytes.fromhex(sent[1][1]["signature"])
    verify_key = client._keypair.to_nacl_verify_key()
    verify_key.verify(CONTEXT + challenge, signature)
    with pytest.raises(BadSignatureError):
        verify_key.verify(challenge, signature)


@pytest.mark.parametrize("forged", [
    # A canonical object/policy the server would like signed: not a challenge.
    b"sezam-ai-policy-v1" + b"\x00" * 26 + b"\x01" + (2**40).to_bytes(8, "big"),
    b"\x00" * 39,
    b"\x00" * 41,
], ids=["policy", "short", "long"])
def test_desktop_refuses_to_sign_a_server_chosen_message(forged):
    client, sent = _client([{"challenge": forged.hex()}, {"token": "jwt"}])
    with pytest.raises(RuntimeError, match="malformed login challenge"):
        client.authenticate()
    assert [path for path, _ in sent] == ["/api/auth/challenge"]


@_node_mark
def test_web_signs_context_and_challenge_and_refuses_other_lengths():
    challenge = (b"\x07" * 32 + int(time.time() * 1000).to_bytes(8, "big")).hex()
    script = f"""
    (() => {{
      const kp = sodium.crypto_sign_keypair();
      const ch = hex('{challenge}');
      const sig = signAuthChallenge('{challenge}', kp.privateKey, sodium);
      const msg = new Uint8Array([...new TextEncoder().encode('sezam-auth-challenge-signature-v1'), ...ch]);
      const refused = ['00'.repeat(39), '00'.repeat(41), 'zz'.repeat(40), '{challenge}0'].map(c => {{
        try {{ signAuthChallenge(c, kp.privateKey, sodium); return false; }}
        catch (e) {{ return /malformed login challenge/.test(e.message); }}
      }});
      return {{
        context: sodium.crypto_sign_verify_detached(sig, msg, kp.publicKey),
        bare: sodium.crypto_sign_verify_detached(sig, ch, kp.publicKey),
        refused,
      }};
    }})()
    """
    out = _run(["hexToBytes", "signAuthChallenge"], script)
    assert out == {"context": True, "bare": False, "refused": [True, True, True, True]}


def test_no_web_call_site_signs_a_challenge_bare():
    # Every challenge the web answers goes through signAuthChallenge.
    assert not re.search(r"crypto_sign_detached\(\s*hexToBytes\(", APP)
    assert not re.search(r"crypto_sign_detached\(\s*challenge", APP, re.IGNORECASE)
    assert APP.count("signAuthChallenge(") >= 9
