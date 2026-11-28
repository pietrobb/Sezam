"""tests/vectors/signed_messages.json on the desktop and the server: the login,
key rotation, reseed/rejoin and org-recovery rewrap messages are the core's
(docs/CORE_UNIFICATION.md U6c). core/tests/signed_messages_vectors.rs checks
the core itself, mobile/test/signed_messages_vectors_test.dart the phone."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from server.app import auth as server_auth
from server.app.routers import recovery as server_recovery
from sezam.vault import key_rotation, reseed, sync_common

V = json.loads(
    (Path(__file__).parent / "vectors" / "signed_messages.json").read_text(encoding="utf-8")
)
KEYS = ("old_signing_pk", "old_encryption_pk", "new_signing_pk", "new_encryption_pk")


@pytest.mark.parametrize("case", V["auth_challenge"])
def test_login_message(case):
    challenge = bytes.fromhex(case["challenge"])
    current = case["current_key"]
    assert server_auth.auth_challenge_message(challenge, current).hex() == case["message"]
    assert sync_common.auth_challenge_message(case["challenge"], current).hex() == case["message"]


@pytest.mark.parametrize("case", V["auth_challenge_refused"])
def test_a_malformed_challenge_is_no_login(case):
    with pytest.raises(RuntimeError):
        sync_common.auth_challenge_message(case["challenge"])
    try:
        challenge = bytes.fromhex(case["challenge"])
    except ValueError:
        return
    with pytest.raises(ValueError):
        server_auth.auth_challenge_message(challenge)


@pytest.mark.parametrize("case", V["key_rotation"])
def test_key_rotation_message(case):
    keys = [bytes.fromhex(case[k]) for k in KEYS]
    for build in (server_auth.key_rotation_message, sync_common.key_rotation_message):
        assert build(case["user_id"], *keys).hex() == case["message"]


@pytest.mark.parametrize("case", V["key_rotation_refused"])
def test_a_key_rotation_the_message_cannot_hold_is_refused(case):
    good = V["key_rotation"][0]
    keys = [bytes.fromhex(good[k]) for k in KEYS]
    user_id = case.get("user_id", good["user_id"])
    if case.get("short_key"):
        keys[0] = keys[0][:31]
    for build in (server_auth.key_rotation_message, sync_common.key_rotation_message):
        with pytest.raises(ValueError):
            build(user_id, *keys)


@pytest.mark.parametrize("case", V["reseed"])
def test_reseed_message(case):
    args = (
        bytes.fromhex(case["challenge"]), case["user_id"], case["username"],
        bytes.fromhex(case["signing_pk"]), bytes.fromhex(case["encryption_pk"]), case["key_epoch"],
    )
    for build in (server_auth.reseed_message, reseed.reseed_message):
        assert build(*args, rejoin=case["rejoin"]).hex() == case["message"]


@pytest.mark.parametrize("case", V["org_recovery_rewrap"])
def test_org_recovery_rewrap_message(case):
    args = (
        case["user_id"], case["key_epoch"], case["threshold"], case["total_shares"],
        bytes.fromhex(case["wrapped_kek"]),
    )
    for build in (server_recovery.org_recovery_rewrap_message, key_rotation.org_recovery_rewrap_message):
        assert build(*args).hex() == case["message"]


@pytest.mark.parametrize("case", V["org_recovery_rewrap_refused"])
def test_a_rewrap_the_message_cannot_hold_is_refused(case):
    args = dict(V["org_recovery_rewrap"][1])
    args.update(case)
    for build in (server_recovery.org_recovery_rewrap_message, key_rotation.org_recovery_rewrap_message):
        with pytest.raises(ValueError):
            build(args["user_id"], args["key_epoch"], args["threshold"], args["total_shares"],
                  bytes.fromhex(args["wrapped_kek"]))


def test_the_web_builds_every_message_through_the_core():
    from tests.test_review_web import _run

    seed = bytes(range(32))
    script = """(() => {
      const V = %s;
      const kp = sodium.crypto_sign_seed_keypair(hexToBytes('%s'));
      const refused = (f) => { try { f(); return false; } catch (_) { return true; } };
      return {
        rotation: V.key_rotation.map(v => bytesToHex(keyRotationMessage(v.user_id,
          hexToBytes(v.old_signing_pk), hexToBytes(v.old_encryption_pk),
          hexToBytes(v.new_signing_pk), hexToBytes(v.new_encryption_pk)))),
        rewrap: V.org_recovery_rewrap.map(v => bytesToHex(orgRecoveryRewrapMessage(v.user_id,
          v.key_epoch, v.threshold, v.total_shares, hexToBytes(v.wrapped_kek)))),
        logins: V.auth_challenge.filter(v => !v.current_key).map(v =>
          bytesToHex(signAuthChallenge(v.challenge, kp.privateKey, sodium))),
        refused: V.auth_challenge_refused.map(v =>
          refused(() => signAuthChallenge(v.challenge, kp.privateKey, sodium))),
      };
    })()""" % (json.dumps(V), seed.hex())
    out = _run(["keyRotationMessage", "orgRecoveryRewrapMessage", "signAuthChallenge"], script)
    assert out["rotation"] == [v["message"] for v in V["key_rotation"]]
    assert out["rewrap"] == [v["message"] for v in V["org_recovery_rewrap"]]
    logins = [v for v in V["auth_challenge"] if not v["current_key"]]
    verify = SigningKey(seed).verify_key
    for case, signature in zip(logins, out["logins"], strict=True):
        verify.verify(bytes.fromhex(case["message"]), bytes.fromhex(signature))
    assert out["refused"] == [True] * len(V["auth_challenge_refused"])
