"""Review e4cd15a (low): a web KEK journal the server refuses with 409 stayed.

An org-recovery password change interrupted on the web is resent at every
login from its journal. When the server refused it for good (a data key
added elsewhere since the journal was written: "Key epoch advance must
include every active DEK"), the journal was kept and resent at every login,
failing the same way forever. Every 409 other than a lost epoch race now
drops the journal and tells the user why; the login screen shows it.
"""

from __future__ import annotations

from sezam import cli
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)
from tests.test_review2_web_rotation import NEW_PASSWORD, _apply, pytestmark  # noqa: F401
from tests.test_review_web import ROOT, _function


def test_journal_the_server_refuses_for_good_is_dropped(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    user_id = laptop.db.get_meta("user_id")
    old_keypair = next(u for u in db._storage["users"] if u["id"] == user_id)["encrypted_keypair"]

    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    client = _client(laptop, url)
    deks = [o for o in client._collect_dirty_objects() if o["object_type"] == "dek"]
    assert len(deks) >= 2
    material = client._key_rotation_payload(1)
    journal = {
        "username": "admin", "user_id": user_id,
        "argon2_salt": material["argon2_salt"], "argon2_params": material["argon2_params"],
        "encrypted_keypair": material["encrypted_keypair"],
        "deks": deks[:-1],  # a data key the journal does not know
        "key_epoch": 1, "recovery_store": None,
    }
    signing_sk = (bytes(laptop.keypair.signing_sk) + laptop.keypair.signing_pk).hex()

    refused = _apply(url, journal, material["auth_proof"], signing_sk, client.token)
    assert refused["errorName"] == "KekRotationRefusedError", refused
    assert refused["error"] == "recovery.rotation_refused" and refused["cleared"]
    user = next(u for u in db._storage["users"] if u["id"] == user_id)
    assert user["encrypted_keypair"] == old_keypair
    laptop.lock()


def test_login_shows_the_refusal_instead_of_a_wrong_password():
    login = _function("handleLogin")
    resume = login[login.index("await resumeKekRotation("):login.index("// 1. Get meta")]
    assert "resumeErr instanceof KekRotationRefusedError" in resume
    i18n = (ROOT / "web" / "static" / "js" / "i18n.js").read_text(encoding="utf-8")
    assert i18n.count("'recovery.rotation_refused':") == 2  # sk + en
