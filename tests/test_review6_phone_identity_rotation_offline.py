"""Review main@d615826 (mobile): offline edits after taking over an identity rotation.

Desktop A rotated the account's identity keys while the phone had an edit it
had not sent yet. The phone took the rotation over with the password, but the
edit kept the signature of the retired key, so the server refused it on every
push and it never synced. It now goes out signed with the new key; a new
desktop joining the account reads it.
"""

from __future__ import annotations

import pytest

from sezam import cli
from sezam.vault.team_migration import found_team_log
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    NEW_PASSWORD,
    _client,
    _vault,
    server,
)

PHONE_TEST = "test/phone_identity_rotation_offline_test.dart"


@pytest.mark.parametrize("with_team_log", ["qr-portable", "qr-portable-downgrade", "qr-portable-conflict", "qr-portable-crash", "qr-portable-authfail", "qr-portable-autolock", "qr-connect-portable", False, True, "portable", "portable-crash", "portable-downgrade", "portable-conflict", "locked-portable", "locked-portable-downgrade", "locked-portable-conflict", "recover-portable-downgrade", "locked-portable-crash", "connect-portable", "connect-portable-crash", "connect-portable-downgrade", "connect-portable-conflict", "connect-portable-authfail", "connect-portable-autolock"], ids=["qr-portable", "qr-portable-downgrade", "qr-portable-conflict", "qr-portable-crash", "qr-portable-authfail", "qr-portable-autolock", "qr-connect-portable", "legacy", "team-log", "portable", "portable-crash", "portable-downgrade", "portable-conflict", "locked-portable", "locked-portable-downgrade", "locked-portable-conflict", "recover-portable-downgrade", "locked-portable-crash", "connect-portable", "connect-portable-crash", "connect-portable-downgrade", "connect-portable-conflict", "connect-portable-authfail", "connect-portable-autolock"])
def test_offline_edit_syncs_after_the_phone_takes_over_an_identity_rotation(server, tmp_path, with_team_log):  # noqa: F811
    url, _db = server
    qr = isinstance(with_team_log, str) and with_team_log.startswith("qr-")
    with_team_log = with_team_log.removeprefix("qr-") if qr else with_team_log
    recover = isinstance(with_team_log, str) and with_team_log.startswith("recover-")
    locked = recover or isinstance(with_team_log, str) and with_team_log.startswith("locked-")
    with_team_log = with_team_log.removeprefix("locked-").removeprefix("recover-") if locked else with_team_log
    reconnect = isinstance(with_team_log, str) and with_team_log.startswith("connect-")
    with_team_log = with_team_log.removeprefix("connect-") if reconnect else with_team_log
    current_password = NEW_PASSWORD if locked or reconnect or qr else PASSWORD
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    if with_team_log:
        client = _client(laptop, url)
        found_team_log(laptop, client)
        client.append_team_log([("folder.key", {
            "folder": folder, "dek_id": laptop.dek_mgr.get_dek_for_node(folder)[0], "prev_dek_id": None,
        })])
    if isinstance(with_team_log, str):
        from sezam.crypto import aead
        from sezam.crypto.keys import KeyPair
        uid = laptop.db.get_meta("user_id")
        genesis = client.team_state().genesis_hash
        keys = KeyPair.from_private_only(aead.encode_account_keypair(laptop.keypair.serialize_private(), genesis))
        laptop.rebind_server_identity(uid, keys)
        user = next(u for u in _db._storage["users"] if u["id"] == uid)
        user["encrypted_keypair"] = aead.encrypt_keypair_wrap(
            laptop.keypair.serialize_private(), laptop.current_kek,
            laptop.db.get_meta("kek_dek_id").encode(), uid.encode())
    old_pk = laptop.keypair.signing_pk
    honest_wrap = None

    def rotated():
        _client(laptop, url).prepare_key_change()
        proof = laptop.change_password(PASSWORD, current_password, rotate_identity=not reconnect)
        proof[:] = b"\x00" * len(proof)
        laptop.unlock(current_password)
        _client(laptop, url).push()
        assert (laptop.keypair.signing_pk == old_pk) == reconnect
        if with_team_log in ("portable-downgrade", "portable-conflict"):
            nonlocal honest_wrap
            current_user = next(u for u in _db._storage["users"] if u["id"] == uid)
            honest_wrap = current_user["encrypted_keypair"]
            raw, _ = aead.decode_account_keypair(laptop.keypair.serialize_private())
            candidate = raw if with_team_log == "portable-downgrade" else aead.encode_account_keypair(raw, "cd" * 32)
            current_user["encrypted_keypair"] = aead.encrypt_keypair_wrap(
                candidate, laptop.current_kek, laptop.db.get_meta("kek_dek_id").encode(), uid.encode())

    def qr_token():
        tokens = [_client(laptop, url).create_provisioning_token()["token"] for _ in range(6)]
        (tmp_path / "phone" / "qr-token.txt").write_text("\n".join(tokens), encoding="utf-8")

    def restore_bundle():
        next(u for u in _db._storage["users"] if u["id"] == uid)["encrypted_keypair"] = honest_wrap

    _phone(url, tmp_path, {"username": "admin", "password": PASSWORD,
                          "genesis": genesis if isinstance(with_team_log, str) else None,
                          "crash": with_team_log == "portable-crash", "locked": locked,
                          "current_password": current_password, "recover": recover, "reconnect": reconnect, "qr": qr,
                          "authfail": with_team_log == "portable-authfail", "autolock": with_team_log == "portable-autolock",
                          "refuse": with_team_log in ("portable-downgrade", "portable-conflict")},
           {"rotated": rotated, **({"qr_token": qr_token} if qr else {}), **({"restore_bundle": restore_bundle}
             if with_team_log in ("portable-downgrade", "portable-conflict") else {})}, PHONE_TEST)

    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, current_password)
    passwords = {
        e["name"]: tablet.get_field_value(e["id"], "password")
        for n in tablet.list_nodes() for e in tablet.list_entries(n["id"])
    }
    assert passwords == {"db01": "s3cret", "offline": "o1"}
    tablet.lock()
    laptop.lock()
