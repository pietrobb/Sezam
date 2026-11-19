"""Stateful test finding SM70 (web device): a change the web queued before its
folder was re-keyed went out under the old folder key.

The admin shared a folder with a member. The web saved an entry in it while
the network was down, so the page queued the encrypted entry. The admin then
removed the member, which re-keys the folder: the member keeps the old key.
The page pulled the new key and Retry sent the queued entry as it was, sealed
under the old key - readable by the removed member. Retry now seals a queued
change again under its folder's current key, as the desktop does with its
unsent items.
"""

from __future__ import annotations

from sezam import cli
from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid
from sezam.vault import revocation
from sezam.vault.crud import Vault
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PARAMS,
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401
from tests.web_tab import WebTab


def _entry_dek(db, entry_id: str) -> str:
    obj = next(o for o in db._storage["vault_objects"] if o["id"] == entry_id)
    payload = bytes(obj["payload"])
    return bytes_to_ulid(parse_envelope(payload[4:4 + int.from_bytes(payload[:4], "big")]).dek_id)


def _member(url, tmp_path, laptop, desk) -> str:
    invitation = desk.create_invitation()
    vault = Vault.create(tmp_path / "member", PASSWORD, PARAMS)
    vault.db.set_meta("username", "m1")
    poll = cli._poll_for_approval
    cli._poll_for_approval = lambda *a, **k: None
    try:
        cli._server_register_and_upload(
            url, vault, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"],
        )
    finally:
        cli._poll_for_approval = poll
    user_id = vault.db.get_meta("user_id")
    vault.lock()
    desk.approve_user(user_id=user_id)
    return user_id


def test_queued_web_change_is_sealed_under_the_folder_key_after_a_rekey(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Team")
    cli._server_connect_flow(url, laptop, PASSWORD)
    desk = _client(laptop, url)
    member = _member(url, tmp_path, laptop, desk)
    revocation.grant_member(laptop, desk, member, folder, "read", confirm_fingerprint=lambda _fp: True)
    old_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))[0]

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        saved = tab.do("save_object", mode="entry", name="db01", parent=folder,
                       fields=[{"key": "password", "value": "web-secret"}],
                       fail={"method": "POST", "path": "/api/sync", "mode": "before"})
        assert saved["view"]["dirty"], saved
        entry = saved["view"]["dirty"][0]

        desk.pull()
        assert revocation.revoke_member(laptop, desk, member) == 1
        new_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))[0]
        assert new_dek != old_dek

        assert tab.do("refresh")["error"] is None
        retried = tab.do("retry")
        assert retried["error"] is None, retried
        assert not retried["view"]["dirty"], retried
        assert _entry_dek(db, entry) == new_dek  # not the key the removed member holds
    finally:
        tab.kill()
    desk.pull()
    assert _entry_value(laptop, "Team", "db01", "password") == "web-secret"
    laptop.lock()
