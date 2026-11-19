"""Stateful test finding SM89 (web device): a server restore went unnoticed
after a password change elsewhere.

The page saved an item and the server was then restored from a backup taken
before it; the laptop changed the account password on the restored server.
The page's rollback checkpoint was sealed with the old KEK: the sign-in with
the new password set it aside as unreadable and dropped it, so the full pull
had nothing to compare with. The restored server's state was taken without
the question SM71 asks, and the item the page had saved was gone without a
word. Sealed then with a key from the account's signing key, it was still
dropped by an identity rotation elsewhere (SM90). It is now sealed with a
random key of this browser, which no key change of the account touches.
"""

from __future__ import annotations

import copy

import pytest

from sezam import cli
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401
from tests.web_tab import WebTab

NEW_PASSWORD = "integration-new-pw-Sezam!"


def _names(view: dict) -> set[str]:
    return {e["name"] for e in view["entries"]}


@pytest.mark.parametrize("rotate", [False, True], ids=["password", "identity_sm90"])
def test_web_notices_a_restore_after_a_password_change_elsewhere(server, tmp_path, rotate):  # noqa: F811
    # SM90: a rotated identity key (with or without a new password) dropped
    # the checkpoint sealed under a key from the signing key just the same.
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    log = tmp_path / "tab.log"

    tab = WebTab(url, log)
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        backup = copy.deepcopy(db._storage)
        saved = tab.do("save_object", mode="entry", name="web01", parent=folder,
                       fields=[{"key": "password", "value": "w"}])
        assert saved["error"] is None, saved
        db._storage.clear()
        db._storage.update(copy.deepcopy(backup))

        proof = laptop.change_password(PASSWORD, NEW_PASSWORD, rotate_identity=rotate)
        proof[:] = b"\x00" * len(proof)
        client = _client(laptop, url)
        assert client.push()["conflicts"] == []

        tab = WebTab(url, log, tab.close())
        refused = tab.do("login", username="admin", password=NEW_PASSWORD, confirm=False)
        assert any("rollback_confirm" in c for c in refused["confirms"]), (
            "the page took the restored server without asking", refused["error"], refused["confirms"])
        assert "ROLLBACK DETECTED" in (refused["error"] or ""), refused

        tab = WebTab(url, log, tab.close())
        accepted = tab.do("login", username="admin", password=NEW_PASSWORD, confirm=True)
        assert accepted["error"] is None, accepted
        assert any("rollback_confirm" in c for c in accepted["confirms"]), accepted
        assert _names(accepted["view"]) == {"db01"}
    finally:
        tab.kill()
    laptop.lock()
