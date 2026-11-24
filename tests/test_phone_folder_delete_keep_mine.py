"""Capability run 567 (R16-Z SM22), phone: a kept folder delete is refused forever.

The phone holds X below Y and deletes X offline. Meanwhile the desktop moves X
up to T and Y below X. The phone's delete is a conflict with that copy; the
user keeps it. The phone rebased the tombstone on the server copy but signed
its own old parent Y: the server read that as a move of X below its own child
(folder_move_cycle, SM22). That refusal carries the same version, so a pull
brought nothing new and the phone resent the delete on every sync, never
settling. The phone moves nothing: a kept delete stays where the server copy is.
"""

from __future__ import annotations

from sezam import cli
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import PASSWORD, _client, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)

PHONE_TEST = "test/phone_folder_delete_keep_mine_test.dart"


def _stored(db, obj_id: str) -> dict:
    return next(o for o in db._storage["vault_objects"] if o["id"] == obj_id)


def test_a_kept_folder_delete_settles_after_the_folder_moved(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    top = laptop.create_node("T")
    y = laptop.create_node("Y", top)
    x = laptop.create_node("X", y)
    cli._server_connect_flow(url, laptop, PASSWORD)
    client = _client(laptop, url)
    assert client.push()["conflicts"] == []

    def moved():
        client.pull()
        laptop.move_node(x, top)
        laptop.move_node(y, x)
        assert client.push()["conflicts"] == []
        assert (_stored(db, x)["parent_ref"], _stored(db, y)["parent_ref"]) == (top, x)

    out = _phone(url, tmp_path, {
        "username": "admin", "password": PASSWORD, "x": x, "y": y, "top": top,
    }, {"moved": moved}, PHONE_TEST)
    assert "All tests passed!" in out, out
    row = _stored(db, x)
    assert (row["is_deleted"], row["parent_ref"]) == (1, top)
    laptop.lock()
