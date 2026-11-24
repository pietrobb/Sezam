"""R16-Z SM22, INV-3: the server names where a refused crossed folder move goes
back, but it may withhold, not forge.

ebc634d moved the folder below an unsigned ``server_parent_ref``: a server
lying in it put the folder (its name and its subtree's keys resealed for that
parent) below any folder the device holds. Now the parent comes only from the
server's signed copy of the folder, and only when that copy is the one the
move was made on; a forged copy leaves the folder where the user put it.
"""

from __future__ import annotations

from tests.test_crossed_moves_devices_sm22 import _parents
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def _forging(client, z):
    real = client._request

    def request(method, path, body=None, **kw):
        resp = real(method, path, body, **kw)
        if (method, path) == ("POST", "/api/sync"):
            for c in resp.get("conflicts", []):
                if c.get("code") == "folder_move_cycle":
                    c["server_parent_ref"] = z
                    if c.get("stored_object"):
                        c["stored_object"] = {**c["stored_object"], "parent_ref": z}
        return resp

    client._request = request


def test_a_forged_parent_does_not_move_the_folder(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client = _client(laptop, url)
    top = _folder(laptop)
    x = laptop.create_node("X", top)
    y = laptop.create_node("Y", top)
    z = laptop.create_node("Z", top)
    laptop_client.push()
    phone_client = _client(phone, url)
    phone_client.pull()

    laptop.move_node(x, y)
    laptop_client.push()
    phone.move_node(y, x)
    _forging(phone_client, z)
    phone_client.push()

    assert _parents(phone)[y] == x, "the server's unsigned word moved the folder"
    assert phone_client.dirty_object_count() > 0
    laptop.lock()
    phone.lock()
