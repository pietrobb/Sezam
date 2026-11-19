"""Stateful test finding SM34: a change below a folder deleted elsewhere failed an atomic push.

The phone created a subfolder in F while the laptop, which had not seen it,
deleted F: the server kept the subfolder live below the deleted folder. After
the last pull the laptop renamed the subfolder and changed the password. The
push is one atomic batch (password re-wrap, or a re-key after removing a
member), and the server refused the rename ('parent folder is deleted'), so
the whole push failed. The pull revived such a folder; the push did not. It
now does before collecting what to send.
"""

from __future__ import annotations

from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def test_rename_below_a_folder_deleted_elsewhere_goes_out_with_a_password_change(
    server, tmp_path  # noqa: F811
):
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    sub = phone.create_node("sub", parent_id=folder)
    assert not phone_client.push()["conflicts"]
    laptop.delete_node(folder)
    assert not laptop_client.push()["conflicts"]
    laptop_client.pull()
    phone_client.pull()

    laptop.rename_node(sub, "renamed")
    laptop.change_password(PASSWORD, "new-pw-sm34!")
    assert not laptop_client.push()["conflicts"]
    assert not laptop_client.has_pending_key_change()
    assert not laptop.db.fetchone("SELECT 1 FROM nodes WHERE id IN (SELECT object_id FROM outbox WHERE kind = 'write')")
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ? AND is_deleted = 0", (folder,))
    laptop.lock()
    phone.lock()
