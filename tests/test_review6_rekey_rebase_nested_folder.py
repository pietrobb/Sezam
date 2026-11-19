"""Stateful test (second admin): a refused member re-key of a folder and its
subfolder could never land after another device renamed the subfolder.

The subfolder is in the batch twice: as a child of the re-keyed parent (its
meta is sealed with the parent's key) and as the folder of its own new key.
The rebase re-sealed the other device's copy under the parent's new key, then
the subfolder's own pass saw that copy was not sealed with the subfolder's
old key and put it back as the server had it, at the server's version: every
later push refused the whole batch ("Atomic re-key batch conflict").
"""

from __future__ import annotations

import os

import pytest

from sezam.vault import pending_states
from sezam import cli
from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid, new_ulid
from tests.test_integration_client_server import (  # noqa: F401
    PASSWORD,
    _client,
    _server_member,
    _vault,
    server,
)
from tests.test_rekey_rebase_review8 import _server_object
from sezam.vault import outbox


def _dek(vault, node_id):
    return vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (node_id,))["dek_id"]


@pytest.mark.parametrize("map_order", ["parent_first", "child_first"])
def test_a_rebased_rekey_lands_over_a_renamed_subfolder(server, tmp_path, map_order):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    ops = laptop.create_node("Ops")
    sub = laptop.create_node("Sub", ops)
    laptop.create_entry(sub, "vpn", [{"key": "password", "value": "v1", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    member_id = _server_member(db)
    for node in (ops, sub):
        laptop.db.execute(
            "INSERT INTO access_envelopes "
            "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
            "VALUES (?, ?, ?, ?, 'read', ?)",
            (new_ulid(), _dek(laptop, node), member_id, laptop.db.get_meta("user_id"), os.urandom(72)),
        )
        outbox.queue_write(laptop.db, node)
    assert _client(laptop, url).push()["conflicts"] == []
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)

    phone.rename_node(sub, "Sub-renamed")
    assert _client(phone, url).push()["conflicts"] == []

    assert laptop.rekey_after_revocation(member_id) == 2
    if map_order == "child_first":
        batch = (pending_states.rekey_batch(laptop.db) or None)
        batch["dek_map"] = dict(reversed(list(batch["dek_map"].items())))
        pending_states.set_rekey_batch(laptop.db, batch)
    _client(laptop, url).push()

    assert pending_states.rekey_batch(laptop.db) == {}
    new_ops_dek = _dek(laptop, ops)
    sub_meta = bytes(_server_object(db, sub)["payload"])
    assert bytes_to_ulid(parse_envelope(sub_meta).dek_id) == new_ops_dek
    assert laptop.read_node(sub)["name"] == "Sub-renamed"
    _client(phone, url).pull()
    assert phone.read_node(sub)["name"] == "Sub-renamed"
    laptop.lock()
    phone.lock()
