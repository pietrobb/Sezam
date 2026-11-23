"""A device vouches only for server copies, never for its unsent versions (R16-Z, deep stateful run on 736ade3).

SecondAdminMachine counterexample (INV-3, goal #443): desktop A deleted a
folder; its entries became tombstones at version 2 with their payload
unchanged, not yet sent. A then posted the list of the versions it "holds"
(``_post_legacy_vouchers``), signed by the account's current key, and
``_held_entries`` named (id, 2, payload_hash) of those unsent tombstones. The
server, holding the key the account's rotation retired, signed a live v2 with
that payload and the web took it: the voucher key (id, version, payload_hash)
does not carry is_deleted or parent_ref. Invariant: a device vouches only for
what the server holds and it verified, a queued row's server copy, never for
a version it made and has not sent (that one goes out signed by the current
key).
"""

from __future__ import annotations

import pytest

from sezam import cli
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401  (fixture)


@pytest.mark.parametrize("change", ["delete", "edit"])
def test_an_unsent_version_is_not_held(server, tmp_path, change):  # noqa: F811
    url, _db = server
    vault = _vault(tmp_path / "a", "admin")
    cli._server_connect_flow(url, vault, PASSWORD)
    client = _client(vault, url)
    folder = vault.create_node("F")
    entry = vault.create_entry(folder, "e", [{"key": "password", "value": "pw"}])
    assert client.push()["conflicts"] == []
    sent = {e for e in client._held_entries() if e[0] == entry}
    assert [version for _id, version, _hash in sent] == [1]

    if change == "delete":
        vault.delete_entry(entry)
    else:
        vault.update_entry(entry, fields=[{"key": "password", "value": "new"}])
    assert vault.db.fetchone("SELECT version FROM entries WHERE id = ?", (entry,))["version"] == 2

    held = {e for e in client._held_entries() if e[0] == entry}
    assert all(version == 1 for _id, version, _hash in held), f"vouches for its unsent version: {held}"
    assert held <= sent

    assert client.push()["conflicts"] == []
    assert {version for _id, version, _hash in client._held_entries() if _id == entry} == {2}
