"""INV-3 (docs/ROOT_CAUSE_PLAN.md S4): a DEK's owner_id is not signed.

With a password change the server has not received, a full resync takes the
server's DEK wraps only if the KEK the change replaces opens them (SM40); a
server restored to before an earlier change serves wraps under an even older
KEK, and the resync refuses ("a full resync would make every entry
unreadable"). The check skipped every DEK whose unsigned owner_id named
someone else, so a server relabelling the account's own DEKs let the resync
through. Whose DEK it is now comes from its verified signature.
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

FIRST = "first-new-pw!"
SECOND = "second-new-pw!"


@pytest.mark.parametrize("relabel", [False, True], ids=["honest", "owner_id lie"])
def test_full_resync_refuses_deks_under_an_older_kek_whatever_their_owner_id(server, tmp_path, relabel):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    me = laptop.db.get_meta("user_id")
    kept = {o["id"]: copy.deepcopy(o) for o in db._storage["vault_objects"] if o["object_type"] == "dek"}
    laptop.change_password(PASSWORD, FIRST)
    assert not _client(laptop, url).push()["conflicts"]
    # The server answers with the wraps it kept from before that change:
    # under the first KEK, validly signed when they were current.
    objects = db._storage["vault_objects"]
    objects[:] = [copy.deepcopy(kept[o["id"]]) if o["id"] in kept else o for o in objects]

    laptop.change_password(FIRST, SECOND)  # not pushed; the journal keeps the KEK it replaces
    client = _client(laptop, url)
    deks = [o for o in db._storage["vault_objects"] if o["object_type"] == "dek" and not o["is_deleted"]]
    assert deks and all(o.get("signature_user_id") in (None, me) for o in deks)
    if relabel:
        for obj in deks:
            obj["owner_id"] = "someone-else"  # the lie; the signature still names this account

    deks_before = laptop.db.fetchall("SELECT id, encrypted_dek, version FROM deks")
    with pytest.raises(RuntimeError, match="password change the server has not received"):
        client.full_resync(confirmed=True)
    assert laptop.db.fetchall("SELECT id, encrypted_dek, version FROM deks") == deks_before
    laptop.lock()
