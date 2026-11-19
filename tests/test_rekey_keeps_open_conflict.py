"""Review e4cd15a #3: a second re-key silently overwrote the conflict V1 made.

After a rebased re-key the laptop's own edit is kept as a conflict with the
phone's (M1). A second re-key of the same folder (revoking a second member;
since #8b it runs on its own from the push) took the conflicting row for a
plain local edit, sealed it one version up and pushed it: the conflict was
gone and the phone's edit lost without a word. Now a re-key over open
conflicts is refused, the member stays queued, and the re-key runs with the
push after the user settled the conflict.
"""

from __future__ import annotations

import os

import pytest

from sezam.vault import pending_states
from sezam.models import new_ulid
from sezam.vault.revocation import (
    finish_queued_revocations,
    queued_revocations,
    revoke_member,
)
from tests.test_integration_client_server import (
    _client,
    _entry_value,
    _server_member,
    server,  # noqa: F401  (fixture)
)
from tests.test_rekey_rebase_keeps_local_edit import _laptop_value
from tests.test_rekey_rebase_review8 import (
    _assert_member_cut_off,
    _folder_shared_with_member,
)


@pytest.mark.parametrize("keep", ["local", "server"])
def test_second_rekey_waits_for_the_open_conflict(server, tmp_path, keep):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)
    phone.update_entry(entry, fields=_laptop_value("v2-phone-draft"))
    phone.update_entry(entry, fields=_laptop_value("v2-phone"))
    assert _client(phone, url).push()["conflicts"] == []

    laptop.update_entry(entry, fields=_laptop_value("v2-laptop"))
    assert laptop.rekey_after_revocation(member_id) == 1
    client = _client(laptop, url)
    client.push()
    first_dek = _assert_member_cut_off(db, laptop, folder, old_dek_id, member_id)
    assert [c["id"] for c in client.get_pull_conflicts()] == [entry]

    # A second member on the re-keyed folder.
    second = _server_member(db)
    laptop.db.execute(
        "INSERT INTO access_envelopes "
        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, 'read', ?)",
        (new_ulid(), first_dek, second, laptop.db.get_meta("user_id"), os.urandom(72)),
    )
    before = laptop.db.fetchone("SELECT version FROM entries WHERE id = ?", (entry,))["version"]

    with pytest.raises(RuntimeError, match="unresolved sync conflicts") as blocked:
        laptop.rekey_after_revocation(second)
    assert blocked.value.object_ids == [entry]
    assert (pending_states.rekey_batch(laptop.db) or None) in (None, {})
    assert laptop.db.fetchone("SELECT version FROM entries WHERE id = ?", (entry,))["version"] == before
    assert [c["id"] for c in client.get_pull_conflicts()] == [entry]

    # Through revoke_member (the server revocation is mocked away): queued.
    client.revoke_user = lambda user_id: None
    with pytest.raises(RuntimeError, match="unresolved sync conflicts"):
        revoke_member(laptop, client, second)
    assert queued_revocations(laptop) == [second]
    # The phone's edit is still the server's copy; the conflict is still open.
    assert [c["id"] for c in client.push()["conflicts"]] == [entry]
    _client(phone, url).pull()
    assert _entry_value(phone, "Ops", "vpn", "password") == "v2-phone"
    assert [c["id"] for c in client.get_pull_conflicts()] == [entry]

    # Settled: the queued re-key runs and the chosen copy survives it.
    client.resolve_conflict(entry, keep)
    assert finish_queued_revocations(laptop, client) == {second: 1}
    assert queued_revocations(laptop) == []
    expected = "v2-laptop" if keep == "local" else "v2-phone"
    assert _entry_value(laptop, "Ops", "vpn", "password") == expected
    _client(phone, url).pull()
    assert _entry_value(phone, "Ops", "vpn", "password") == expected
    laptop.lock()
    phone.lock()
