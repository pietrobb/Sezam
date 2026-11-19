"""Review 688edcb V1: the re-key rebase (#8a) dropped the local edit.

The laptop revokes a member and edits an entry of the re-keyed folder before
the re-key reaches the server; the phone pushes its own edit of the same
entry first. The refused batch was rebased onto the phone's copy and the
laptop's edit vanished without a conflict. Now the batch still lands on the
server copy (the member is cut off) and the laptop's edit comes back as an
ordinary conflict (M1) the user settles.
"""

from __future__ import annotations

import pytest

from tests.test_integration_client_server import (
    _client,
    _entry_value,
    server,  # noqa: F401  (fixture)
)
from tests.test_rekey_rebase_review8 import (
    _assert_member_cut_off,
    _folder_shared_with_member,
    _server_entry_dek,
)


def _laptop_value(value: str) -> list[dict]:
    return [{"key": "password", "value": value, "sensitive": True}]


@pytest.mark.parametrize("edit_before_rekey", [False, True])
@pytest.mark.parametrize("keep", ["local", "server"])
def test_local_edit_of_a_rebased_rekey_becomes_a_conflict(
    server, tmp_path, keep, edit_before_rekey  # noqa: F811
):
    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)

    # Two phone edits: the server copy is at least as new as the laptop's
    # (re-key + edit), so the batch is refused and rebased.
    phone.update_entry(entry, fields=_laptop_value("v2-phone-draft"))
    phone.update_entry(entry, fields=_laptop_value("v2-phone"))
    assert _client(phone, url).push()["conflicts"] == []

    if edit_before_rekey:
        laptop.update_entry(entry, fields=_laptop_value("v2-laptop"))
    assert laptop.rekey_after_revocation(member_id) == 1
    if not edit_before_rekey:
        laptop.update_entry(entry, fields=_laptop_value("v2-laptop"))
    client = _client(laptop, url)
    client.push()

    # The re-key landed: the member's old key opens nothing on the server.
    new_dek_id = _assert_member_cut_off(db, laptop, folder, old_dek_id, member_id)
    assert _server_entry_dek(db, entry) == new_dek_id
    # The laptop's edit is kept locally, as a conflict with the phone's.
    assert _entry_value(laptop, "Ops", "vpn", "password") == "v2-laptop"
    assert [c["id"] for c in client.get_pull_conflicts()] == [entry]
    # It is not pushed over the phone's edit behind the user's back.
    assert [c["id"] for c in client.push()["conflicts"]] == [entry]
    client.pull()
    assert [c["id"] for c in client.get_pull_conflicts()] == [entry]

    client.resolve_conflict(entry, keep)
    expected = "v2-laptop" if keep == "local" else "v2-phone"
    assert client.push()["conflicts"] == []
    assert _entry_value(laptop, "Ops", "vpn", "password") == expected
    assert _server_entry_dek(db, entry) == new_dek_id
    _client(phone, url).pull()
    assert _entry_value(phone, "Ops", "vpn", "password") == expected
    laptop.lock()
    phone.lock()
