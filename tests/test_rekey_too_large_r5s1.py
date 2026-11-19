"""Review d150605 S1: a re-key with an item over the server's 1 MiB limit.

An entry saved before the per-entry size check (526419e #1) could be over
the server's 1 MiB limit per object. Re-keying its folder made an atomic
batch the server never takes: every push raised SyncUnitTooLarge, so no
other change went out, and in finish_queued_revocations the error stopped
the whole queue - the next revoked member was never re-keyed. Now the re-key
is refused before a batch exists (the member stays queued with the reason),
an old batch like that waits for 'sezam abandon-rekey' while the rest of the
push goes out, and the members after it are re-keyed.
"""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

from sezam.vault import pending_states
from sezam import cli
from sezam.vault import crud
from sezam.vault.revocation import finish_queued_revocations, queued_revocations
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    _client,
    server,
)
from tests.test_revoke_second_member_8b import _admin_with_two_members, _envelopes_live


def _big_entry_in_bobs_folder(admin, bob_id, monkeypatch):
    """An entry over 1 MiB, as one saved before the per-entry check."""
    folder = admin.db.fetchone(
        "SELECT n.id FROM nodes n JOIN access_envelopes a ON a.dek_id = n.dek_id "
        "WHERE a.user_id = ?", (bob_id,)
    )["id"]
    with monkeypatch.context() as patched:
        patched.setattr(crud, "require_syncable_entry", lambda *a: None)
        return admin.create_entry(
            folder, "huge-note", [{"key": "note", "value": os.urandom(600 * 1024).hex()}]
        )


def _setup(url, db, tmp_path, monkeypatch):
    admin, bob_id, carol_id = _admin_with_two_members(url, db, tmp_path, monkeypatch)
    big = _big_entry_in_bobs_folder(admin, bob_id, monkeypatch)
    client = _client(admin, url)
    client.push()  # the big entry stays local (over the limit)
    client.revoke_user(bob_id)
    client.revoke_user(carol_id)
    return admin, client, bob_id, carol_id, big


def test_too_large_member_rekey_is_refused_and_the_queue_goes_on(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    admin, client, bob_id, carol_id, _big = _setup(url, db, tmp_path, monkeypatch)
    pending_states.set_revocation_queue(admin.db, [bob_id, carol_id])

    with pytest.raises(RuntimeError) as waiting:
        finish_queued_revocations(admin, client)
    assert getattr(waiting.value, "done", None) == {carol_id: 1}
    too_large = getattr(waiting.value, "too_large", {})
    assert bob_id in too_large and "1024 KiB" in too_large[bob_id]
    assert not (pending_states.rekey_batch(admin.db) or None)  # no batch made
    assert not _envelopes_live(db, carol_id)
    assert _envelopes_live(db, bob_id)
    assert queued_revocations(admin) == [bob_id]


def test_old_too_large_rekey_batch_does_not_hold_back_the_push(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    admin, client, bob_id, _carol_id, _big = _setup(url, db, tmp_path, monkeypatch)
    # A batch made before the check (as old versions did).
    with monkeypatch.context() as patched:
        patched.setattr(crud, "payload_too_large", lambda size: False)
        admin.rekey_after_revocation(bob_id)
    assert (pending_states.rekey_batch(admin.db) or None)
    other = admin.db.fetchone(
        "SELECT id FROM nodes WHERE id NOT IN "
        "(SELECT n.id FROM nodes n JOIN access_envelopes a ON a.dek_id = n.dek_id "
        "WHERE a.user_id = ?) AND parent_id IS NULL", (bob_id,)
    )["id"]
    new_entry = admin.create_entry(other, "made-meanwhile", [{"key": "password", "value": "x"}])

    result = client.push()

    assert any(a["id"] == new_entry for a in result["accepted"])
    assert "sezam abandon-rekey" in result["rekey_too_large"]
    assert (pending_states.rekey_batch(admin.db) or None)  # waits for the abandon
    assert _envelopes_live(db, bob_id)

    cli_result = CliRunner().invoke(cli.main, ["push"])
    assert cli_result.exit_code == 0, cli_result.output
    assert "sezam abandon-rekey" in cli_result.output
