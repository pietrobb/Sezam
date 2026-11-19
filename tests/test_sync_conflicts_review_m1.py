"""Lockout review 2026-11-08, medium finding M1: desktop sync conflicts.

A pull keeps an item edited both here and on another device as a conflict
shadow (sync_conflicts), but nothing read it: the user never learned about
it, every push conflicted again, and there was no way to pick a copy. Pull
results now warn (CLI and GUI), and ``sezam conflicts`` lists them and
resolves each by keeping the local or the server copy.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.vault import outbox
from sezam.vault.sync_client import pull_warnings
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,  # noqa: F401  (fixture)
)


@pytest.fixture
def conflicted(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Ops")
    entry = laptop.create_entry(folder, "vpn", [{"key": "password", "value": "base"}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)

    phone.update_entry(entry, fields=[{"key": "password", "value": "phone"}])
    assert _client(phone, url).push()["conflicts"] == []
    laptop.update_entry(entry, fields=[{"key": "password", "value": "laptop"}])
    assert [c["id"] for c in _client(laptop, url).push()["conflicts"]] == [entry]

    monkeypatch.setattr(cli, "_open_vault", lambda: laptop)
    monkeypatch.setattr(cli, "_unlock_vault", lambda vault, *a, **k: None)
    monkeypatch.setattr(laptop, "lock", lambda: None)
    yield url, laptop, phone, entry
    phone.lock()


def test_pull_warns_about_conflicts_and_cli_lists_them(conflicted):
    url, laptop, _phone, entry = conflicted
    result = _client(laptop, url).pull()

    assert any("SYNC CONFLICT: 1 item(s)" in w for w in pull_warnings(result))
    listed = CliRunner().invoke(cli.main, ["conflicts"])
    assert listed.exit_code == 0, listed.output
    assert entry in listed.output and "vpn" in listed.output
    # Both copies are still there until the user decides.
    assert _entry_value(laptop, "Ops", "vpn", "password") == "laptop"


def test_keeping_the_local_copy_supersedes_the_server(conflicted):
    url, laptop, phone, entry = conflicted
    _client(laptop, url).pull()

    resolved = CliRunner().invoke(
        cli.main, ["conflicts", "resolve", entry, "--keep", "local"]
    )
    assert resolved.exit_code == 0, resolved.output
    assert _client(laptop, url).push()["conflicts"] == []
    assert laptop.db.fetchall("SELECT object_id FROM sync_conflicts") == []
    _client(phone, url).pull()
    assert _entry_value(phone, "Ops", "vpn", "password") == "laptop"
    assert _entry_value(laptop, "Ops", "vpn", "password") == "laptop"


def test_keeping_a_local_delete_sends_the_tombstone_and_it_stays_restorable(
    server, tmp_path, monkeypatch  # noqa: F811
):
    """Review 688edcb M1: --keep local on an item deleted here.

    A delete only bumps the row version, so the tombstone's blobs stay sealed
    one version below it. Resolving opened them at the row version and the
    CLI died with a CryptoError traceback.
    """
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Ops")
    entry = laptop.create_entry(folder, "vpn", [{"key": "password", "value": "base"}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    phone.update_entry(entry, fields=[{"key": "password", "value": "phone"}])
    assert _client(phone, url).push()["conflicts"] == []
    laptop.delete_entry(entry)
    assert [c["id"] for c in _client(laptop, url).push()["conflicts"]] == [entry]
    _client(laptop, url).pull()
    monkeypatch.setattr(cli, "_open_vault", lambda: laptop)
    monkeypatch.setattr(cli, "_unlock_vault", lambda vault, *a, **k: None)
    monkeypatch.setattr(laptop, "lock", lambda: None)

    resolved = CliRunner().invoke(cli.main, ["conflicts", "resolve", entry, "--keep", "local"])

    assert resolved.exit_code == 0, resolved.output
    assert resolved.exception is None or isinstance(resolved.exception, SystemExit)
    assert _client(laptop, url).push()["conflicts"] == []
    _client(phone, url).pull()
    assert phone.db.fetchone("SELECT is_deleted FROM entries WHERE id = ?", (entry,))[0] == 1
    # The tombstone still opens: the delete can be undone from the trash.
    from sezam.vault.trash import restore_entry

    restore_entry(laptop, entry)
    assert _entry_value(laptop, "Ops", "vpn", "password") == "base"
    phone.lock()


def test_taking_the_server_copy_replaces_the_local_edit(conflicted):
    url, laptop, _phone, entry = conflicted
    _client(laptop, url).pull()

    resolved = CliRunner().invoke(
        cli.main, ["conflicts", "resolve", entry, "--keep", "server"]
    )
    assert resolved.exit_code == 0, resolved.output
    assert _entry_value(laptop, "Ops", "vpn", "password") == "phone"
    assert not outbox.has_write(laptop.db, entry)
    assert _client(laptop, url).push()["conflicts"] == []
    assert CliRunner().invoke(cli.main, ["conflicts"]).output.startswith("No sync conflicts")
