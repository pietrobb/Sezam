"""Review c78fd19 (medium): a device pinned to a team log the server lost for
good had no way out. 'sezam team-log forget-pin GENESIS' drops the pin after
the user typed it; the next pull follows the server's log as a new one.
"""

from __future__ import annotations

import pytest

from sezam.models import new_ulid
from sezam.vault.team_log_forget import forget_team_log_pin, pinned_genesis
from sezam.vault.team_log_local import (
    CONFIRMED_GENESIS_META, FORGOTTEN_GENESIS_META, GENESIS_META, TeamLogMismatch, import_account_anchor,
)
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_team_log_desktop import (  # noqa: F401
    _confirm_founder,
    _forget_server_cache,
    _found_with_bob,
    team,
)


def _reseed_server(db, client) -> str:
    """The server lost the log for good; the admin founds another one."""
    db._storage["team_log"] = []
    _forget_server_cache()
    client._db.execute("DELETE FROM team_log")
    client._db.execute("DELETE FROM vault_meta WHERE key IN (?, ?)", (GENESIS_META, CONFIRMED_GENESIS_META))
    client._team_state_cache = None
    client.found_team_log(new_ulid())
    return client.team_state().genesis_hash


def _cli(monkeypatch, vault, *args):
    from click.testing import CliRunner
    from sezam import cli

    monkeypatch.setattr(cli, "_open_vault", lambda: vault)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda v: v.unlock(PASSWORD))
    return CliRunner().invoke(cli.main, ["team-log", *args], input="y\n")


def test_a_device_leaves_a_lost_log_and_follows_the_new_one(team, monkeypatch):  # noqa: F811
    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    old = bob_client.team_state().genesis_hash
    bob.db.set_meta(CONFIRMED_GENESIS_META, old)
    new = _reseed_server(db, client)

    with pytest.raises(TeamLogMismatch, match="forget-pin"):
        bob_client.pull()

    for typed in ("", old[:15], new[:16], "f" * 64):
        with pytest.raises(ValueError, match="Type the pinned genesis"):
            forget_team_log_pin(bob, typed, bob_client)
    assert pinned_genesis(bob) == {old}

    result = _cli(monkeypatch, bob, "forget-pin")
    assert result.exit_code == 0 and old in result.output
    bob.unlock(PASSWORD)
    assert pinned_genesis(bob) == {old}
    result = _cli(monkeypatch, bob, "forget-pin", old[:16])
    assert result.exit_code == 0, result.output
    bob.unlock(PASSWORD)
    assert pinned_genesis(bob) == set()
    assert bob.db.get_meta_json(FORGOTTEN_GENESIS_META) == [old]

    bob_client = _client(bob, bob.db.get_meta("server_url"))
    bob_client.pull()
    assert bob_client.team_state().genesis_hash == new
    assert bob_client.team_log_trusted()  # the founder's keys are the confirmed ones


def test_forget_pin_drops_the_anchor_of_the_local_keys_and_ignores_the_bundle(team):  # noqa: F811
    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    old = bob_client.team_state().genesis_hash
    bob.keypair.confirmed_genesis = old  # as published in the account keys
    assert pinned_genesis(bob) == {old}
    _reseed_server(db, client)

    forget_team_log_pin(bob, old, bob_client)
    assert bob.keypair.confirmed_genesis is None
    bob.lock()
    bob.unlock(PASSWORD)
    assert bob.keypair.confirmed_genesis is None and pinned_genesis(bob) == set()

    # The account bundle on the server still names the old log: not taken back.
    bob.keypair.confirmed_genesis = old
    import_account_anchor(bob.db, bob.keypair)
    assert bob.keypair.confirmed_genesis is None
    assert bob.db.get_meta(CONFIRMED_GENESIS_META) is None


def test_confirming_the_genesis_again_ends_the_forgetting(team, monkeypatch):  # noqa: F811
    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    old = bob_client.team_state().genesis_hash
    _reseed_server(db, client)
    forget_team_log_pin(bob, old, bob_client)

    result = _cli(monkeypatch, bob, "confirm-genesis", old)
    assert result.exit_code == 0, result.output
    bob.unlock(PASSWORD)
    assert bob.db.get_meta(CONFIRMED_GENESIS_META) == old
    assert not bob.db.get_meta_json(FORGOTTEN_GENESIS_META)


def test_after_forgetting_a_server_without_log_is_a_mismatch_until_the_admin_founds_one(team, monkeypatch):  # noqa: F811
    """Review 8bc70f7 M2: the device went back to the rules from before any log."""
    from server.app import team_log as server_log
    from sezam.vault import team_migration

    async def refuse(cur, records, user_id, **_):
        raise server_log.ApiError(400, server_log.TEAM_LOG_REFUSED, {"message": "no"})

    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    old = bob_client.team_state().genesis_hash
    db._storage["team_log"] = []  # lost for good (no restore), nothing founded yet
    _forget_server_cache()
    monkeypatch.setattr(server_log, "restore", refuse)
    for vault, device in ((bob, bob_client), (admin, client)):
        with pytest.raises(TeamLogMismatch, match="forget-pin"):
            device.pull()
        forget_team_log_pin(vault, old, device)
        with pytest.raises(TeamLogMismatch, match="left an earlier one"):
            device.pull()

    team_migration.found_team_log(admin, client, confirm_fingerprint=lambda _u, _fp: True)
    new = client.team_state().genesis_hash
    assert new != old
    bob_client.pull()  # a log again: followed, trusted only once its founder is confirmed
    assert bob_client.team_state().genesis_hash == new


def test_forget_pin_waits_for_unsent_team_changes(team):  # noqa: F811
    from sezam.vault import outbox

    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    old = client.team_state().genesis_hash
    outbox.put(client._db, outbox.TEAM_CHANGE, ["folder.key", {}], new_ulid())
    with pytest.raises(RuntimeError, match="settle them first"):
        forget_team_log_pin(admin, old, client)
    assert pinned_genesis(admin) == {old}
