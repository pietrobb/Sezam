"""Review 526419e N6: 'sezam abandon-pending-change' dropped more than it said.

It threw away the new password set on this device and, with it, an identity
key rotation done after a leak - the leaked key stayed valid on the server -
without a word. It now says what goes and asks first (--yes skips it).
"""

from __future__ import annotations

import os

from click.testing import CliRunner

from sezam.vault import oplock, pending_states
from sezam import cli
from sezam.vault import sync_client as sync_client_module
from tests.test_grant_folder_access import team  # noqa: F401  (fixture)
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401  (fixture)
from tests.test_stuck_key_change_escape import BOB_NEW, _bob


def _stuck_bob(team, tmp_path, monkeypatch, *, identity: bool):  # noqa: F811
    bob, _client = _bob(team, tmp_path)
    monkeypatch.setattr(
        sync_client_module, "open_current_auth_proof",
        lambda *a: bytearray(os.urandom(32)), raising=False,
    )
    bob.change_password(PASSWORD, BOB_NEW)
    if identity:
        journal = (pending_states.key_change_journal(bob.db) or None)
        with oplock.exclusive(bob.db.path):  # INV-6
            pending_states.set_key_change_journal(bob.db, {**journal, "identity": {}})
    bob.lock()
    monkeypatch.setattr(cli, "_open_vault", lambda: bob)
    monkeypatch.setattr(cli, "_load_session", lambda: None)
    monkeypatch.setattr(
        cli, "_get_password",
        lambda prompt="", **_kw: PASSWORD if "server has now" in prompt else BOB_NEW,
    )
    return bob


def test_it_warns_and_a_no_keeps_the_change(team, tmp_path, monkeypatch):  # noqa: F811
    bob = _stuck_bob(team, tmp_path, monkeypatch, identity=False)
    result = CliRunner().invoke(cli.main, ["abandon-pending-change"], input="n\n")
    assert result.exit_code != 0
    assert "drops the new password set on this device" in result.output
    assert "rotate-identity" not in result.output
    bob.unlock(BOB_NEW)
    try:
        assert (pending_states.key_change_journal(bob.db) or None)
    finally:
        bob.lock()


def test_it_names_a_dropped_identity_rotation(team, tmp_path, monkeypatch):  # noqa: F811
    _stuck_bob(team, tmp_path, monkeypatch, identity=True)
    result = CliRunner().invoke(cli.main, ["abandon-pending-change"], input="n\n")
    assert result.exit_code != 0
    assert "old identity key stays valid" in result.output
    assert "sezam rotate-identity" in result.output
