"""Review 8595ec1 (R10-C, goal #373): founding the log silently hid older items.

Before the log, Bob wrote an item into Ops with a write grant; later he was
lowered to read (or this device never confirmed his key). Founded from that
state, the log gives him no write access to Ops, so every client judges his
item as written without write access and hides it. 8595ec1 founded without a
word about it. Now the plan names those items (author, folder, reason) before
anything is signed, and 'sezam team-log init' shows them with the ways out.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.models import new_ulid
from sezam.vault import revocation
from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META
from sezam.vault.team_migration import found_team_log
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review7_forged_root_folder_desktop_h4 import _login, _push
from tests.test_team_log_desktop import team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_pull import _entry_payload
from tests.test_team_log_migration import _approved, _as, _yes
from tests.test_team_log_desktop_changes import _ops


def _bob_wrote_then_lowered(team, server, tmp_path, monkeypatch):  # noqa: F811
    """Bob writes into Ops with a write grant (no log yet); the admin's grant
    then says read, as after re-sharing it at read."""
    url, _ = server
    db, admin, admin_client, bob, _bob_client = team
    carol = _approved(url, admin_client, tmp_path / "carol", "carol", monkeypatch)
    ops = _ops(admin)
    ids = {name: v.db.get_meta("user_id") for name, v in (("bob", bob), ("carol", carol))}
    revocation.grant_member(admin, admin_client, ids["bob"], ops, "write", confirm_fingerprint=_yes)
    revocation.grant_member(admin, admin_client, ids["carol"], ops, "read", confirm_fingerprint=_yes)
    sk = bob.keypair.to_nacl_signing_key()
    entry = new_ulid()
    _push(url, _login(url, sk, "bob"), sk, entry, "entry", ops, _entry_payload(admin.dek_mgr.get_dek_for_node(ops)[0]))
    admin_client.pull()
    assert admin.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (entry,))  # the old rules took it
    admin.db.execute(
        "UPDATE access_envelopes SET access_level = 'read' WHERE user_id = ? AND created_by = ?",
        (ids["bob"], admin.db.get_meta("user_id")),
    )
    return admin, admin_client, carol, ids, ops, entry


def _carol_has(carol, admin, url, entry) -> bool:
    """A member's first pull after founding: what every client now shows."""
    from tests.test_integration_client_server import _client

    carol.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {admin.db.get_meta("user_id"): admin.keypair.fingerprint})
    _client(carol, url).pull()
    return carol.db.fetchone("SELECT 1 FROM entries WHERE id = ? AND is_deleted = 0", (entry,)) is not None


def test_founding_hides_the_item_of_a_member_left_at_read(team, server, tmp_path, monkeypatch):  # noqa: F811
    url, _ = server
    admin, admin_client, carol, ids, ops, entry = _bob_wrote_then_lowered(team, server, tmp_path, monkeypatch)
    result = found_team_log(admin, admin_client, lambda uid, fp: True)
    assert not _carol_has(carol, admin, url, entry)  # the reproduction: hidden after founding
    # 8595ec1: nothing named it; now the result (and the plan before it) does.
    assert [(h.item, h.author, h.folder, h.reason) for h in result.hidden] == [(entry, ids["bob"], ops, "read")]

    # The way out the warning names: write access in the log brings it back.
    revocation.grant_member(admin, admin_client, ids["bob"], ops, "write")
    assert admin_client.team_state().access[ops][ids["bob"]] == "write"
    assert _carol_has(carol, admin, url, entry)
    carol.lock()


def test_declining_the_plan_signs_nothing(team, server, tmp_path, monkeypatch):  # noqa: F811
    admin, admin_client, carol, ids, ops, entry = _bob_wrote_then_lowered(team, server, tmp_path, monkeypatch)
    seen = []
    with pytest.raises(RuntimeError, match="nothing was signed"):
        found_team_log(admin, admin_client, lambda uid, fp: True, confirm_plan=lambda plan: seen.append(plan) or False)
    assert admin_client.team_state() is None
    assert [(h.item, h.reason) for h in seen[0].hidden] == [(entry, "read")]
    carol.lock()


def test_an_unconfirmed_author_is_named_too(team, server, tmp_path, monkeypatch):  # noqa: F811
    admin, admin_client, carol, ids, ops, entry = _bob_wrote_then_lowered(team, server, tmp_path, monkeypatch)
    confirmed = admin.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META)
    del confirmed[ids["bob"]]  # another device of the admin, which never confirmed Bob
    admin.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, confirmed)
    seen = []
    with pytest.raises(RuntimeError, match="nothing was signed"):
        found_team_log(admin, admin_client, lambda uid, fp: False, confirm_plan=lambda plan: seen.append(plan) or False)
    assert [(h.item, h.author, h.reason) for h in seen[0].hidden] == [(entry, ids["bob"], "unconfirmed")]
    carol.lock()


def test_cli_init_warns_before_signing(team, server, tmp_path, monkeypatch):  # noqa: F811
    admin, admin_client, carol, ids, ops, entry = _bob_wrote_then_lowered(team, server, tmp_path, monkeypatch)
    _as(admin, monkeypatch)
    out = CliRunner().invoke(cli.main, ["team-log", "init"], input="n\n")
    assert out.exit_code != 0 and "nothing was signed" in out.output
    assert "1 item(s) written before the log would be hidden" in out.output
    assert f"entry {entry} by {ids['bob']} in {ops}: only read access" in out.output
    assert "grant-access USER_ID FOLDER --write" in out.output

    out = CliRunner().invoke(cli.main, ["team-log", "init"], input="y\n")
    assert out.exit_code == 0, out.output
    assert "1 item(s) hidden" in out.output  # repeated after signing
    carol.lock()

