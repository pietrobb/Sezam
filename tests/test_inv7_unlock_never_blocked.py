"""INV-7 (docs/ROOT_CAUSE_PLAN.md, capability run 397): a team log this device
refuses never keeps the vault locked. It blocks team operations only, and each
cause names a way out that runs on the unlocked vault.

On b8c74ed the desktop checked the team log inside the unlock and locked the
vault again on any error: a copy that no longer replays (a bare TeamLogError),
one whose stored hashes do not match, or account keys naming another genesis
than the one this device holds (anchor_conflict) kept every personal secret
out of reach, and 'sezam team-log forget-pin' / 'status' failed at the unlock.

Each state here is a real desktop vault holding the team's log (pinned and
confirmed, the account keys anchored to it) and a personal entry, then:

* holds_damaged_sig / holds_damaged_hash: the copy's last record no longer
  verifies, or its stored hash is not the record's. Way out: the next pull
  fetches the log again, held to the pins the copy names (its genesis, the
  head seen: at that seq the server's record is the stored hash or the stored
  record): the same log is followed, one behind or forked is still refused.
* anchor_names_other: the account keys name another genesis than the log this
  device holds. The device cannot tell which is the team's; a server serving
  an old account bundle produces it, so forgetting is offered as a risk
  (INV-8), and typing both pinned genesis hashes leaves both.
"""

from __future__ import annotations

import pytest

from sezam import teamlog as tl
from sezam.crypto import aead
from sezam.models import ulid_to_bytes
from sezam.vault.team_log_forget import forget_team_log_pin
from sezam.vault.team_log_local import (
    CONFIRMED_GENESIS_META, FORGOTTEN_GENESIS_META, GENESIS_META, RISK_MARKER, TeamLogMismatch, TeamLogMixin,
    forgotten_genesis, local_team_state,
)
from tests.team_log_mismatch_vectors import _servers
from tests.test_integration_client_server import PASSWORD, _vault

SERVERS = _servers()
TEAM, TEAM_HEAD = SERVERS["same"]
OTHER_GENESIS = SERVERS["another_genesis"][1]["genesis_hash"]
# Capability run 418: damage to the first record (the genesis) read as
# anchor_conflict: the held genesis was the damaged record's own hash.
DAMAGED = ("holds_damaged_sig", "holds_damaged_hash", "holds_damaged_genesis_sig", "holds_damaged_genesis_hash")
STATES = (*DAMAGED, "anchor_names_other")
CAUSE = {**{state: "local_damaged" for state in DAMAGED}, "anchor_names_other": "anchor_conflict"}


def _seq(record: dict) -> int:
    return tl.parse_body(record["body"])["seq"]


class _Server(TeamLogMixin):
    """The desktop's team log follower over the vault's database; the server
    serves ``served`` and refuses every restore (a restore that lands is INV-2)."""

    def __init__(self, vault, served: str):
        self._db = vault.db
        self._served, self._head = SERVERS[served]
        self._token = "session"

    def _request(self, method, path, body=None, auth=False):
        assert method == "GET" and path.startswith("/api/team-log?since="), path
        since = int(path.split("since=", 1)[1])
        return {"records": [r for r in self._served if _seq(r) > since], "head": self._head}

    def _restore_server_team_log(self, local, server_head):
        return False


def _wrap_keys(vault, genesis: str) -> None:
    """Store the account keys naming ``genesis`` (as a bundle from another device would)."""
    keys = vault.keypair
    held = keys.confirmed_genesis
    keys.confirmed_genesis = genesis
    try:
        data = keys.serialize_private()
    finally:
        keys.confirmed_genesis = held
    wrapped = aead.encrypt_keypair_wrap(
        keypair_data=data, kek=vault.dek_mgr._kek,
        kek_dek_id=ulid_to_bytes(vault.dek_mgr._wrapping_kek_id()),
        user_object_id=ulid_to_bytes(vault.db.get_meta("user_id")),
    )
    vault.db.set_meta("encrypted_keypair", wrapped.hex())


def _device(tmp_path, state: str, forgotten: str | None = None):
    vault = _vault(tmp_path / "v", "owner")
    entry = vault.create_entry(vault.db.get_meta("root_node_id"), "private", [{"key": "password", "value": "keep-me"}])
    vault.create_personal_folder("mine")
    vault.db.set_meta("server_url", "http://team.invalid")  # capability run 406: a real device is connected
    genesis = TEAM_HEAD["genesis_hash"]
    with vault.db.transaction(immediate=True):
        _Server(vault, "same")._store_team_log(TEAM, tl.replay(TEAM))
        vault.db.set_meta(CONFIRMED_GENESIS_META, genesis)
        _wrap_keys(vault, genesis)
    vault.lock()
    vault.unlock(PASSWORD)  # the team's log, held and anchored: opens
    assert vault.keypair.confirmed_genesis == genesis
    assert local_team_state(vault.db).head_hash == TEAM_HEAD["hash"]
    with vault.db.transaction(immediate=True):
        if state == "holds_damaged_sig":
            vault.db.execute("UPDATE team_log SET sig = ? WHERE seq = 2", ("00" * 64,))
        elif state == "holds_damaged_hash":
            vault.db.execute("UPDATE team_log SET hash = ? WHERE seq = 2", ("00" * 32,))
        elif state == "holds_damaged_genesis_sig":
            vault.db.execute("UPDATE team_log SET sig = ? WHERE seq = 0", ("00" * 64,))
        elif state == "holds_damaged_genesis_hash":
            vault.db.execute("UPDATE team_log SET hash = ? WHERE seq = 0", ("00" * 32,))
        elif state == "anchor_names_other":
            _wrap_keys(vault, OTHER_GENESIS)
        if forgotten is not None:
            vault.db.set_meta(FORGOTTEN_GENESIS_META, forgotten)
    vault.lock()
    return vault, entry


@pytest.mark.parametrize("state", STATES)
def test_the_vault_opens_and_only_the_team_waits(tmp_path, state):
    vault, entry = _device(tmp_path, state)
    vault.unlock(PASSWORD)
    assert vault.get_field_value(entry, "password") == "keep-me"
    mine = vault.db.fetchone("SELECT id FROM nodes WHERE parent_id IS NULL AND id != ?",
                             (vault.db.get_meta("root_node_id"),))["id"]
    written = vault.create_entry(mine, "written", [{"key": "password", "value": "new"}])
    assert vault.get_field_value(written, "password") == "new"
    refusal = _Server(vault, "same").team_log_refusal()
    if state == "anchor_names_other":
        assert refusal is not None and refusal.cause == "anchor_conflict"
        assert refusal.offers_forget and RISK_MARKER in str(refusal) and "forget-pin" in str(refusal)
    else:
        assert refusal is None  # fetched again under its pins: the team's log
    vault.lock()
    vault.unlock(PASSWORD)
    assert vault.get_field_value(entry, "password") == "keep-me"


def _personal_mutations(vault) -> dict:
    """Every personal write the vault offers, each run on its own (capability
    run 403: one sampled create left a move and a tier-2 create blocked)."""
    mine = _mine(vault)
    held = {}

    def folder(name):
        return vault.create_node(name, parent_id=mine)

    def entry(tier=None):
        node = held.setdefault("a", folder("a"))
        return vault.create_entry(node, "e", [{"key": "password", "value": "v"}], tier=tier)

    def other():
        return held.setdefault("b", folder("b"))

    return {
        "create_node": lambda: folder("made"),
        "create_entry_tier1": lambda: entry(),
        "create_entry_tier2": lambda: entry(tier=2),
        "update_entry": lambda: vault.update_entry(entry(), fields=[{"key": "password", "value": "w"}]),
        "update_entry_to_tier2": lambda: vault.update_entry(entry(), tier=2),
        "rename_node": lambda: vault.rename_node(folder("old"), "new"),
        "move_entry_tier1": lambda: vault.move_entry(entry(), other()),
        "move_entry_tier2": lambda: vault.move_entry(entry(tier=2), other()),
        "move_node": lambda: vault.move_node(vault.create_node("c", parent_id=folder("p")), other()),
        "move_node_holding_tier2": lambda: (
            lambda c: (vault.create_entry(c, "t2", [{"key": "k", "value": "v"}], tier=2),
                       vault.move_node(c, other()))
        )(vault.create_node("c2", parent_id=folder("p2"))),
        "delete_entry": lambda: vault.delete_entry(entry()),
        "delete_node": lambda: vault.delete_node(folder("gone")),
    }


@pytest.mark.parametrize("state", STATES)
def test_every_personal_write_goes_on_while_the_team_waits(tmp_path, state):
    vault, org_entry = _device(tmp_path, state)
    vault.unlock(PASSWORD)
    refused = {}
    for name, op in _personal_mutations(vault).items():
        try:
            op()
        except Exception as exc:  # noqa: BLE001 - every refusal is the finding
            refused[name] = f"{type(exc).__name__}: {getattr(exc, 'cause', '')} {exc}"[:160]
    with pytest.raises(TeamLogMismatch) as still:
        local_team_state(vault.db)  # nothing above fetched the log again: still refused
    assert still.value.cause == CAUSE[state]
    assert refused == {}, sorted(refused)
    root = vault.db.get_meta("root_node_id")  # the organisation's tree still waits
    with pytest.raises(TeamLogMismatch):
        vault.create_entry(root, "team", [{"key": "password", "value": "v"}], tier=2)
    with pytest.raises(TeamLogMismatch):
        vault.move_entry(org_entry, _mine(vault))


WAY_OUT = {"local_damaged": "'sezam pull'", "anchor_conflict": "'sezam team-log forget-pin"}


@pytest.mark.parametrize("state", STATES)
def test_status_names_the_refusal_and_its_way_out(tmp_path, state, monkeypatch):
    """Capability run 406: a connected device ran local_team_state in
    pending_states unguarded, so 'sezam status' ended on the refusal."""
    from click.testing import CliRunner

    from sezam import cli
    from sezam.vault.pending_states import pending_states
    from tests.test_ai_r1_snapshots import _cli_env

    vault, _ = _device(tmp_path, state)
    vault.unlock(PASSWORD)
    states = {s.key: s for s in pending_states(vault)}
    vault.lock()
    refused = states.get("team_log_refused")
    assert refused is not None, sorted(states)
    assert WAY_OUT[CAUSE[state]] in refused.resolve
    assert (RISK_MARKER in refused.resolve) == (CAUSE[state] == "anchor_conflict")
    assert "lone_admin_without_recovery" not in states  # decided from a log this device refuses
    _cli_env(tmp_path / "v", monkeypatch)
    out = CliRunner().invoke(cli.main, ["status"], input=PASSWORD + "\n")
    assert out.exit_code == 0, out.output
    assert WAY_OUT[CAUSE[state]] in out.output


@pytest.mark.parametrize("state", STATES)
def test_a_pending_recovery_reset_names_the_refusal_first(tmp_path, state, monkeypatch):
    """Capability run 407: the way out of an org-recovery reset the server
    refuses read the log on its own, unguarded, so with such a reset pending
    'status' (and the refused-change messages) still ended on the refusal."""
    from click.testing import CliRunner

    from sezam import cli
    from sezam.vault.pending_states import key_reset_way_out, pending_states, set_key_change_journal
    from tests.test_ai_r1_snapshots import _cli_env

    vault, _ = _device(tmp_path, state)
    vault.unlock(PASSWORD)
    from sezam.vault import oplock

    with oplock.exclusive(vault.db.path):  # INV-6
        set_key_change_journal(vault.db, {"recovery_secret": "x"})
    assert vault.key_change_unpushed()
    states = {s.key: s for s in pending_states(vault)}
    way_out = key_reset_way_out(vault.db, vault.db.get_meta("user_id"))
    vault.lock()
    assert {"key_change", "team_log_refused"} <= set(states), sorted(states)
    for text in (states["key_change"].drop, way_out):  # what cli.py prints on a refused change
        assert WAY_OUT[CAUSE[state]] in text, text
        assert (RISK_MARKER in text) == (CAUSE[state] == "anchor_conflict"), text
        assert "allow-key-reset" not in text, text  # who may allow it is decided from the log
    _cli_env(tmp_path / "v", monkeypatch)
    out = CliRunner().invoke(cli.main, ["status"], input=PASSWORD + "\n")
    assert out.exit_code == 0, out.output
    assert "org recovery has not reached" in out.output and WAY_OUT[CAUSE[state]] in out.output


def test_status_on_keys_naming_another_log_before_this_device_holds_one(tmp_path):
    """Run 406: shared_before_team_log read the log unguarded while no genesis is
    held, so a member who confirmed one founder and whose keys name another saw
    'status' end on the refusal."""
    from sezam.vault.pending_states import pending_states

    vault, _ = _device(tmp_path, "anchor_names_other")
    vault.unlock(PASSWORD)
    with vault.db.transaction(immediate=True):  # confirmed one founder, holds no log yet
        vault.db.execute("DELETE FROM team_log")
        vault.db.execute("DELETE FROM vault_meta WHERE key = ?", (GENESIS_META,))
    with pytest.raises(TeamLogMismatch):
        local_team_state(vault.db)
    keys = {s.key for s in pending_states(vault)}
    assert "team_log_refused" in keys and "shared_before_team_log" not in keys, keys


def _mine(vault) -> str:
    return vault.db.fetchone("SELECT id FROM nodes WHERE parent_id IS NULL AND id != ?",
                             (vault.db.get_meta("root_node_id"),))["id"]


@pytest.mark.parametrize("state", DAMAGED)
def test_server_keys_on_a_damaged_copy_are_taken_and_the_pull_repairs_it(tmp_path, state):
    """Capability run 418: keys from the server (password changed elsewhere,
    org recovery) naming the genesis this device pins were refused as
    anchor_conflict in rebind_server_identity, before the pull that repairs
    a damaged copy, and the risky forget-pin was the only way out offered."""
    from sezam.crypto.keys import KeyPair, generate_keypair

    vault, entry = _device(tmp_path, state)
    vault.unlock(PASSWORD)
    raw = generate_keypair().serialize_private()
    try:
        server_keys = KeyPair.from_private_only(aead.encode_account_keypair(raw, TEAM_HEAD["genesis_hash"]))
    finally:
        raw[:] = bytes(len(raw))
    vault.rebind_server_identity(vault.db.get_meta("user_id"), server_keys)
    assert vault.keypair.confirmed_genesis == TEAM_HEAD["genesis_hash"]
    with pytest.raises(TeamLogMismatch) as damaged:
        local_team_state(vault.db)
    assert damaged.value.cause == "local_damaged" and not damaged.value.offers_forget
    assert _Server(vault, "same").team_log_refusal() is None  # the pull fetches it again under its pins
    assert local_team_state(vault.db).head_hash == TEAM_HEAD["hash"]
    assert vault.db.get_meta(CONFIRMED_GENESIS_META) == TEAM_HEAD["genesis_hash"]
    vault.lock()
    vault.unlock(PASSWORD)
    assert vault.get_field_value(entry, "password") == "keep-me"
    assert local_team_state(vault.db).head_hash == TEAM_HEAD["hash"]


@pytest.mark.parametrize("state", DAMAGED)
@pytest.mark.parametrize("served", sorted(SERVERS))
def test_a_damaged_copy_is_fetched_again_under_its_pins(tmp_path, state, served):
    vault, _ = _device(tmp_path, state)
    vault.unlock(PASSWORD)
    with pytest.raises(TeamLogMismatch) as damaged:
        local_team_state(vault.db)
    assert damaged.value.cause == "local_damaged"
    refusal = _Server(vault, served).team_log_refusal()
    # The pins of the copy (its genesis, confirmed, and the head it saw) decide
    # exactly as for the intact copy: a damaged copy changes nothing else.
    holds = {"same": None, "extended": None, "none": "confirmed_genesis", "behind": "went_back",
             "forked": "differs", "another_genesis": "confirmed_genesis", "short_of_head": "short_of_head",
             "forged": "does_not_replay", "two_admins": "refused_at_head",
             # Goal #440: what the records carry decides, not the unsigned head.
             "no_head_over_the_log": "head_genesis", "no_head_over_another_genesis": "confirmed_genesis",
             "head_names_another_genesis": "head_genesis", "records_past_the_head": None}[served]
    assert (refusal.cause if refusal else None) == holds, str(refusal)
    if holds is None:  # followed up to the head the server announced
        assert local_team_state(vault.db).head_hash == SERVERS[served][1]["hash"]


@pytest.mark.parametrize("value", ["{", "42", '"' + "a" * 64 + '"', '["zz"]', '{"a": 1}', "[1]"])
def test_an_unreadable_list_of_left_logs_opens_and_names_its_way_out(tmp_path, value, monkeypatch):
    """Capability run 411: record_account_anchor read the genesis hashes this
    device left unguarded, so a damaged list failed every unlock with the
    correct password (JSONDecodeError, TypeError), and a string matched any
    genesis it contains. Now the team is refused (local_damaged) and
    'sezam team-log confirm-genesis' replaces the list."""
    from click.testing import CliRunner

    from sezam import cli
    from sezam.vault.pending_states import pending_states

    vault, entry = _device(tmp_path, "intact", forgotten=value)
    vault.unlock(PASSWORD)
    assert vault.get_field_value(entry, "password") == "keep-me"
    written = vault.create_entry(_mine(vault), "written", [{"key": "password", "value": "new"}])
    assert vault.get_field_value(written, "password") == "new"
    with pytest.raises(TeamLogMismatch) as local:
        local_team_state(vault.db)
    for refusal in (local.value, _Server(vault, "same").team_log_refusal()):
        assert refusal is not None and refusal.cause == "local_damaged" and not refusal.offers_forget
        assert "confirm-genesis" in str(refusal), str(refusal)
    assert "confirm-genesis" in {s.key: s for s in pending_states(vault)}["team_log_refused"].resolve
    vault.lock()
    vault.unlock(PASSWORD)  # still refused, never locked
    assert vault.get_field_value(entry, "password") == "keep-me"
    assert vault.db.get_meta(FORGOTTEN_GENESIS_META) == value, "nothing replaced on its own"
    vault.lock()

    monkeypatch.setattr(cli, "_open_vault", lambda: vault)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda v: v.unlock(PASSWORD))
    result = CliRunner().invoke(cli.main, ["team-log", "confirm-genesis", TEAM_HEAD["genesis_hash"]])
    assert result.exit_code == 0, result.output
    vault.unlock(PASSWORD)
    assert forgotten_genesis(vault.db) == []
    assert local_team_state(vault.db).head_hash == TEAM_HEAD["hash"]
    assert _Server(vault, "same").team_log_refusal() is None


def test_conflicting_pins_are_left_together_and_the_vault_follows_the_team_again(tmp_path):
    vault, entry = _device(tmp_path, "anchor_names_other")
    vault.unlock(PASSWORD)
    client = _Server(vault, "another_genesis")
    with pytest.raises(ValueError):
        forget_team_log_pin(vault, TEAM_HEAD["genesis_hash"][:16], client)  # one of two pins
    left = forget_team_log_pin(vault, f"{TEAM_HEAD['genesis_hash'][:16]} {OTHER_GENESIS[:16]}", client)
    assert left == {TEAM_HEAD["genesis_hash"], OTHER_GENESIS}
    assert vault.db.get_meta(GENESIS_META) is None and vault.keypair.confirmed_genesis is None
    vault.lock()
    vault.unlock(PASSWORD)
    assert vault.get_field_value(entry, "password") == "keep-me"
    assert _Server(vault, "another_genesis").team_log_refusal() is None  # a new log, its founder to confirm
