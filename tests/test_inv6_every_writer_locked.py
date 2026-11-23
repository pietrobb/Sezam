"""INV-6 structurally (docs/ROOT_CAUSE_PLAN.md, R15-P5, review e443cbc).

Only four outbox kinds (outbox.LOCKED: key_change, rekey, revoke,
org_recovery) and the pending-state keys checked the vault lock where they
were written (they still require it held across their whole operation). Every other outbox row (a queued write, an envelope, an audit
record, a team change, a team grant, a reseed, a bootstrap, a withdrawal) and
every other vault_meta key was written by whatever process came, while a push
in another process read, sent and cleared the same rows. flush_team_log and
append_team_log read the team change queue, sent it and rewrote it without
the lock.

Now the database orders it: every write statement and transaction of a
VaultDB takes the vault lock before its connection guard, and the outbox and
vault_meta refuse a write (also one through the raw connection) from a thread
that does not hold it. The only exception is the AI kill switch
(VaultDB.brake): stopping an agent never waits for a sync.

The inventories below fail on a new writer that bypasses VaultDB and on a
lock site that is moved or removed without updating them (section 5).
"""

from __future__ import annotations

import ast
import pathlib
import sqlite3

import pytest

from sezam.vault import ai_access, oplock, outbox
from sezam.vault.crud import Vault
from tests.test_ai_p3_session_limits import FAST_PARAMS
from tests.test_review6_vault_oplock import _hold_in_another_process

PASSWORD = "inv6-master-password"
SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "sezam"

KINDS = sorted(
    value for name, value in vars(outbox).items()
    if name.isupper() and isinstance(value, str) and value
    and name not in {"QUEUED", "REFUSED", "HELD", "ONE", "REVIVED_BODY"}
)


@pytest.fixture
def vault(tmp_path):
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    yield vault
    vault.lock()


def _outbox(vault):
    return [tuple(r) for r in vault.db.fetchall("SELECT kind, object_id, body, state FROM outbox ORDER BY seq")]


def _meta(vault):
    return {r["key"]: r["value"] for r in vault.db.fetchall("SELECT key, value FROM vault_meta")}


def test_the_outbox_kinds_are_the_ones_this_test_knows():
    assert KINDS == sorted([
        "write", "envelope", "audit", "key_change", "rekey", "revoke", "org_recovery",
        "reseed", "bootstrap", "team_change", "team_grant", "withdrawal",
    ])


@pytest.mark.parametrize("kind", KINDS)
def test_a_raw_outbox_write_of_any_kind_without_the_lock_is_refused(vault, kind):
    before = _outbox(vault)
    conn = vault.db.conn
    with pytest.raises(sqlite3.DatabaseError, match="INV-6"):
        conn.execute("INSERT INTO outbox (kind, object_id) VALUES (?, 'x')", (kind,))
    assert _outbox(vault) == before
    with oplock.exclusive(vault.db.path):
        conn.execute("INSERT INTO outbox (kind, object_id) VALUES (?, 'x')", (kind,))
    with pytest.raises(sqlite3.DatabaseError, match="INV-6"):
        conn.execute("UPDATE outbox SET state = 'held' WHERE kind = ?", (kind,))
    with pytest.raises(sqlite3.DatabaseError, match="INV-6"):
        conn.execute("DELETE FROM outbox WHERE kind = ?", (kind,))
    assert (kind, "x", None, "queued") in _outbox(vault)


@pytest.mark.parametrize("sql", [
    "INSERT INTO vault_meta (key, value) VALUES ('inv6_probe', '1')",
    "UPDATE vault_meta SET value = 'x' WHERE key = 'schema_version'",
    "DELETE FROM vault_meta WHERE key = 'schema_version'",
    f"UPDATE vault_meta SET value = '1' WHERE key = '{ai_access.ENABLED_KEY}'",
])
def test_a_raw_vault_meta_write_without_the_lock_is_refused(vault, sql):
    before = _meta(vault)
    with pytest.raises(sqlite3.DatabaseError, match="INV-6"):
        vault.db.conn.execute(sql)
    assert _meta(vault) == before


def _transaction(vault):
    with vault.db.transaction():
        pass


WRITERS = {
    "a new folder (outbox write + audit)": lambda v: v.create_node("inv6 folder"),
    "an audit record": lambda v: v._audit_log("read", b'{"target": "x"}'),
    "a vault_meta key": lambda v: v.db.set_meta("server_url", "https://other.example"),
    "a vault_meta json key": lambda v: v.db.set_meta_json("inv6_probe", [1]),
    "a transaction": _transaction,
    "a queued team change": lambda v: outbox.put(v.db, outbox.TEAM_CHANGE, [["member.add", {}]], "1"),
    "a queued write": lambda v: outbox.queue_write(v.db, "01HZZZZZZZZZZZZZZZZZZZZZZZ"),
    "a dropped write": lambda v: outbox.drop_all_writes(v.db),
    "a withdrawal": lambda v: outbox.put(v.db, outbox.WITHDRAWAL, {}, "w", outbox.HELD),
}


@pytest.mark.parametrize("what", sorted(WRITERS))
def test_a_write_waits_for_another_process_holding_the_lock(vault, monkeypatch, what):
    """Red on e443cbc: each of them was written while another process held
    the lock (a push between reading the outbox and clearing what it sent)."""
    before = (_outbox(vault), _meta(vault))
    monkeypatch.setattr(oplock, "DEFAULT_TIMEOUT", 0.3)
    proc = _hold_in_another_process(vault.db.path, 3.0)
    try:
        with pytest.raises(oplock.VaultBusy):
            WRITERS[what](vault)
        assert (_outbox(vault), _meta(vault)) == before
    finally:
        proc.wait(10)


def test_the_brake_keys_are_the_kill_switch():
    from sezam.vault.db import BRAKE_KEYS

    assert BRAKE_KEYS == {
        ai_access.ENABLED_KEY, ai_access.EPOCH_KEY, ai_access.STATE_MAC_KEY, ai_access.PENDING_AUDIT_KEY,
    }


def test_the_ai_brake_never_waits_for_a_sync(vault, monkeypatch):
    """The exception: 'sezam ai off' while another process syncs stops the
    agent at once; its audit record waits for the next unlock."""
    ai_access.enable(vault, "test")
    monkeypatch.setattr(oplock, "DEFAULT_TIMEOUT", 0.3)
    proc = _hold_in_another_process(vault.db.path, 3.0)
    try:
        state = ai_access.disable(vault, "test")
        assert not state.enabled
        assert not ai_access.read_state(vault).enabled
        assert vault.db.get_meta_json(ai_access.PENDING_AUDIT_KEY)
        with vault.db.brake():  # nothing but the switch itself
            with pytest.raises(sqlite3.DatabaseError, match="INV-6"):
                vault.db.set_meta("server_url", "https://other.example")
    finally:
        proc.wait(10)


def test_an_ai_off_queued_during_the_unlock_flush_is_kept(vault, tmp_path, monkeypatch):
    """Capability review run 470: the brake appends to the audit queue
    without the vault lock, and the unlock flush read the queue, wrote the
    records and deleted the key in separate steps. A 'sezam ai off' from
    another process in between was deleted unwritten."""
    other = Vault(tmp_path)  # another process, vault locked
    ai_access.enable(vault, "test")
    ai_access.disable(other, "first")
    assert [r["detail"]["source"] for r in vault.db.get_meta_json(ai_access.PENDING_AUDIT_KEY)] == ["first"]
    original = ai_access._write_audit
    calls = []

    def write_audit(v, action, detail):
        if v is other:  # the second process's own attempt (its vault is locked)
            return original(v, action, detail)
        if not calls:
            calls.append(detail["source"])
            ai_access.disable(other, "probe")
        else:
            calls.append(detail["source"])
        return original(v, action, detail)

    monkeypatch.setattr(ai_access, "_write_audit", write_audit)
    ai_access.flush_pending_audit(vault)
    monkeypatch.setattr(ai_access, "_write_audit", original)
    assert calls == ["first"]
    # kept for the next flush, not deleted unwritten
    assert [r["detail"]["source"] for r in ai_access._pending(vault.db)] == ["probe"]
    ai_access.flush_pending_audit(vault)
    assert ai_access._pending(vault.db) == []
    assert vault.db.fetchone("SELECT COUNT(*) FROM audit_log WHERE action = 'ai_off'")[0] == 2


BRAKE_KEY_NAMES = {"ENABLED_KEY", "EPOCH_KEY", "STATE_MAC_KEY", "PENDING_AUDIT_KEY"}
BRAKE_READS = {"get_meta", "get_meta_json", "_pending", "_verified", "_state_mac", "_state_verified", "_parse"}
BRAKE_WRITES = {"set_meta", "set_meta_json", "execute"}
# Functions that read and rewrite a brake key outside their own immediate
# transaction, with why no brake can land in between.
BRAKE_REWRITES_ELSEWHERE = {
    "seal_new_vault": "a vault being created or imported; nothing else has it open",
    "rewrap_macs": "inside the KEK change's transaction, which already holds the write lock "
                   "(rewrap_all_deks writes the DEKs first)",
    "_seal_home": "called only inside the immediate transaction of anchor_home / rehome_anchor "
                  "(R16-H3: a verified 'on' is sealed again next to its new home)",
}


def _immediate_transaction(item: ast.withitem) -> bool:
    call = item.context_expr
    return isinstance(call, ast.Call) and _dotted(call.func).endswith(".transaction") and any(
        k.arg == "immediate" and isinstance(k.value, ast.Constant) and k.value.value is True
        for k in call.keywords
    )


def test_a_brake_key_is_read_and_rewritten_in_one_immediate_transaction():
    """Capability review run 470: the brake writes these keys without the
    vault lock, so the lock does not order a read-then-rewrite of them; only
    SQLite's write lock does, which the brake's own transaction also takes."""
    tree = ast.parse((SRC / "vault" / "ai_access.py").read_text(encoding="utf-8"))
    loose = {}
    for func in (n for n in tree.body if isinstance(n, ast.FunctionDef)):
        def walk(node, guarded, out):
            if isinstance(node, ast.With) and any(_immediate_transaction(i) for i in node.items):
                guarded = True
            if isinstance(node, ast.Call):
                name = _dotted(node.func).rsplit(".", 1)[-1]
                keyed = any(isinstance(a, ast.Name) and a.id in BRAKE_KEY_NAMES
                            for arg in node.args for a in ast.walk(arg))
                if name in BRAKE_READS:
                    out["read"] = True
                if name in BRAKE_WRITES and keyed and not guarded:
                    out["loose"].append(node.lineno)
            for child in ast.iter_child_nodes(node):
                walk(child, guarded, out)

        out = {"read": False, "loose": []}
        walk(func, False, out)
        if out["read"] and out["loose"]:
            loose[func.name] = out["loose"]
    assert set(loose) == set(BRAKE_REWRITES_ELSEWHERE), loose


def test_flushing_and_appending_team_changes_hold_the_lock(vault, monkeypatch):
    """Red on e443cbc: both read the team change queue, sent it and rewrote
    it without the lock."""
    from sezam.vault.sync_client import SyncClient

    client = SyncClient(vault.db, "http://127.0.0.1:9", None, "nobody")
    seen = []

    def pending(self):
        seen.append(oplock.held_here(vault.db.path))
        return []

    monkeypatch.setattr(SyncClient, "pending_team_changes", pending)
    monkeypatch.setattr(SyncClient, "set_aside_team_changes", lambda self: seen.append(
        oplock.held_here(vault.db.path)) or [])
    monkeypatch.setattr(SyncClient, "queue_team_changes", lambda self, changes: None)
    monkeypatch.setattr(SyncClient, "team_state", lambda self: None)
    client.flush_team_log()
    client.append_team_log([("member.add", {})])
    assert seen and all(seen)


# -- inventories -------------------------------------------------------------

def _sites(predicate):
    """(module, qualified function, what) for every function in src/sezam."""
    found = set()
    for path in sorted(SRC.rglob("*.py")):
        module = path.relative_to(SRC.parent).as_posix()
        stack = [(ast.parse(path.read_text(encoding="utf-8")), "")]
        while stack:
            node, scope = stack.pop()
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    name = f"{scope}.{child.name}" if scope else child.name
                    if not isinstance(child, ast.ClassDef):
                        found |= {(module, name, what) for what in predicate(child)}
                    stack.append((child, name))
                else:
                    stack.append((child, scope))
    return found


def _dotted(node) -> str:
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _dotted(node.func) + "()"
    return "?"


def _own_calls(fn):
    """Calls in ``fn``'s own body, not in functions nested in it."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Call):
            yield node
        stack.extend(ast.iter_child_nodes(node))


def _lock_sites(fn):
    sites = [f"@{_dotted(d)}" for d in fn.decorator_list if _dotted(d) in ("oplock.held", "oplock.writes")]
    sites += sorted({
        _dotted(call.func) for call in _own_calls(fn)
        if _dotted(call.func) in {"oplock.exclusive", "oplock.require", "oplock.network"}
    })
    return sites


def _raw_connections(fn):
    found = set()
    for call in _own_calls(fn):
        name = _dotted(call.func)
        if name == "sqlite3.connect" or (
            name.split(".")[-2:-1] in (["conn"], ["_conn"])
            and name.rsplit(".", 1)[-1] in {"execute", "executemany", "executescript"}
        ):
            found.add(name)
    return sorted(found)


# Every place that holds or checks the vault lock. Moving or removing one
# needs its reason and a test in the commit (ROOT_CAUSE_PLAN section 5).
LOCK_SITES = {
    ("sezam/cli.py", "abandon_rekey", "oplock.exclusive"),
    ("sezam/vault/ai_access.py", "anchor_home", "oplock.exclusive"),
    ("sezam/vault/ai_access.py", "name_server", "oplock.exclusive"),
    ("sezam/vault/ai_access.py", "raise_floor", "oplock.exclusive"),
    ("sezam/vault/ai_access.py", "rehome_anchor", "oplock.exclusive"),
    ("sezam/vault/crud.py", "Vault.adopt_account_kek", "@oplock.held"),
    ("sezam/vault/crud.py", "Vault.change_password", "@oplock.held"),
    ("sezam/vault/crud.py", "Vault.grant_folder_access", "@oplock.held"),
    ("sezam/vault/crud.py", "Vault.move_entry", "@oplock.writes"),  # R16-M1
    ("sezam/vault/crud.py", "Vault.move_node", "@oplock.writes"),  # R16-M1
    ("sezam/vault/crud.py", "Vault.org_recovery", "@oplock.held"),
    ("sezam/vault/crud.py", "Vault.rename_node", "@oplock.writes"),  # R16-M1
    ("sezam/vault/crud.py", "Vault.rekey_after_handover", "@oplock.held"),
    ("sezam/vault/crud.py", "Vault.rekey_after_revocation", "@oplock.held"),
    ("sezam/vault/crud.py", "Vault.setup_org_recovery", "@oplock.held"),
    ("sezam/vault/crud.py", "Vault.update_entry", "@oplock.writes"),  # R16-M1
    ("sezam/vault/db.py", "VaultDB._ordered", "oplock.exclusive"),
    ("sezam/vault/db.py", "VaultDB._settle_transaction", "oplock.exclusive"),
    ("sezam/vault/db.py", "VaultDB._upgrade_sync_columns", "oplock.exclusive"),
    ("sezam/vault/org_recovery_server.py", "setup_and_register", "oplock.exclusive"),
    ("sezam/vault/org_recovery_server.py", "withhold_superseded_setup", "oplock.exclusive"),
    ("sezam/vault/outbox.py", "_write", "oplock.require"),
    ("sezam/vault/pending_states.py", "set_last_pushed_key_epoch", "oplock.require"),
    ("sezam/vault/pre_proof_change.py", "finish_pending_change", "@oplock.held"),
    ("sezam/vault/rekey_abandon.py", "abandon_pending_rekey", "@oplock.held"),
    ("sezam/vault/reseed.py", "rejoin_server", "@oplock.held"),
    ("sezam/vault/reseed.py", "reseed_server", "@oplock.held"),
    ("sezam/vault/revocation.py", "finish_handover_rekeys", "@oplock.held"),
    ("sezam/vault/revocation.py", "finish_queued_into", "@oplock.held"),
    ("sezam/vault/revocation.py", "finish_queued_revocations", "@oplock.held"),
    ("sezam/vault/revocation.py", "grant_member", "@oplock.held"),
    ("sezam/vault/revocation.py", "push_with_queued_revocations", "@oplock.held"),
    ("sezam/vault/revocation.py", "queue_revoked_holders", "@oplock.held"),
    ("sezam/vault/revocation.py", "revoke_member", "@oplock.held"),
    ("sezam/vault/sync_client.py", "SyncClient.abandon_pending_change", "@oplock.held"),
    ("sezam/vault/sync_client.py", "SyncClient.adopt_rotated_key_material", "@oplock.held"),
    ("sezam/vault/sync_client.py", "SyncClient.finish_pending_change", "@oplock.held"),
    ("sezam/vault/sync_client.py", "SyncClient.register_org_recovery", "oplock.exclusive"),
    # R16-M3: the one place a sync holder gives the write lock up (a request).
    ("sezam/vault/sync_client.py", "SyncClient._request", "oplock.network"),
    ("sezam/vault/sync_pull.py", "PullMixin.pull", "@oplock.held"),
    ("sezam/vault/sync_push.py", "PushMixin.push", "@oplock.held"),
    ("sezam/vault/sync_rekey.py", "RekeyMixin.close_rekey_if_landed", "@oplock.held"),
    ("sezam/vault/sync_resync.py", "ResyncMixin.full_resync", "@oplock.held"),
    # caed6b9 (R14-M1): the push before it, the envelopes and the role records
    # under one hold; test_review14_handover_m1.py.
    ("sezam/vault/team_migration.py", "hand_over_admin", "@oplock.held"),
    ("sezam/vault/team_log_local.py", "TeamLogMixin.append_team_log", "@oplock.held"),
    ("sezam/vault/team_log_local.py", "TeamLogMixin.flush_team_log", "@oplock.held"),
    ("sezam/vault/team_log_local.py", "TeamLogMixin.queue_team_changes", "@oplock.held"),
    ("sezam/vault/trash.py", "restore_entry", "@oplock.writes"),  # R16-M1
    ("sezam/vault/trash.py", "restore_node", "@oplock.writes"),  # R16-M1
}

# Every call on a connection that is not VaultDB.execute/executemany (which
# take the lock themselves), with why it may. ``?``: any function of the module.
RAW_CONNECTIONS = {
    ("sezam/vault/db.py", "VaultDB.open", "sqlite3.connect"): "the connection VaultDB wraps",
    ("sezam/vault/db.py", "VaultDB.open", "self._conn.execute"): "pragmas; the upgrade runs under oplock.exclusive",
    ("sezam/vault/db.py", "VaultDB.open", "self._conn.executescript"): "CREATE ... IF NOT EXISTS of tables and triggers",
    ("sezam/vault/db.py", "VaultDB._check_schema", "self._conn.execute"): "a read",
    ("sezam/vault/db.py", "VaultDB._guard_writes", "self._conn.execute"): "a read",
    ("sezam/vault/db.py", "VaultDB._guard_writes", "self._conn.executescript"): "the INV-6 TEMP triggers themselves",
    ("sezam/vault/db.py", "VaultDB.create_schema", "self.conn.executescript"): "a new file's tables; their rows go through set_meta",
    ("sezam/vault/db.py", "VaultDB.execute", "self.conn.execute"): "the ordered statement",
    ("sezam/vault/db.py", "VaultDB.executemany", "self.conn.executemany"): "the ordered statement",
    ("sezam/vault/db.py", "VaultDB.fetchone", "self.conn.execute"): "a read",
    ("sezam/vault/db.py", "VaultDB.fetchall", "self.conn.execute"): "a read",
    ("sezam/vault/db.py", "VaultDB.backup", "sqlite3.connect"): "a copy, not the vault",
    ("sezam/vault/db.py", "VaultDB._upgrade_sync_columns", "?"): "called by VaultDB.open under oplock.exclusive",
    ("sezam/vault/db.py", "VaultDB._upgrade_sync_columns.columns", "conn.execute"): "a read",
    ("sezam/vault/db.py", "VaultDB._upgrade_sync_columns.has_table", "conn.execute"): "a read",
    ("sezam/vault/db.py", "VaultDB._upgrade_sync_columns.meta", "conn.execute"): "a read",
    ("sezam/vault/db.py", "_has_pending_meta", "conn.execute"): "a read",
    ("sezam/vault/db.py", "_move_pending_meta", "?"): "inside _upgrade_sync_columns",
    ("sezam/vault/ai_access.py", "off_in_copy", "conn.execute"): "a copy (snapshot, backup), not the vault",
    ("sezam/vault/search.py", "?", "?"): "the in-memory search index",
    ("sezam/vault/snapshots.py", "?", "?"): "copies; a restore holds the vault exclusively (InUseLock)",
}


def _known(site, recorded):
    return any(
        site[0] == r[0] and r[1] in ("?", site[1]) and r[2] in ("?", site[2]) for r in recorded
    )


def test_every_lock_site_is_recorded():
    found = _sites(_lock_sites)
    assert found - LOCK_SITES == set(), "a new lock site: record it in LOCK_SITES"
    assert LOCK_SITES - found == set(), (
        "a lock site was moved or removed: its reason and test go in the commit (section 5)"
    )


def test_no_new_connection_bypasses_vaultdb():
    found = _sites(_raw_connections)
    assert {site for site in found if not _known(site, RAW_CONNECTIONS)} == set(), (
        "a new writer bypasses VaultDB and its lock (INV-6): go through VaultDB, "
        "or record it in RAW_CONNECTIONS with why it may"
    )
