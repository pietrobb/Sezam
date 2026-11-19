"""Review 1141a20 M-AI4: an L1 agent copied the kill switch out of an automatic snapshot.

Snapshots (and encrypted backups) are copies of sezam.db made while AI access
was on: they held ai_access_enabled = 1 with a valid MAC under the same KEK.
An agent running as the owner's OS user (L1) needs no saved copy of its own:
after 'sezam ai off' it wrote the three rows of any snapshot back into the
live vault, and the next process to open it read a verified 'on'.

A copy now never carries 'on': the rows are written off and without a MAC in
the copy itself. A restore turned AI access off anyway (review a159e97), so
nothing a copy is used for needs them.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sezam.vault import ai_access
from sezam.vault.snapshots import take_snapshot
from tests.test_ai_r2_snapshot_cli import (  # noqa: F401  (fixtures)
    _restore,
    _with_vault,
    sent,
    vault_dir,
)

_SWITCH = (ai_access.ENABLED_KEY, ai_access.EPOCH_KEY, ai_access.STATE_MAC_KEY)


def _rows(path: Path) -> dict:
    with sqlite3.connect(str(path)) as conn:
        return dict(conn.execute(
            f"SELECT key, value FROM vault_meta WHERE key IN ({','.join('?' * len(_SWITCH))})", _SWITCH,
        ).fetchall())


def _write_back(live: Path, rows: dict) -> None:
    """What an agent with a shell does: the copy's switch rows into the live vault."""
    conn = sqlite3.connect(str(live))
    try:
        with conn:
            conn.execute(
                f"DELETE FROM vault_meta WHERE key IN ({','.join('?' * len(_SWITCH))})", _SWITCH,
            )
            conn.executemany("INSERT INTO vault_meta (key, value) VALUES (?, ?)", list(rows.items()))
    finally:
        conn.close()


def _copy(kind: str, vault, tmp_path: Path) -> Path:
    if kind == "snapshot":
        return take_snapshot(vault.db, "pre-sync")
    dest = tmp_path / "export.sezam"
    vault.db.backup(dest)
    return dest


@pytest.mark.parametrize("kind", ["snapshot", "backup"])
def test_a_copy_taken_while_on_cannot_turn_ai_access_back_on(vault_dir, tmp_path, kind):  # noqa: F811
    def copy_while_on(vault):
        assert ai_access.verified_on_epoch(vault) is not None
        return _copy(kind, vault, tmp_path)

    copy = _with_vault(vault_dir, copy_while_on)
    off = _with_vault(vault_dir, lambda vault: ai_access.disable(vault, "test"))
    assert off.enabled is False

    copied = _rows(copy)
    assert copied.get(ai_access.ENABLED_KEY) != "1"
    assert ai_access.STATE_MAC_KEY not in copied
    _write_back(vault_dir / "sezam.db", copied)

    def fresh_process(vault):  # no in-memory brake: a new mcp-serve or GUI
        return ai_access.read_state(vault), ai_access.verified_on_epoch(vault)

    state, verified = _with_vault(vault_dir, fresh_process)
    assert state.enabled is False
    assert verified is None


def test_the_live_vault_keeps_ai_access_on_when_a_snapshot_is_taken(vault_dir):  # noqa: F811
    def snapshot(vault):
        take_snapshot(vault.db, "pre-sync")
        return ai_access.read_state(vault), ai_access.verified_on_epoch(vault)

    state, verified = _with_vault(vault_dir, snapshot)
    assert state.enabled is True and verified == state.epoch


def test_a_snapshot_still_restores_with_ai_access_off(vault_dir):  # noqa: F811
    name = _with_vault(vault_dir, lambda vault: take_snapshot(vault.db, "import").name)
    assert _restore(name).exit_code == 0
    state = _with_vault(vault_dir, ai_access.read_state)
    assert state.enabled is False and state.epoch >= 1
