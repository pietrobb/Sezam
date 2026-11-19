"""Review 1141a20 (R9-E, goal #361): a snapshot restore took back the team log trust.

Restoring an older snapshot brought back a shorter team log and no pinned or
confirmed genesis (or confirmed founder keys): the device then followed a
server log it had refused before, an automatic downgrade. The live vault's
log, pins and confirmations now survive the restore.
"""

from __future__ import annotations

from sezam import teamlog
from sezam.vault.snapshots import take_snapshot
from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META
from sezam.vault.team_log_local import CONFIRMED_GENESIS_META, GENESIS_META
from tests.team_log_vectors import A, B, C, Log
from tests.test_ai_r2_snapshot_cli import (  # noqa: F401  (fixtures)
    _restore,
    _with_vault,
    sent,
    vault_dir,
)

LOG = Log().genesis().member(B).member(C)


def _store(vault, records) -> None:
    with vault.db.transaction():
        vault.db.execute("DELETE FROM team_log")
        for seq, record in enumerate(records):
            vault.db.execute(
                "INSERT INTO team_log (seq, body, sig, hash) VALUES (?, ?, ?, ?)",
                (seq, record["body"], record["sig"], teamlog.record_hash(record)),
            )


def _anchors(vault):
    return (
        [row["hash"] for row in vault.db.fetchall("SELECT hash FROM team_log ORDER BY seq")],
        vault.db.get_meta(GENESIS_META),
        vault.db.get_meta(CONFIRMED_GENESIS_META),
        vault.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META),
    )


def test_an_older_snapshot_keeps_the_log_pin_and_confirmations(vault_dir):  # noqa: F811
    genesis = teamlog.replay(LOG.records).genesis_hash

    def before_the_log(vault):
        return take_snapshot(vault.db, "import").name

    def accept(vault):
        _store(vault, LOG.records)
        vault.db.set_meta(GENESIS_META, genesis)
        vault.db.set_meta(CONFIRMED_GENESIS_META, genesis)
        vault.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {A.uid: "fp-a"})
        return _anchors(vault)

    empty = _with_vault(vault_dir, before_the_log)
    held = _with_vault(vault_dir, accept)

    assert _restore(empty).exit_code == 0
    assert _with_vault(vault_dir, _anchors) == held


def test_a_snapshot_with_a_shorter_log_keeps_the_longer_one(vault_dir):  # noqa: F811
    def shorter(vault):
        _store(vault, LOG.records[:2])
        vault.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {B.uid: "fp-b"})
        return take_snapshot(vault.db, "import").name

    def longer(vault):
        _store(vault, LOG.records)
        vault.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {A.uid: "fp-a"})

    name = _with_vault(vault_dir, shorter)
    _with_vault(vault_dir, longer)

    assert _restore(name).exit_code == 0
    hashes, _, _, members = _with_vault(vault_dir, _anchors)
    assert hashes == [teamlog.record_hash(r) for r in LOG.records]
    assert members == {B.uid: "fp-b", A.uid: "fp-a"}  # nothing confirmed is lost


def test_a_vault_without_a_log_keeps_the_snapshots(vault_dir):  # noqa: F811
    def with_log(vault):
        _store(vault, LOG.records)
        name = take_snapshot(vault.db, "import").name
        vault.db.execute("DELETE FROM team_log")
        return name

    name = _with_vault(vault_dir, with_log)
    assert _restore(name).exit_code == 0
    hashes, _, _, _ = _with_vault(vault_dir, _anchors)
    assert hashes == [teamlog.record_hash(r) for r in LOG.records]
