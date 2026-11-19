"""Review a159e97 (AI broker, medium): a snapshot restore turned AI access back on.

The snapshot held 'on' with a MAC under the same KEK, so after 'sezam ai off'
a restore of an older snapshot brought back a verified 'on'. The restored
vault now starts off, at an epoch past both, and the 'ai_off' audit record is
written at the next unlock.
"""

from __future__ import annotations

import json

from sezam.vault import ai_access
from sezam.vault.snapshots import take_snapshot
from tests.test_ai_r2_snapshot_cli import (  # noqa: F401  (fixtures)
    _restore,
    _with_vault,
    sent,
    vault_dir,
)


def test_a_restore_does_not_turn_ai_access_back_on(vault_dir):  # noqa: F811
    def snapshot_while_on(vault):
        assert ai_access.verified_on_epoch(vault) is not None
        return take_snapshot(vault.db, "import").name

    name = _with_vault(vault_dir, snapshot_while_on)
    off = _with_vault(vault_dir, lambda vault: ai_access.disable(vault, "test"))
    assert off.enabled is False

    assert _restore(name).exit_code == 0

    def state(vault):
        audit = [
            row["action"] for row in vault.db.fetchall("SELECT action FROM audit_log")
        ]
        return ai_access.read_state(vault), ai_access.verified_on_epoch(vault), audit

    restored, verified, audit = _with_vault(vault_dir, state)
    assert restored.enabled is False
    assert verified is None
    assert restored.epoch > off.epoch
    assert audit.count("ai_off") == 1  # the queued record, written at this unlock


def test_the_restore_record_names_its_source(vault_dir):  # noqa: F811
    name = _with_vault(vault_dir, lambda vault: take_snapshot(vault.db, "import").name)
    assert _restore(name).exit_code == 0
    from sezam.vault.db import VaultDB

    db = VaultDB(vault_dir / "sezam.db")
    db.open()
    try:
        pending = json.loads(db.get_meta(ai_access.PENDING_AUDIT_KEY))
    finally:
        db.close()
    assert pending[-1]["action"] == "ai_off"
    assert pending[-1]["detail"]["source"] == "restore"
