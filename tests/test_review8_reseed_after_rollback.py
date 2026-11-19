"""Review a159e97 (core, medium): a reseed after a detected rollback never finished.

A pull that sees the server behind this device's checkpoint records the
rollback (SERVER_ROLLBACK_META) and stops delta pulls until a full resync.
The reseed reset the checkpoint and commit anchor for the new, empty server
but kept that flag, so its closing pull raised "The server went back" and the
journal stayed at "push": every rerun pushed and failed the same way.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault.reseed import reseed_server
from sezam.vault.sync_common import SERVER_ROLLBACK_META
from tests.test_ai_r3_reseed import NEW_PASSWORD, _seeded_laptop, _wipe
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    _client,
    _entry_value,
    server,
)


def test_reseed_after_a_detected_rollback_completes(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _seeded_laptop(url, db, tmp_path)
    # The server is behind what this device saw: the pull flags the rollback.
    laptop.db.set_meta("last_known_commit_seq", "999")
    assert _client(laptop, url).pull().get("rollback_warning")
    assert laptop.db.get_meta(SERVER_ROLLBACK_META) is not None

    _wipe(db)
    result = reseed_server(laptop, url, NEW_PASSWORD)

    assert result["conflicts"] == []
    assert pending_states.reseed_state(laptop.db) is None
    assert laptop.db.get_meta(SERVER_ROLLBACK_META) is None
    assert "rollback_warning" not in _client(laptop, url).pull()
    assert _entry_value(laptop, "Servers", "db01", "password") == "s3cret"
    laptop.lock()
