"""Review c02cc47 R17-L, desktop: a team key the log replaced, held only
through an envelope, no longer opened, and one refused key wiped every
cached key.

_team_key_state lets this account open a superseded key while the log lets it
hold the folder's current one (sync core may_open_superseded), but
_open_team_envelope_with judged its envelope with teamlog.envelope_valid,
which starts with may_hold_key: false for every key the log replaced. A member
whose log moved past a re-key before the re-sealed copies came could not read
what it held. And unlock_dek zeroed and cleared the whole DEK cache on any
failure, the personal keys too, though every unlock checks its own key's
authority again.
"""

from __future__ import annotations

import pytest
from nacl.exceptions import CryptoError

from sezam import teamlog
from sezam.models import new_ulid
from sezam.vault import revocation
from tests.test_integration_client_server import PASSWORD
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _ops


def _shared(team):  # noqa: F811
    _, admin, client, bob, receiver = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    folder = _ops(admin)
    item = admin.create_entry(folder, "receipt", [{"key": "password", "value": "actual-secret"}])
    revocation.grant_member(admin, client, bob.db.get_meta("user_id"), folder, "read")
    client.push()
    receiver.pull()
    assert bob.get_field_value(item, "password") == "actual-secret"
    return admin, client, bob, receiver, folder, item


def test_a_superseded_key_held_by_envelope_opens(team, server):  # noqa: F811
    admin, client, bob, receiver, folder, item = _shared(team)
    old = teamlog.current_key(receiver.team_state(), folder)
    client.append_team_log([("folder.key", {"folder": folder, "dek_id": new_ulid(), "gen": 1, "prev_dek_id": old})])
    receiver.pull()
    assert teamlog.current_key(receiver.team_state(), folder) != old
    bob.lock()
    bob.unlock(PASSWORD)
    assert len(bob.dek_mgr.unlock_dek(old)) == 32
    assert bob.get_field_value(item, "password") == "actual-secret"


def test_a_refused_key_leaves_the_other_cached_keys(team, server):  # noqa: F811
    admin, client, bob, receiver, folder, item = _shared(team)
    key = teamlog.current_key(receiver.team_state(), folder)
    own = bob.create_node("private")
    bob.create_entry(own, "mine", [{"key": "password", "value": "mine"}])
    own_key = bob.dek_mgr.get_dek_for_node(own)[0]
    own_raw = bytes(bob.dek_mgr.unlock_dek(own_key))
    cached = bob.dek_mgr.unlock_dek(key)
    envelope = bob.db.fetchone(
        "SELECT id FROM access_envelopes WHERE dek_id = ? AND user_id = ?", (key, bob.db.get_meta("user_id")))
    bob.db.execute("INSERT INTO withdrawn_envelopes (envelope_id) VALUES (?)", (envelope["id"],))
    with pytest.raises(CryptoError):
        bob.dek_mgr.unlock_dek(key)
    assert not any(cached)
    assert key not in bob.dek_mgr._dek_cache
    assert bytes(bob.dek_mgr._dek_cache[own_key]) == own_raw
