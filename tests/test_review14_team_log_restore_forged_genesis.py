"""Review 8bc70f7 high #2: any member took a server without a team log over via restore.

POST /api/team-log/restore checked only that a genesis named an active admin
of the server, not its keys. A member forged a genesis under the admin's id
with a key of its own, added itself as admin and removed the admin; removed
members skipped the final key check, so the forged keys were never compared
with the users table. Now every member the restored log names, removed or
not, must end on the keys its account signs in with (or a rotation the log
itself retired, or no account yet).
"""

from __future__ import annotations

import pytest

from sezam import teamlog
from sezam.crypto.keys import generate_keypair
from sezam.models import new_ulid
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import team  # noqa: F401


def _forged_takeover(admin_id: str, bob, bob_id: str) -> list[dict]:
    fake = generate_keypair()
    fake_sk = fake.to_nacl_signing_key()
    state = teamlog.TeamState()
    records = []

    def add(kind, author, data, key):
        nonlocal state
        record = teamlog.sign_record(teamlog.next_body(state, kind, author, data), key)
        state = teamlog.apply_record(state, record)
        records.append(record)

    add("genesis", admin_id, {
        "org": new_ulid(), "user_id": admin_id,
        "signing_pk": fake.signing_pk.hex(), "encryption_pk": fake.encryption_pk.hex(),
    }, fake_sk)
    add("member.add", admin_id, {
        "user_id": bob_id, "signing_pk": bytes(bob.keypair.signing_pk).hex(),
        "encryption_pk": bytes(bob.keypair.encryption_pk).hex(), "role": "admin",
    }, fake_sk)
    add("member.remove", bob_id, {"user_id": admin_id}, bob.keypair.to_nacl_signing_key())
    return records


def test_a_member_cannot_take_a_server_without_log_over_through_restore(team):  # noqa: F811
    db, admin, client, bob, bob_client = team
    bob_id = bob_client._user_id
    records = _forged_takeover(client._user_id, bob, bob_id)
    teamlog.replay(records)  # the rules alone take it: only the users table can refuse

    # INV-2: the forged genesis gives the admin keys the account does not sign in with.
    with pytest.raises(RuntimeError, match=f"gives {client._user_id} keys the account does not sign in with"):
        bob_client._request("POST", "/api/team-log/restore", {"records": records}, auth=True)
    assert db._storage["team_log"] == []
    users = {u["id"]: u for u in db._storage["users"]}
    assert users[client._user_id]["status"] == "active"
    assert int(users[client._user_id]["is_admin"]) == 1
    assert int(users[bob_id]["is_admin"] or 0) == 0


def test_a_forged_genesis_cannot_be_hidden_by_re_adding_the_admin_on_its_real_keys(team, lock_spy):  # noqa: F811
    """Capability run 385: the log ended on the admin's real keys (removed, then
    re-added as a member), so a check of the final keys alone let it through;
    the founder's genesis keys themselves must be the account's."""
    db, admin, client, bob, bob_client = team
    admin_id, bob_id = client._user_id, bob_client._user_id
    records = _forged_takeover(admin_id, bob, bob_id)
    state = teamlog.replay(records)
    readd = teamlog.sign_record(teamlog.next_body(state, "member.add", bob_id, {
        "user_id": admin_id, "signing_pk": bytes(client._keypair.signing_pk).hex(),
        "encryption_pk": bytes(client._keypair.encryption_pk).hex(), "role": "member",
    }), bob.keypair.to_nacl_signing_key())
    records.append(readd)
    teamlog.replay(records)  # the rules alone take it

    with pytest.raises(RuntimeError, match=f"gives {admin_id} keys the account does not sign in with"):
        bob_client._request("POST", "/api/team-log/restore", {"records": records}, auth=True)
    assert lock_spy == []  # refused before the push lock (M6)
    assert db._storage["team_log"] == []
    users = {u["id"]: u for u in db._storage["users"]}
    assert int(users[admin_id]["is_admin"]) == 1
    assert int(users[bob_id]["is_admin"] or 0) == 0


@pytest.fixture
def lock_spy(monkeypatch):
    """How often an endpoint opened the transaction that takes the push lock."""
    from server.app.routers import team_log as router

    calls = []
    real = router.run_transaction

    async def spy(db, fn):
        calls.append(fn)
        return await real(db, fn)

    monkeypatch.setattr(router, "run_transaction", spy)
    return calls


def test_a_refused_restore_never_takes_the_push_lock(team, lock_spy):  # noqa: F811
    """Review 8bc70f7 M6: the replay and the key check run before the lock."""
    db, admin, client, bob, bob_client = team
    records = _forged_takeover(client._user_id, bob, bob_client._user_id)
    with pytest.raises(RuntimeError, match="keys the account does not sign in with"):
        bob_client._request("POST", "/api/team-log/restore", {"records": records}, auth=True)
    assert lock_spy == []


def test_a_member_cannot_make_every_push_wait_on_a_long_append(team, lock_spy):  # noqa: F811
    """Review 8bc70f7 M6: a member signs only its own member.keys; 1000 of them
    were replayed under the lock every other push waits on."""
    from tests.test_review13_team_log_restore_admin_only import _thief_member_keys
    from tests.test_team_log_desktop import _confirm_founder, _found_with_bob

    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    head = len(db._storage["team_log"])
    forged = _thief_member_keys(bob, bob_client)
    lock_spy.clear()
    with pytest.raises(RuntimeError, match="too many team log records"):
        bob_client._request("POST", "/api/team-log", {"records": [forged] * 5}, auth=True)
    assert lock_spy == []
    # One record still gets to the lock (and is refused there by the users table).
    with pytest.raises(RuntimeError, match="member.keys must carry the account's rotated keys"):
        bob_client._request("POST", "/api/team-log", {"records": [forged]}, auth=True)
    assert len(lock_spy) == 1
    assert len(db._storage["team_log"]) == head
