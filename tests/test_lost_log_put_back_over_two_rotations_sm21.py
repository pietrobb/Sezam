"""Stateful test finding R16-Z SM21 (TeamLogMachine, deep run of gate 16):
a stale device puts a lost team log back with one link over two rotations.

The laptop rotated the account's identity twice (K1 -> K2 -> K3). The phone
still held the log from before and K1. The server then lost its log. The phone
took K3 over with the password and put the log back as it held it, with one
link K1 -> K3 (R15, #429). The laptop's copy holds K1 -> K2 -> K3: the
server's log went back from its view and forked at the first rotation. The
K1 -> K3 change was on the server's side, the K1 -> K2 step was not, and a
member.keys bound to its head is not made again, so the laptop refused the
fork ('went back') on every pull and push for good. The same held in the page
and the phone (one account's browser holds the same log).

Invariant (INV-7, R16-H1 kept): a device follows a fork of its own account's
records when the server's side ends with the account on the keys this device
holds; the rotations it lost in between are moot (and withdrawn). Every other
refusal of fork_refusal stands (tests/vectors/team_log_fork.json).
"""

from __future__ import annotations

from sezam.models import new_ulid
from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_review9_team_identity import _rotate
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_team_log_desktop import _forget_server_cache


def test_a_device_follows_a_lost_log_put_back_with_one_link_over_its_rotations(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    _folder(laptop)
    laptop_client.push()
    laptop_client.found_team_log(new_ulid())
    phone_client.pull()
    assert phone_client.team_state() is not None
    uid = laptop.db.get_meta("user_id")

    for _ in range(2):
        laptop_client = _rotate(laptop, laptop_client, url)
        laptop_client.push()
    rotated = laptop_client.team_state()
    assert rotated.members[uid].signing_pk == laptop.keypair.signing_pk.hex()

    db._storage["team_log"] = []
    _forget_server_cache()
    try:
        phone_client.pull()
    except KeyEpochStale:
        pass
    phone_client.adopt_rotated_key_material(phone, PASSWORD)
    phone_client = _client(phone, url)
    phone_client.push()
    phone_client.pull()
    put_back = phone_client.team_state()
    assert db._storage["team_log"] and put_back.head_seq < rotated.head_seq

    laptop_client = _client(laptop, url)
    laptop_client.pull()
    laptop_client.push()
    state = laptop_client.team_state()
    assert (state.head_seq, state.head_hash) == (put_back.head_seq, put_back.head_hash)
    assert state.members[uid].signing_pk == laptop.keypair.signing_pk.hex()
    laptop.lock()
    phone.lock()
