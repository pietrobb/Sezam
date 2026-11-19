"""Review a159e97 (mobile, port of desktop 1cff856): 410 for good after a snapshot.

When the server's newest commits were tombstones its GC collected, a snapshot
(the first pull of a new phone, or a full resync) ends below the GC floor.
The phone stored that seq as its cursor, so every later pull asked from below
the floor and was refused with 410. The cursor now continues from the floor.
"""

from __future__ import annotations

from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    server,
)
from tests.test_review8_full_snapshot_below_gc_floor import _newest_commits_collected

PHONE_TEST = "test/phone_snapshot_below_gc_floor_test.dart"


def _collect_newest(db):
    counter = db._storage["commit_counter"][0]
    counter["gc_floor_seq"] = counter["next_seq"] + 2
    counter["next_seq"] += 3


def test_phone_pulls_after_a_snapshot_below_the_gc_floor(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _newest_commits_collected(url, tmp_path, db)

    def add(name):
        laptop.create_node(name)
        assert _client(laptop, url).push()["accepted"]

    _phone(url, tmp_path, {"username": "admin", "password": PASSWORD}, {
        "after": lambda: add("After"),
        "collected": lambda: _collect_newest(db),
        "later": lambda: add("Later"),
    }, PHONE_TEST)
    laptop.lock()
