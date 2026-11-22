"""Review 8bc70f7 M8 (goal #421): reseal_target took 106 s at 40 000 keys and
held the GIL the whole time.

The core answers 40 000 keys in one call in well under a second, but the
desktop asked it once per unsent item (sync_rekey._successor_dek), and each
ask replayed the local team log and sent every folder of the team again: one
re-key over many items was quadratic. The PyO3 binding also kept the GIL
while the core ran, so the GUI thread stood still.
"""

from __future__ import annotations

import threading
import time

import sezam_sync_core

from sezam.vault import revocation, sync_core, sync_rekey
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _two_devices
from tests.test_unsent_under_rekeyed_folder_sm26 import _sealed_with

FOLDERS = 5
PER_FOLDER = 3


def test_a_reseal_over_many_unsent_items_reads_the_log_and_asks_the_core_once(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    root = laptop.db.get_meta("root_node_id")
    folders = [laptop.create_node(f"Ops {i}", parent_id=root) for i in range(FOLDERS)]
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    for folder in folders:
        revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()
    entries = {
        laptop.create_entry(folder, f"e{i}", [{"key": "password", "value": f"after {i}", "sensitive": True}]): folder
        for folder in folders for i in range(PER_FOLDER)
    }
    assert revocation.revoke_member(phone, phone_client, bob_id) == FOLDERS

    # Each reseal (one at the pull's end, one before the push) counts the
    # times it reads the local team log and asks the core.
    counts: list[dict[str, int]] = []
    real_call, real_fetchall = sync_core.call, laptop.db.fetchall
    real_reseal = sync_rekey.RekeyMixin._reseal_under_successors

    def call(op, **arguments):
        if op == "reseal_targets" and counts:
            counts[-1]["core"] += 1
        return real_call(op, **arguments)

    def fetchall(sql, *args, **kwargs):
        if "FROM team_log" in sql and counts:
            counts[-1]["log"] += 1
        return real_fetchall(sql, *args, **kwargs)

    def reseal(self):
        counts.append({"core": 0, "log": 0})
        try:
            return real_reseal(self)
        finally:
            counts.append(counts.pop() | {"done": 1})

    monkeypatch.setattr(sync_core, "call", call)
    monkeypatch.setattr(laptop.db, "fetchall", fetchall)
    monkeypatch.setattr(sync_rekey.RekeyMixin, "_reseal_under_successors", reseal)
    laptop_client.pull()
    assert not laptop_client.push()["conflicts"]
    monkeypatch.undo()
    for entry, folder in entries.items():
        new_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
        assert _sealed_with(db, entry) == new_dek
    # Before: per item one ask of the core and a log read, and per retired
    # key two more reads to unlock it (76 reads and 15 asks here). Now a
    # fixed few, whatever the number of folders and items.
    assert counts and all(c["core"] <= 1 and c["log"] <= 3 for c in counts), counts
    phone_client.pull()
    assert "after 0" in str(phone.read_entry(next(iter(entries))))
    laptop.lock()
    phone.lock()


def _team(n: int) -> dict:
    return {
        "folders": {f"F{i:05}": [f"old{i}", f"new{i}"] for i in range(n)},
        "may_hold": [f"new{i}" for i in range(n)],
    }


def test_forty_thousand_keys_are_answered_in_one_call_quickly():
    n = 40_000
    started = time.perf_counter()
    out = sync_core.call(
        "reseal_targets", team=_team(n), successors={},
        held=[f"new{i}" for i in range(n)], keys=[f"old{i}" for i in range(n)],
    )
    elapsed = time.perf_counter() - started
    assert out[123] == {"send": "reseal", "key": "new123"}
    assert elapsed < 10, elapsed


def test_the_core_lets_other_python_threads_run():
    import json

    payload = json.dumps({
        "team": _team(40_000), "successors": {}, "held": [],
        "keys": [f"old{i}" for i in range(40_000)],
    })
    ticks = [0]
    stop = threading.Event()

    def spin():
        while not stop.is_set():
            ticks[0] += 1

    worker = threading.Thread(target=spin)
    worker.start()
    try:
        before, started = ticks[0], time.perf_counter()
        time.sleep(0.3)
        rate = (ticks[0] - before) / (time.perf_counter() - started)
        shares = []
        for _ in range(3):
            before, started = ticks[0], time.perf_counter()
            sezam_sync_core.call("reseal_targets", payload)
            shares.append((ticks[0] - before) / (rate * (time.perf_counter() - started)))
    finally:
        stop.set()
        worker.join()
    # Holding the GIL, the spinning thread only ran in the switch interval
    # around the call (a few percent of it).
    assert max(shares) > 0.5, shares
