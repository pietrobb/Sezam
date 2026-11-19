"""Review 8595ec1 (low): two ways a device lost its snapshots.

1. Every restore attempt first takes a 'pre-restore' snapshot, which counted
   against the 20 kept: a few attempts (each failed or undone one included)
   pushed out the oldest snapshots, the ones from before the incident that
   were being looked for.
2. Taking over a password changed on another device deleted every snapshot of
   the old password and took none under the new one: the device was left with
   no way back at all.
"""

from __future__ import annotations

import pytest

from sezam import cli
from sezam.vault.sync_client import KeyEpochStale
from sezam.vault.snapshots import (
    KEEP_SNAPSHOTS,
    discard_staged,
    install_staged,
    list_snapshots,
    stage_snapshot,
    take_snapshot,
)
from tests.test_ai_r1_snapshots import _opens_with
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)

NEW = "changed-elsewhere-pw!"


def test_restore_attempts_do_not_push_out_older_snapshots(tmp_path):
    vault = _vault(tmp_path / "v", "admin")
    vault.create_node("F")
    first = take_snapshot(vault.db, "import").name
    for _ in range(KEEP_SNAPSHOTS - 1):
        take_snapshot(vault.db, "delete-folder")
    vault.lock()
    regular = [s.name for s in list_snapshots(tmp_path / "v")]
    assert first in regular and len(regular) == KEEP_SNAPSHOTS

    # Looking for the right one: restore, undo, try another, ... and one
    # attempt that is abandoned after staging.
    for attempt in range(10):
        staging = stage_snapshot(tmp_path / "v", regular[-1 - attempt % 5])
        if attempt == 3:
            discard_staged(staging)
            continue
        install_staged(tmp_path / "v", staging)

    names = [s.name for s in list_snapshots(tmp_path / "v")]
    assert set(regular) <= set(names), "a restore attempt pushed out an older snapshot"
    assert len([n for n in names if n.endswith("-pre-restore.db")]) <= 3


def test_pre_restore_snapshots_still_go_and_the_latest_one_stays(tmp_path):
    vault = _vault(tmp_path / "v", "admin")
    name = take_snapshot(vault.db, "import").name
    vault.lock()
    for _ in range(6):
        install_staged(tmp_path / "v", stage_snapshot(tmp_path / "v", name))
    pre = [s for s in list_snapshots(tmp_path / "v") if s.reason == "pre-restore"]
    assert 1 <= len(pre) <= 3


def test_taking_over_a_password_changed_elsewhere_leaves_a_snapshot(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.create_node("F")
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    phone_client = _client(phone, url)
    phone_client.pull()
    take_snapshot(phone.db, "delete-folder")  # of the old password

    laptop.change_password(PASSWORD, NEW)
    assert not _client(laptop, url).push()["conflicts"]
    with pytest.raises(KeyEpochStale):
        phone_client.pull()
    phone_client.adopt_rotated_key_material(phone, NEW)

    snapshots = list_snapshots(tmp_path / "phone")
    assert snapshots, "taking the password over left no snapshot"
    assert all(_opens_with(s.path, tmp_path, NEW) for s in snapshots)
    assert not any(_opens_with(s.path, tmp_path, PASSWORD) for s in snapshots)
    phone.lock()
    laptop.lock()
