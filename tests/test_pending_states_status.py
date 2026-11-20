"""Review 526419e SYS: every pending state is listed and has a way out.

Each review round found another state a vault kept waiting for the server -
a password change, a member re-key, the revocation queue, edits held by a
re-key, conflicts, a recovery key the server lacks - and some had no visible
or no usable way out. 'sezam status' lists them all with the command that
drops each one without a forgotten secret. Every combination that can arise
is built here; taking the listed ways out leaves nothing waiting and a clean
push.
"""

from __future__ import annotations

import itertools
import os
import re

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.models import new_ulid
from sezam.vault import oplock, outbox, pending_states
from tests.test_ai_r1_snapshots import _cli_env
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _server_member,
    _vault,
    server,
)

NEW = "a-new-password-1!"
STATES = ("conflicts", "key_change", "org_recovery_registration", "rekey", "queued_revocations")
SUMMARIES = {
    "key_change": "password or key change has not reached the server",
    "rekey": "re-key after removing member",
    "queued_revocations": "removed member(s) wait",
    "conflicts": "conflict(s) with the server's copies",
    "org_recovery_registration": "has not registered this vault's org recovery",
}
# A password change and a member re-key never wait together (review 526419e V4).
COMBOS = [
    combo for n in range(1, len(STATES) + 1) for combo in itertools.combinations(STATES, n)
    if not {"key_change", "rekey"} <= set(combo)
]


def _member_on(vault, db, dek_id: str) -> str:
    member = _server_member(db)
    vault.db.execute(
        "INSERT INTO access_envelopes "
        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, 'read', ?)",
        (new_ulid(), dek_id, member, vault.db.get_meta("user_id"), os.urandom(72)),
    )
    return member


def _build(url, db, tmp_path, combo) -> str:
    """Put the laptop into every state of ``combo``; returns its password."""
    laptop = _vault(tmp_path / "laptop", "admin")
    ops = laptop.create_node("Ops")
    laptop.create_entry(ops, "vpn", [{"key": "password", "value": "v1", "sensitive": True}])
    misc = laptop.create_node("Misc")
    note = laptop.create_entry(misc, "note", [{"key": "text", "value": "n1"}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    def dek_of(node):
        return laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (node,))["dek_id"]

    # (Fake members without keys: each one alone on a folder.)
    first, second = _member_on(laptop, db, dek_of(ops)), _member_on(laptop, db, dek_of(misc))
    outbox.queue_write(laptop.db, ops)
    outbox.queue_write(laptop.db, misc)
    assert _client(laptop, url).push()["conflicts"] == []
    password = PASSWORD

    if "conflicts" in combo:
        phone = _vault(tmp_path / "phone", "admin")
        cli._server_connect_flow(url, phone, PASSWORD)
        phone.update_entry(note, fields=[{"key": "text", "value": "phone"}])
        assert _client(phone, url).push()["conflicts"] == []
        phone.lock()
        laptop.update_entry(note, fields=[{"key": "text", "value": "laptop"}])
        client = _client(laptop, url)
        client.push()
        client.pull()
        assert laptop.db.fetchall("SELECT object_id FROM sync_conflicts")
    if "key_change" in combo:
        laptop.change_password(PASSWORD, NEW)
        password = NEW
    if "org_recovery_registration" in combo:
        laptop.setup_org_recovery(threshold=2, shares=3)  # never sent to the server
    if "rekey" in combo:
        assert laptop.rekey_after_revocation(first) == 1
    if "queued_revocations" in combo:
        with oplock.exclusive(laptop.db.path):  # INV-6
            pending_states.set_revocation_queue(laptop.db, [second])
    laptop.lock()
    return password


def _run(args, password, extra_input=""):
    result = CliRunner().invoke(cli.main, args, input=f"{password}\n{extra_input}")
    assert result.exit_code == 0, (args, result.output)
    return result.output


def _waiting(password) -> list[str]:
    output = _run(["status"], password)
    return [key for key, text in SUMMARIES.items() if text in output]


def _drop(state: str, password: str) -> str:
    """Take the 'drop' way out of ``state``; returns the vault password after."""
    if state == "key_change":
        _run(["abandon-pending-change", "--yes"], password, f"{PASSWORD}\n")
        return PASSWORD
    if state == "rekey":
        _run(["abandon-rekey", "--yes"], password)
    elif state == "queued_revocations":
        _run(["abandon-rekey", "--queued", "--yes"], password)
    elif state == "conflicts":
        listing = _run(["conflicts"], password)
        for object_id in sorted(set(re.findall(r"\b[0-9A-HJKMNP-TV-Z]{26}\b", listing))):
            CliRunner().invoke(
                cli.main, ["conflicts", "resolve", object_id, "--keep", "server"],
                input=f"{password}\n",
            )
    elif state == "org_recovery_registration":
        _run(["org-recovery-setup", "-t", "2", "-n", "3", "--replace"], password)
    return password


@pytest.mark.parametrize("combo", COMBOS, ids=lambda c: "+".join(c))
def test_status_lists_every_pending_state_and_each_way_out_works(
    server, tmp_path, monkeypatch, combo  # noqa: F811
):
    url, db = server
    password = _build(url, db, tmp_path, combo)
    _cli_env(tmp_path / "laptop", monkeypatch)

    assert sorted(_waiting(password)) == sorted(combo)
    for _ in range(2 * len(STATES)):
        waiting = _waiting(password)
        if not waiting:
            break
        password = _drop(waiting[0], password)  # in the order status lists them
    assert _waiting(password) == []

    output = _run(["push"], password)
    assert ", 0 conflicts." in output, output
    assert "Nothing is waiting." in _run(["status"], password)
