"""Review 7c10379 (desktop sync Y6, Y7): a server rollback is shown.

A device that saw the server go back (restored from a backup) stops pulling
and pushing until a full resync, and remembers it (server_rollback_head).
'sezam push' then printed "Push: 0 accepted, 0 conflicts." and nothing else,
and 'sezam status' said nothing was waiting: the user never learned why
nothing synced or what to do. Both now name the rollback and the way out,
and after the full resync it is gone from 'sezam status'.
"""

from __future__ import annotations

import copy

from click.testing import CliRunner

from sezam import cli
from tests.test_ai_r1_snapshots import _cli_env
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    server,
)
from tests.test_rollback_commit_token_sm7 import _add, _restore, _two_devices

ROLLBACK = "server went back"
WAY_OUT = "sezam pull --full-resync"


def _run(args, extra_input: str = "") -> str:
    result = CliRunner().invoke(cli.main, args, input=f"{PASSWORD}\n{extra_input}")
    assert result.exit_code == 0, (args, result.output)
    return result.output


def test_push_and_status_name_the_rollback_and_the_way_out(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    backup = copy.deepcopy(db._storage)
    _add(laptop, "lost")
    assert _client(laptop, url).push()["accepted"]
    _restore(db, backup)
    phone_client = _client(phone, url)
    for name in ("a", "b", "c", "d", "e", "f"):
        _add(phone, name)
        phone_client.push()
    _add(laptop, "x")
    laptop.lock()
    phone.lock()

    _cli_env(tmp_path / "laptop", monkeypatch)
    pushed = _run(["push"])
    assert "ROLLBACK WARNING" in pushed and WAY_OUT in pushed, pushed
    status = _run(["status"])
    assert ROLLBACK in status and WAY_OUT in status, status
    assert "Nothing is waiting" not in status

    _run(["pull", "--full-resync"], "y\n")
    _run(["push"])
    assert ROLLBACK not in _run(["status"])
