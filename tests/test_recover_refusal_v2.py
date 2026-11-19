"""Review 688edcb V2: a throttled /api/auth/recover is not "no account here".

The desktop connect flow (CLI and GUI) treated 423/429 like a wrong password
and fell through to "Na tomto serveri nemas ucet" and the invitation prompt,
steering the owner of a locked account towards creating a second account.
"""

from __future__ import annotations

import io
import time

from sezam import cli
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _vault,
    server,
)


def test_cli_connect_to_a_locked_account_says_so_instead_of_asking_for_an_invitation(
    server, tmp_path, monkeypatch, capsys  # noqa: F811
):
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    account = next(u for u in db._storage["users"] if u["username"] == "admin")
    now_ms = int(time.time() * 1000)
    account.update({
        "recovery_locked": 1, "recovery_attempts": 20,
        "last_recovery_attempt": now_ms,
    })
    stdin = io.StringIO("should-not-be-read\n")
    monkeypatch.setattr("sys.stdin", stdin)
    capsys.readouterr()

    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, "a-typo-" + PASSWORD)
    out = capsys.readouterr()
    assert "nemas ucet" not in out.out + out.err
    assert "invitation" not in (out.out + out.err).lower()
    assert stdin.tell() == 0
    assert "docasne" in out.err
    assert len([u for u in db._storage["users"] if u["username"] == "admin"]) == 1
    laptop.lock()
    phone.lock()


def test_refusal_messages_cover_only_throttling():
    from sezam.vault.crud import recover_refusal
    from sezam.vault.sync_common import ServerError

    assert "docasne" in recover_refusal(ServerError(429, "Too many"))
    assert "zamknuty" in recover_refusal(ServerError(423, "Recovery locked"))
    assert recover_refusal(ServerError(401, "Recovery failed")) is None
    assert recover_refusal(ServerError(503, "down")) is None
