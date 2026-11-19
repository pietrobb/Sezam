"""Review 688edcb, low: a master password ending in \\r.

Piped input was read with ``rstrip("\\r\\n")``, which also ate a \\r that is
part of the password, so such a password could never be entered in the CLI.
And the desktop accepted a new password with a control character, which no
browser or phone password field can type.
"""

from __future__ import annotations

import io

import pytest

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.vault.crud import Vault

FAST = Argon2Params(time_cost=1, memory_cost=8 * 1024, parallelism=1)


def _piped(monkeypatch, text: str) -> None:
    stream = io.StringIO(text)
    stream.isatty = lambda: False
    monkeypatch.setattr(cli.sys, "stdin", stream)


@pytest.mark.parametrize("piped, password", [
    ("pw\n", "pw"),
    ("pw\r\n", "pw"),
    # One line ending is stripped, nothing more: a trailing \r is typed
    # before it (works for LF and CRLF pipes alike).
    ("pw\r\r\n", "pw\r"),
    ("pw", "pw"),
])
def test_piped_password_loses_only_its_line_ending(monkeypatch, piped, password):
    _piped(monkeypatch, piped)
    assert cli._get_password() == password


@pytest.mark.parametrize("bad", ["pw\r", "p\tw", "pw\n", "pw\x00", "pw\x7f"])
def test_new_password_with_a_control_character_is_refused(tmp_path, bad):
    with pytest.raises(ValueError, match="control character"):
        Vault.create(tmp_path / "v", bad, FAST)
    assert not (tmp_path / "v" / "sezam.db").exists()

    vault = Vault.create(tmp_path / "ok", "good password", FAST)
    try:
        with pytest.raises(ValueError, match="control character"):
            vault.change_password("good password", bad, FAST)
    finally:
        vault.lock()
    reopened = Vault(tmp_path / "ok")
    reopened.unlock("good password")
    reopened.lock()


def test_cli_new_password_prompt_refuses_a_trailing_cr(monkeypatch, capsys):
    _piped(monkeypatch, "pw\r\r\npw\r\r\n")
    with pytest.raises(SystemExit):
        cli._get_new_password()
    assert "control character" in capsys.readouterr().err
