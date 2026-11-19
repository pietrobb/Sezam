"""AI broker R4 (TODO section 10): docs/EMERGENCY_KIT.md stays true to the CLI.

The kit is only useful if every command it tells you to run in an emergency
exists with the options shown.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import click
import pytest

from sezam import cli

DOCS = Path(__file__).resolve().parent.parent / "docs"
KIT = DOCS / "EMERGENCY_KIT.md"


def _commands() -> list[str]:
    return sorted(set(re.findall(r"`(sezam [^`]+)`", KIT.read_text(encoding="utf-8"))))


def test_kit_covers_the_required_topics():
    text = KIT.read_text(encoding="utf-8")
    for needle in (
        "sezam export-key", "sezam org-recovery-setup", "--format backup",
        "sezam snapshot list", "sezam snapshot restore", "sezam server reseed",
        "quarter", "clean device",
    ):
        assert needle in text, needle


@pytest.mark.parametrize("line", _commands())
def test_every_command_in_the_kit_exists_with_its_options(line):
    tokens = shlex.split(line.replace("…", ""))[1:]
    command: click.Command = cli.main
    while isinstance(command, click.Group) and tokens and not tokens[0].startswith("-"):
        name = tokens.pop(0)
        assert name in command.commands, f"{line}: no command {name!r}"
        command = command.commands[name]
    assert not isinstance(command, click.Group), f"{line}: names a group, not a command"
    known = {opt for param in command.params for opt in getattr(param, "opts", [])}
    for token in tokens:
        if token.startswith("-"):
            assert token.split("=")[0] in known, f"{line}: unknown option {token}"


def test_linked_sections_exist():
    tech = (DOCS / "TECHNICKA_DOKUMENTACIA.md").read_text(encoding="utf-8")
    for section in re.findall(r"TECHNICKA_DOKUMENTACIA\.md §([\d.]+)", KIT.read_text(encoding="utf-8")):
        assert re.search(rf"^### {re.escape(section)} ", tech, re.M), section
