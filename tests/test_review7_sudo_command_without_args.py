"""Review 7c10379 (AI broker, medium): '--sudo-command' without arguments allowed any arguments.

In sudoers a command written without arguments may be run with any, so
'ai-host-setup --sudo-command /usr/bin/systemctl' let the AI account run
'sudo systemctl edit --full ssh' and so get root. A command without
arguments now gets '""' (sudoers: no arguments at all); one with arguments
is matched exactly as before. (systemctl itself is now listed only with an
action and a unit, R14-M4; an operator's script stands in.)
"""

# ruff: noqa: F811  (pytest fixture imported from the S3b tests)
from __future__ import annotations

import shutil
import subprocess

import pytest

from sezam.mcp.host_setup import host_setup_script
from tests.test_ai_s3b_host_setup import _entry, ca_pem  # noqa: F401  (fixture)
from tests.test_review6_sudoers_escape import _rule


def test_a_command_without_arguments_allows_none(ca_pem):
    rule = _rule(host_setup_script(_entry(ca_pem), "Servers/Web-AI", sudo_command="/usr/local/sbin/deploy"))

    assert rule == 'ai-web ALL=(root) NOPASSWD: /usr/local/sbin/deploy ""'


def test_a_command_with_arguments_is_matched_exactly(ca_pem):
    rule = _rule(host_setup_script(
        _entry(ca_pem), "Servers/Web-AI", sudo_command="/usr/bin/systemctl reload nginx"
    ))

    assert rule == "ai-web ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx"


def _wsl_visudo() -> bool:
    if shutil.which("wsl") is None:
        return False
    try:
        probe = subprocess.run(["wsl", "-e", "test", "-x", "/usr/sbin/visudo"], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


VISUDO = shutil.which("visudo")


@pytest.mark.skipif(not (VISUDO or _wsl_visudo()), reason="needs visudo (or WSL with sudo)")
def test_visudo_accepts_the_rule(ca_pem, tmp_path):
    rule = _rule(host_setup_script(_entry(ca_pem), "p", sudo_command="/usr/local/sbin/deploy"))
    if VISUDO:
        path = tmp_path / "rule"
        path.write_text(rule + "\n")
        result = subprocess.run([VISUDO, "-cf", str(path)], capture_output=True, text=True)
    else:
        result = subprocess.run(
            ["wsl", "-e", "sh", "-c", 'f=$(mktemp); printf "%s\\n" "$1" > "$f"; /usr/sbin/visudo -cf "$f"', "sh", rule],
            capture_output=True, text=True, timeout=60,
        )
    assert result.returncode == 0, result.stdout + result.stderr
