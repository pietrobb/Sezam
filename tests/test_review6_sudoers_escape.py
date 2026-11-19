"""Review main@d615826 (AI broker, medium): ``ai-host-setup --sudo-command``
let ':' and '=' into sudoers.

In a sudoers Cmnd an unescaped ':' ends the command and starts another rule
and '=' separates hosts from commands, so
``--sudo-command "/bin/true x : ALL = NOPASSWD: ALL"`` gave the AI account
root. Both are now escaped ('\\:' '\\='), so they stay plain argument
characters; ``--flag=value`` still works.
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import sys

import pytest

from sezam.mcp.host_setup import host_setup_script
from tests.test_ai_s3b_host_setup import _entry, _lines, ca_pem  # noqa: F401  (fixture)

INJECTION = "/bin/true x : ALL = NOPASSWD: ALL"


def _rule(script: str) -> str:
    line = next(line for line in _lines(script) if "NOPASSWD" in line)
    return shlex.split(line)[2]


def test_colon_and_equals_cannot_start_a_second_rule(ca_pem):  # noqa: F811
    rule = _rule(host_setup_script(_entry(ca_pem), "Servers/Web-AI", sudo_command=INJECTION))

    head, command = rule.split(" NOPASSWD: ", 1)
    assert head == "ai-web ALL=(root)"
    # Every ':' and '=' of the command is escaped: none ends the Cmnd.
    assert re.search(r"(?<!\\)[:=]", command) is None
    assert command == "/bin/true x \\: ALL \\= NOPASSWD\\: ALL"


def test_flag_with_value_is_kept_escaped(ca_pem):  # noqa: F811
    rule = _rule(host_setup_script(
        _entry(ca_pem), "Servers/Web-AI", sudo_command="/usr/bin/systemctl --no-pager=1 reload nginx"
    ))

    assert rule.endswith("NOPASSWD: /usr/bin/systemctl --no-pager\\=1 reload nginx")


@pytest.mark.skipif(
    not (shutil.which("visudo") and sys.platform != "win32"), reason="needs visudo"
)
def test_visudo_reads_the_injection_as_one_command(ca_pem, tmp_path):  # noqa: F811
    path = tmp_path / "rule"
    path.write_text(_rule(host_setup_script(_entry(ca_pem), "p", sudo_command=INJECTION)) + "\n")

    result = subprocess.run(["visudo", "-cf", str(path)], capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
