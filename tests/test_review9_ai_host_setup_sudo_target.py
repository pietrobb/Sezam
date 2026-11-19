"""Review 1141a20 (AI broker, the A5-A11 remainder): 'ai-host-setup --sudo-command' may name a program the AI can rewrite.

The one root command was checked only for sudoers syntax. A program in the
directory handed to the AI ('--web-root /var/www/site --sudo-command
/var/www/site/deploy.sh'), in a home or in /tmp is one the AI account can
replace, and 'sudo' then runs whatever it wrote as root. The command is now
refused when it lies under the web root, a home, a temporary directory or
has '.'/'..' components, and the printed script refuses to install the
sudoers rule unless the program and every directory above it (also after
resolving symlinks) belong to root and nobody else may write them.
"""

# ruff: noqa: F811  (pytest fixture imported from the S3b tests)
from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from sezam.mcp.host_setup import HostSetupError, host_setup_script
from tests.test_ai_s3b_host_setup import _entry, ca_pem  # noqa: F401  (fixture)


@pytest.mark.parametrize("command", [
    "/var/www/site/deploy.sh",
    "/var/www/site/bin/deploy reload",
    "/home/ai-web/bin/tool",
    "/home/someone/tool",
    "/tmp/tool",
    "/var/tmp/tool",
    "/dev/shm/tool",
    "/usr/bin/../../tmp/tool",
    "/usr/./bin/systemctl",
    "/usr//bin/systemctl",
])
def test_a_program_the_ai_may_rewrite_is_refused(ca_pem, command):
    with pytest.raises(HostSetupError):
        host_setup_script(_entry(ca_pem), "p", web_root="/var/www/site", sudo_command=command)


def test_a_system_program_is_still_accepted(ca_pem):
    script = host_setup_script(_entry(ca_pem), "p", web_root="/var/www/site", sudo_command="/usr/bin/systemctl reload nginx")

    assert "NOPASSWD: /usr/bin/systemctl reload nginx" in script


def _check(script: str) -> tuple[str, str]:
    """The ownership check function and the line that calls it."""
    match = re.search(r"^(sezam_root_only\(\) \{\n.*?\n\})$", script, re.S | re.M)
    assert match, "the script has no ownership check"
    call = re.search(r"^sezam_root_only .*$", script, re.M)
    assert call, "the script never runs the ownership check"
    return match.group(1), call.group(0)


def test_the_ownership_check_runs_before_the_rule_is_installed(ca_pem):
    script = host_setup_script(_entry(ca_pem), "p", sudo_command="/usr/bin/systemctl reload nginx")
    _, call = _check(script)

    assert call == "sezam_root_only /usr/bin/systemctl"
    assert script.index(call) < script.index("visudo -cf")


def _wsl_sh() -> bool:
    if shutil.which("wsl") is None:
        return False
    try:
        probe = subprocess.run(["wsl", "-e", "sh", "-c", "stat -c %u / && readlink -f /"], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


SH = shutil.which("sh") if shutil.which("stat") and shutil.which("readlink") else None


def _run(function: str, body: str) -> subprocess.CompletedProcess:
    code = "set -eu\n" + function + "\n" + body
    argv = [SH, "-c", code] if SH else ["wsl", "-e", "sh", "-c", code]
    return subprocess.run(argv, capture_output=True, text=True, timeout=60)


@pytest.mark.skipif(not (SH or _wsl_sh()), reason="needs a POSIX sh with GNU stat (or WSL)")
def test_the_check_refuses_a_program_the_account_owns_and_passes_a_system_one(ca_pem):
    function, _ = _check(host_setup_script(_entry(ca_pem), "p", sudo_command="/usr/bin/env"))

    system = _run(function, "sezam_root_only /usr/bin/env")
    assert system.returncode == 0, system.stdout + system.stderr

    # A program this (non-root) account can rewrite, and a root-owned
    # directory chain that ends in a world-writable one.
    own = _run(function, 'd=$(mktemp -d); touch "$d/tool"; sezam_root_only "$d/tool"')
    assert own.returncode != 0
    assert "root" in own.stderr

    # A symlink in a root-owned place that points into a writable one.
    linked = _run(function, 'd=$(mktemp -d); touch "$d/tool"; ln -s "$d/tool" "$d/link"; sezam_root_only "$d/link"')
    assert linked.returncode != 0

    missing = _run(function, "sezam_root_only /usr/bin/no-such-program-sezam")
    assert missing.returncode != 0
