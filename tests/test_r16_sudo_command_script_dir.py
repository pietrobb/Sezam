"""Review 18c300f R16-L1: 'ai-host-setup --sudo-command' let any program
outside the system directories pass as 'the operator's script'.

'/opt/conda/bin/ipython' is no interpreter the list knew and lies in no
system directory, so the AI account got 'sudo ipython': a root shell. The
same held for any REPL or tool under /opt or /srv. A program outside the
listed system commands is now accepted only as a root-owned script in
/usr/local/sbin (run directly, or given to a system shell/interpreter); the
printed script checks on the host that it still resolves there and, run
directly, starts with '#!'.
"""

# ruff: noqa: F811  (pytest fixture imported from the S3b tests)
from __future__ import annotations

import re

import pytest

from sezam.mcp.host_setup import HostSetupError, host_setup_script
from tests.test_ai_s3b_host_setup import _entry, ca_pem  # noqa: F401  (fixture)
from tests.test_review9_ai_host_setup_sudo_target import SH, _run, _wsl_sh


@pytest.mark.parametrize("command", [
    "/opt/conda/bin/ipython",                  # the review's case: a root shell
    "/opt/conda/bin/jupyter console",
    "/opt/site/deploy.sh",
    "/srv/tools/run --now",
    "/usr/bin/python3 /opt/site/deploy.py",   # an interpreter given a script outside it
    "/bin/sh /srv/tools/deploy",
    "/usr/local/sbin",                         # the directory itself
])
def test_a_program_outside_the_script_directory_is_refused(ca_pem, command):
    with pytest.raises(HostSetupError, match="/usr/local/sbin"):
        host_setup_script(_entry(ca_pem), "p", sudo_command=command)


def test_a_script_run_directly_is_checked_for_its_first_line(ca_pem):
    direct = host_setup_script(_entry(ca_pem), "p", sudo_command="/usr/local/sbin/deploy --env=prod")
    assert "sezam_operator_script /usr/local/sbin/deploy run" in direct
    assert "SEZAM_SCRIPTS=/usr/local/sbin" in direct
    given = host_setup_script(_entry(ca_pem), "p", sudo_command="/usr/bin/python3 /usr/local/sbin/deploy.py")
    assert "sezam_operator_script /usr/local/sbin/deploy.py arg" in given


@pytest.mark.skipif(not (SH or _wsl_sh()), reason="needs a POSIX sh with readlink (or WSL)")
def test_the_host_refuses_a_link_out_of_the_directory_and_a_program_copied_there(ca_pem):
    script = host_setup_script(_entry(ca_pem), "p", sudo_command="/usr/local/sbin/deploy")
    function = re.search(r"^(sezam_operator_script\(\) \{\n.*?\n\})$", script, re.S | re.M).group(1)
    setup = ('d=$(mktemp -d); o=$(mktemp -d); SEZAM_SCRIPTS=$d; printf "#!/bin/sh\\n" > "$d/deploy"; '
             'printf "\\177ELF" > "$d/repl"; printf "#!/opt/conda/bin/python\\n" > "$o/ipython"; '
             'ln -s "$o/ipython" "$d/ipython"; ')

    def check(call: str):
        return _run(function, setup + call)

    assert check('sezam_operator_script "$d/deploy" run').returncode == 0
    linked = check('sezam_operator_script "$d/ipython" run')
    assert linked.returncode != 0 and "not a script in" in linked.stderr, linked.stderr
    binary = check('sezam_operator_script "$d/repl" run')
    assert binary.returncode != 0 and "no #! line" in binary.stderr, binary.stderr
    # Given to an interpreter, the file needs no '#!' line.
    assert check('sezam_operator_script "$d/repl" arg').returncode == 0
    assert check('sezam_operator_script "$d/missing" run').returncode != 0
