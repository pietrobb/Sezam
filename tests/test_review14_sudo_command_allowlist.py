"""Review 8bc70f7 R14-M4: 'ai-host-setup --sudo-command' refused only what it
knew to be dangerous (interpreters, files the AI may write).

Every other system program passed, and many run code or take input from
where the AI stands: 'sudo make install' runs the Makefile of the directory
the AI starts sudo in, 'sudo git pull' its hooks and config, 'systemctl
status' a pager with '!sh', 'tee /etc/sudoers' writes what the AI pipes in.
A system program is now accepted only from a short list of exact shapes;
anything else must be a root-owned script outside the system directories
(run directly or by a shell/interpreter), and the printed script refuses
one that resolves to a system program on the host.
"""

# ruff: noqa: F811  (pytest fixture imported from the S3b tests)
from __future__ import annotations

import re

import pytest

from sezam.mcp.host_setup import HostSetupError, host_setup_script
from tests.test_ai_s3b_host_setup import _entry, ca_pem  # noqa: F401  (fixture)
from tests.test_review9_ai_host_setup_sudo_target import SH, _run, _wsl_sh


@pytest.mark.parametrize("command", [
    "/usr/bin/make install",                  # the review's cases
    "/usr/bin/git pull",
    "/usr/bin/git -C /srv/site pull",
    "/usr/bin/systemctl",                     # a pager with '!sh'
    "/usr/bin/systemctl status nginx",
    "/usr/bin/systemctl edit nginx",
    "/usr/bin/tee /etc/sudoers",
    "/usr/bin/vim /etc/hosts",
    "/usr/bin/less /var/log/syslog",
    "/usr/bin/find /etc -newer /etc/hosts",
    "/usr/bin/tar -xf /srv/site.tar",
    "/usr/bin/cp /srv/a /etc/cron.d/x",
    "/usr/bin/npm install",
    "/usr/bin/apt-get update",
    "/usr/bin/env /usr/local/sbin/deploy",    # a wrapper runs what follows
    "/usr/bin/timeout 60 /usr/local/sbin/deploy",
    "/bin/sh /usr/bin/gettext.sh",            # a shell given a system file
    "/usr/sbin/nginx -g daemon",              # a listed program, another shape
    "/usr/sbin/service nginx status",
    "/opt/node/bin/node /usr/local/sbin/x.js",  # an interpreter outside the system directories
])
def test_a_system_program_off_the_list_is_refused(ca_pem, command):
    with pytest.raises(HostSetupError, match="--sudo-command"):
        host_setup_script(_entry(ca_pem), "p", sudo_command=command)


@pytest.mark.parametrize("command", [
    "/usr/bin/systemctl reload nginx",
    "/bin/systemctl restart php8.2-fpm",
    "/usr/bin/systemctl try-restart my-app@1.service",
    "/usr/sbin/service nginx reload",
    "/usr/sbin/nginx -t",
    "/usr/sbin/nginx -s reload",
    "/usr/sbin/apachectl graceful",
    "/usr/local/sbin/deploy-site",
    "/usr/local/sbin/deploy-site --env=prod",
    "/bin/sh /usr/local/sbin/deploy-site",
    "/usr/bin/python3 /usr/local/sbin/deploy.py",
])
def test_listed_commands_and_root_owned_scripts_pass(ca_pem, command):
    host_setup_script(_entry(ca_pem), "p", web_root="/var/www/site", sudo_command=command)


def _calls(script: str, name: str) -> list[str]:
    return re.findall(rf"^{name} .*$", script, re.M)


def test_the_host_refuses_a_script_that_resolves_to_a_system_program(ca_pem):
    script = host_setup_script(_entry(ca_pem), "p", sudo_command="/bin/sh /usr/local/sbin/deploy-site")
    assert _calls(script, "sezam_operator_script") == ["sezam_operator_script /usr/local/sbin/deploy-site arg"]
    assert script.index("sezam_operator_script /") < script.index("visudo -cf")
    # A listed system command has no script to check.
    listed = host_setup_script(_entry(ca_pem), "p", sudo_command="/usr/bin/systemctl reload nginx")
    assert _calls(listed, "sezam_operator_script") == []


@pytest.mark.skipif(not (SH or _wsl_sh()), reason="needs a POSIX sh with readlink (or WSL)")
def test_the_host_check_refuses_a_system_program_and_passes_a_script(ca_pem):
    script = host_setup_script(_entry(ca_pem), "p", sudo_command="/usr/local/sbin/deploy-site")
    function = re.search(r"^(sezam_operator_script\(\) \{\n.*?\n\})$", script, re.S | re.M).group(1)
    scripts = 'd=$(mktemp -d); SEZAM_SCRIPTS=$d; printf "#!/bin/sh\\n" > "$d/deploy-site"; '

    tool = _run(function, scripts + 'ln -s /usr/bin/env "$d/env"; sezam_operator_script "$d/env" run')
    assert tool.returncode != 0 and "not a script in" in tool.stderr, tool.stdout + tool.stderr
    own = _run(function, scripts + 'sezam_operator_script "$d/deploy-site" run')
    assert own.returncode == 0, own.stdout + own.stderr
