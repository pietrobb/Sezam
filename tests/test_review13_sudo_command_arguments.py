"""Review c78fd19 R13-11: 'ai-host-setup --sudo-command' checks the
arguments too, not only the program.

'/bin/sh /var/www/site/deploy.sh' passed (the program /bin/sh belongs to
root) and gave root to a script the AI can rewrite; a shell without
arguments is a root shell; an interpreter given a relative file or a module
runs code from wherever the AI starts sudo.
"""

# ruff: noqa: F811  (pytest fixture imported from the S3b tests)
from __future__ import annotations

import re

import pytest

from sezam.mcp.host_setup import HostSetupError, host_setup_script
from tests.test_ai_s3b_host_setup import _entry, ca_pem  # noqa: F401  (fixture)


@pytest.mark.parametrize("command", [
    "/bin/sh /var/www/site/deploy.sh",       # the review's case
    "/usr/bin/python3 /home/ai-web/job.py",
    "/usr/bin/perl /tmp/x.pl",
    "/usr/bin/rsync -a /var/www/site/ /srv/backup",  # a file argument in the web root
    "/bin/sh /usr/local/../../tmp/x",
    "/bin/bash",                              # no arguments: a root shell
    "/bin/sh deploy.sh",                      # relative to the AI's directory
    "/usr/bin/python3 -m deploy",
    "/usr/bin/env deploy",
    "/usr/bin/sudo -u root /usr/bin/id",
    "/usr/bin/systemctl restart ./x",         # a relative path argument
])
def test_an_argument_the_ai_controls_is_refused(ca_pem, command):
    with pytest.raises(HostSetupError):
        host_setup_script(_entry(ca_pem), "p", web_root="/var/www/site", sudo_command=command)


def test_a_root_owned_script_is_checked_on_the_host_too(ca_pem):
    script = host_setup_script(
        _entry(ca_pem), "p", web_root="/var/www/site",
        sudo_command="/bin/sh /usr/local/sbin/deploy-site",
    )

    calls = re.findall(r"^sezam_root_only .*$", script, re.M)
    assert calls == ["sezam_root_only /bin/sh", "sezam_root_only /usr/local/sbin/deploy-site"]
    assert all(script.index(c) < script.index("visudo -cf") for c in calls)
    assert "NOPASSWD: /bin/sh /usr/local/sbin/deploy-site" in script


def test_plain_commands_still_pass(ca_pem):
    for command in ("/usr/bin/systemctl reload nginx", "/usr/bin/systemctl", "/usr/sbin/nginx -t"):
        host_setup_script(_entry(ca_pem), "p", web_root="/var/www/site", sudo_command=command)
