"""Review 7c10379: 'sezam ai off --terminate-remote' against a real OpenSSH server.

The old command killed every session of the account but its own shell's.
With OpenSSH privilege separation this login's own sshd process runs as the
account in another session, so it was killed too: the connection dropped
before the mark came back and the outcome read FAILED. And a ~/.bashrc of
the account (bash reads it for an ssh command) that only printed the fixed
mark read as success while the AI's sessions lived on.

Runs the real sshd as root, so only in a throwaway container
(SEZAM_TEST_HOST_SETUP=1, like tests/test_ai_s3b_host_setup.py).
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time

import pytest

from sezam.mcp import agent_sessions

SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
GOLDEN = bool(
    SSHD and hasattr(os, "geteuid") and os.geteuid() == 0
    and os.environ.get("SEZAM_TEST_HOST_SETUP") == "1"
)
USER = "ai-plain"
HOME = f"/home/{USER}"

if not GOLDEN and os.environ.get("SEZAM_REQUIRE_HOST_SETUP") == "1":  # CI host job: must run
    pytest.fail("SEZAM_REQUIRE_HOST_SETUP=1 but no root, sshd or SEZAM_TEST_HOST_SETUP=1", pytrace=False)
pytestmark = pytest.mark.skipif(
    not GOLDEN, reason="runs sshd as root: only in a throwaway container with SEZAM_TEST_HOST_SETUP=1"
)


class _Vault:
    def __init__(self, entry):
        self.entry = entry

    def read_entry(self, _entry_id):
        return self.entry


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _sleeps() -> list[str]:
    return subprocess.run(["pgrep", "-u", USER, "-x", "sleep"], capture_output=True, text=True).stdout.split()


def _wait(predicate, seconds=10.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return predicate()


@pytest.fixture
def host(tmp_path):
    subprocess.run(["useradd", "-m", "-s", "/bin/bash", USER], capture_output=True)
    subprocess.run(["usermod", "-p", "*", USER], check=True)
    subprocess.run(["pkill", "-KILL", "-u", USER], capture_output=True)
    key = tmp_path / "key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    os.makedirs(f"{HOME}/.ssh", exist_ok=True)
    shutil.copy(f"{key}.pub", f"{HOME}/.ssh/authorized_keys")
    for name in (".bashrc", ".profile", ".bash_profile"):
        if os.path.exists(f"{HOME}/{name}"):
            os.remove(f"{HOME}/{name}")
    subprocess.run(["chown", "-R", f"{USER}:{USER}", f"{HOME}/.ssh"], check=True)
    os.chmod(f"{HOME}/.ssh", 0o700)
    subprocess.run(["ssh-keygen", "-A"], check=True, capture_output=True)
    os.makedirs("/run/sshd", exist_ok=True)
    host_key = "/etc/ssh/ssh_host_ed25519_key"
    fingerprint = subprocess.check_output(["ssh-keygen", "-lf", f"{host_key}.pub"], text=True).split()[1]
    port = _free_port()
    log = open(tmp_path / "sshd.log", "w")
    sshd = subprocess.Popen(
        [SSHD, "-D", "-e", "-p", str(port), "-o", f"HostKey={host_key}",
         "-o", "PasswordAuthentication=no", "-o", "ListenAddress=127.0.0.1"],
        stdout=log, stderr=log,
    )
    assert _wait(lambda: socket.socket().connect_ex(("127.0.0.1", port)) == 0), (tmp_path / "sshd.log").read_text()

    def ssh(command, **kwargs):
        args = ["ssh", "-i", str(key), "-p", str(port), "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                f"{USER}@127.0.0.1", command]
        return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, **kwargs)

    entry = {"name": "web", "fields": [
        {"key": "host", "value": "127.0.0.1"}, {"key": "port", "value": str(port)},
        {"key": "username", "value": USER}, {"key": "private_key", "value": key.read_text()},
        {"key": "host_key_sha256", "value": fingerprint},
    ]}
    login = agent_sessions.AgentLogin("entry", "127.0.0.1", port, USER, False)
    held = []
    try:
        yield ssh, _Vault(entry), login, held
    finally:
        for proc in held:
            proc.kill()
        subprocess.run(["pkill", "-KILL", "-u", USER], capture_output=True)
        sshd.terminate()
        sshd.wait(10)
        log.close()


def _hold_sessions(ssh, held):
    """An open shell and a detached process, as the AI leaves them."""
    held.append(ssh("sleep 600"))
    ssh("setsid nohup sleep 700 >/dev/null 2>&1 </dev/null &").wait(20)
    assert _wait(lambda: len(_sleeps()) == 2), _sleeps()


def test_terminate_kills_the_other_sessions_and_says_so(host):
    ssh, vault, login, held = host
    _hold_sessions(ssh, held)

    assert agent_sessions.terminate(vault, login) == agent_sessions.KILLED
    assert _wait(lambda: held[0].poll() is not None)
    assert _wait(lambda: _sleeps() == []), _sleeps()


def test_a_startup_file_printing_the_mark_is_no_success(host):
    ssh, vault, login, held = host
    _hold_sessions(ssh, held)
    with open(f"{HOME}/.bashrc", "w") as rc:
        rc.write(f"echo {agent_sessions.DONE_MARK}; exit 0\n")
    subprocess.run(["chown", f"{USER}:{USER}", f"{HOME}/.bashrc"], check=True)
    probe = ssh("echo not-reached")
    assert probe.communicate(timeout=20)[0].split() == [agent_sessions.DONE_MARK]  # bash reads it

    outcome = agent_sessions.terminate(vault, login)
    assert outcome.startswith("FAILED"), outcome
    assert held[0].poll() is None  # nothing was killed, and the outcome says so
