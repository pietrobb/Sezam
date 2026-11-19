"""AI broker TODO section 3 (S3b): ``sezam ai-host-setup --entry``.

Prints (never runs) the commands for a server account that accepts only
Sezam SSH certificates: dedicated user without sudo, cron/at denied, no
linger, the CA public key and principal for that account only, and an sshd
Match block with ``AuthorizedKeysFile none`` and no forwarding. Every value
is validated and shell-quoted. A golden test (Linux container as root, with
SEZAM_TEST_HOST_SETUP=1) runs the printed script and logs in with a
certificate from ``sezam ssh-agent`` while a key the AI would add to
authorized_keys is refused. After ai_off a detached process and an open
session survive the brake until the root reaper from the script runs once
the session is older than the certificate TTL; then nothing is left.
"""

from __future__ import annotations

import base64
import io
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time

import paramiko
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from sezam import cli
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.host_setup import HostSetupError, host_setup_script
from sezam.mcp.ssh_agent import (
    SSHAgentServer,
    SSHAgentService,
    default_endpoint,
    host_key_fingerprint,
)
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_ai_s2a_ssh_agent import _openssh
from tests.test_mcp_ssh import FAST_PARAMS


@pytest.fixture(scope="module")
def ca_pem():
    return _openssh(ed25519.Ed25519PrivateKey.generate())


def _entry(pem: str, *, username="ai-web", ssh_ca=True, **extra) -> dict:
    fields = [
        {"key": "host", "value": "web.example.test"},
        {"key": "username", "value": username},
        {"key": "private_key", "value": pem},
    ]
    if ssh_ca:
        fields.append({"key": "ssh_ca", "value": "yes"})
    fields += [{"key": k, "value": v} for k, v in extra.items()]
    return {"id": "E1", "name": "Web-AI", "fields": fields}


def _lines(script: str) -> list[str]:
    return script.splitlines()


def test_script_sets_up_a_certificate_only_account(ca_pem):
    script = host_setup_script(_entry(ca_pem, cert_ttl_minutes="15"), "Servers/Web-AI")
    ca_pub = paramiko.Ed25519Key.from_private_key(io.StringIO(ca_pem)).get_base64()
    lines = _lines(script)
    assert lines[0] == "#!/bin/sh" and "set -eu" in lines
    assert "id -u ai-web >/dev/null 2>&1 || useradd --create-home --shell /bin/bash ai-web" in lines
    assert "usermod -p '*' ai-web" in lines
    assert "grep -qxF ai-web /etc/cron.deny || echo ai-web >> /etc/cron.deny" in lines
    assert "if command -v loginctl >/dev/null 2>&1; then loginctl disable-linger ai-web; fi" in lines
    assert f"printf '%s\\n' 'ssh-ed25519 {ca_pub} sezam-ai-ca' > /etc/ssh/sezam_ai_ca_ai-web.pub" in lines
    assert "printf '%s\\n' ai-web > /etc/ssh/principals/ai-web" in lines
    block = lines[lines.index("Match User ai-web"):lines.index("SEZAM_EOF", lines.index("Match User ai-web"))]
    assert "    TrustedUserCAKeys /etc/ssh/sezam_ai_ca_ai-web.pub" in block
    assert "    AuthorizedKeysFile none" in block
    assert "    AuthorizedPrincipalsFile /etc/ssh/principals/%u" in block
    for option in ("AllowAgentForwarding", "AllowTcpForwarding", "X11Forwarding", "PermitTunnel"):
        assert f"    {option} no" in block
    assert "sshd -t" in lines
    assert "within 15 minutes" in script
    # The root reaper: sessions at most the TTL, nothing left without a session.
    reaper = lines[lines.index("cat > /usr/local/sbin/sezam-ai-reap-ai-web <<'SEZAM_EOF'"):]
    assert "U=ai-web" in reaper and "MAX=900" in reaper
    assert "[ \"$live\" = 1 ] || pkill -KILL -u \"$U\"" in reaper
    assert "  systemctl enable --now sezam-ai-reap-ai-web.timer" in lines
    assert "  printf '%s\\n' '* * * * * root /usr/local/sbin/sezam-ai-reap-ai-web' > /etc/cron.d/sezam-ai-reap-ai-web" in lines
    assert lines.index("  exit 1") < lines.index("Match User ai-web")  # no scheduler: account not enabled
    assert "sudo" not in "\n".join(line for line in lines if not line.startswith("#"))
    # Only public material.
    body = "".join(line for line in ca_pem.splitlines() if "PRIVATE KEY" not in line)
    assert body[:40] not in script


def test_optional_web_root_and_single_sudo_command_are_quoted(ca_pem):
    root = "/srv/my site/$(touch pwned)"
    script = host_setup_script(
        _entry(ca_pem), "Servers/Web-AI", web_root=root + "/", sudo_command="/bin/systemctl reload nginx"
    )
    chgrp = next(line for line in _lines(script) if line.startswith("chgrp"))
    assert shlex.split(chgrp) == ["chgrp", "-R", "ai-web", root]
    sudo = next(line for line in _lines(script) if "NOPASSWD" in line)
    assert shlex.split(sudo)[2] == "ai-web ALL=(root) NOPASSWD: /bin/systemctl reload nginx"
    assert "visudo -cf /etc/sudoers.d/.sezam-ai-ai-web.tmp" in script
    assert script.index("visudo -cf") < script.index("mv /etc/sudoers.d/.sezam-ai-ai-web.tmp")


def test_comment_values_cannot_break_out_of_the_comment(ca_pem):
    script = host_setup_script(_entry(ca_pem), "Servers/x\nrm -rf /\n")
    assert "rm -rf /" not in [line.strip() for line in _lines(script)]
    assert all(line.startswith("#") for line in _lines(script)[1:3])


@pytest.mark.parametrize("username", ["root", "AI", "ai web", "$(id)", "ai;id", "-ai", "a" * 33])
def test_refuses_unsafe_or_shared_account_names(ca_pem, username):
    with pytest.raises(HostSetupError):
        host_setup_script(_entry(ca_pem, username=username), "p")


@pytest.mark.parametrize("command", [
    "ALL", "/bin/sh -c 'id'", "/usr/bin/*", "/bin/a, /bin/b", "systemctl reload nginx",
    "/bin/x\n/bin/y", "/bin/x \\", "/bin/x $(id)",
])
def test_refuses_sudo_rules_beyond_one_plain_command(ca_pem, command):
    with pytest.raises(HostSetupError):
        host_setup_script(_entry(ca_pem), "p", sudo_command=command)


@pytest.mark.parametrize("root", ["/", "/var", "relative/dir", "/etc/nginx", "/var/www/../../etc", "/var/www\nx", "/usr/share/x"])
def test_refuses_dangerous_web_roots(ca_pem, root):
    with pytest.raises(HostSetupError):
        host_setup_script(_entry(ca_pem), "p", web_root=root)


def test_refuses_entries_that_are_not_an_ed25519_ssh_ca(ca_pem):
    with pytest.raises(HostSetupError, match="ssh_ca"):
        host_setup_script(_entry(ca_pem, ssh_ca=False), "p")
    with pytest.raises(HostSetupError, match="Ed25519"):
        host_setup_script(_entry(_openssh(rsa.generate_private_key(65537, 2048))), "p")
    with pytest.raises(HostSetupError):
        host_setup_script(_entry(ca_pem, cert_ttl_minutes="90"), "p")


@pytest.mark.skipif(not (shutil.which("sh") and sys.platform != "win32"), reason="needs a POSIX sh")
def test_script_is_valid_sh(ca_pem, tmp_path):
    path = tmp_path / "setup.sh"
    path.write_text(host_setup_script(
        _entry(ca_pem), "Servers/Web-AI", web_root="/var/www/site", sudo_command="/bin/true"
    ))
    result = subprocess.run(["sh", "-n", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_cli_prints_the_script_and_locks_the_vault(tmp_path, monkeypatch, ca_pem):
    vault = Vault.create(tmp_path, "pw", FAST_PARAMS)
    folder = vault.create_node("Servers")
    vault.create_entry(folder, "Web-AI", _entry(ca_pem)["fields"], tier=0, allowed_actions=["ssh_agent"])
    vault.lock()
    monkeypatch.setenv("SEZAM_VAULT", str(tmp_path))
    result = CliRunner().invoke(cli.main, ["ai-host-setup", "--entry", "Servers/Web-AI"], input="pw\n")
    assert result.exit_code == 0, result.output
    assert "#!/bin/sh" in result.output and "Match User ai-web" in result.output
    body = "".join(line for line in ca_pem.splitlines() if "PRIVATE KEY" not in line)
    assert body[:40] not in result.output

    bad = CliRunner().invoke(
        cli.main, ["ai-host-setup", "--entry", "Servers/Web-AI", "--sudo-command", "ALL"], input="pw\n"
    )
    assert bad.exit_code != 0 and "--sudo-command" in bad.output
    missing = CliRunner().invoke(cli.main, ["ai-host-setup", "--entry", "Servers/Nope"], input="pw\n")
    assert missing.exit_code != 0 and "Entry not found" in missing.output


# ── golden: run the printed script in a throwaway Linux container ──

SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
SSH = shutil.which("ssh")
GOLDEN = (
    sys.platform.startswith("linux")
    and os.environ.get("SEZAM_TEST_HOST_SETUP") == "1"
    and hasattr(os, "geteuid") and os.geteuid() == 0
    and SSHD and SSH
)
if not GOLDEN and os.environ.get("SEZAM_REQUIRE_HOST_SETUP") == "1":  # CI host job: must run
    pytest.fail("SEZAM_REQUIRE_HOST_SETUP=1 but no Linux root, sshd/ssh or SEZAM_TEST_HOST_SETUP=1", pytrace=False)


@pytest.mark.skipif(not GOLDEN, reason="runs the script as root: only in a throwaway container "
                    "with sshd and SEZAM_TEST_HOST_SETUP=1")
def test_printed_script_gives_a_certificate_only_account(tmp_path, ca_pem):
    user = "ai-web"
    script = tmp_path / "setup.sh"
    script.write_text(host_setup_script(
        _entry(ca_pem, cert_ttl_minutes="1"), "Servers/Web-AI", web_root="/var/www/site", sudo_command="/bin/true"
    ))
    os.makedirs("/var/www/site", exist_ok=True)
    os.makedirs("/etc/cron.d", exist_ok=True)  # no systemd here: the reaper goes to cron.d
    stub = tmp_path / "bin"
    stub.mkdir()
    for tool in ("systemctl", "loginctl"):  # no systemd as PID 1 in a container
        (stub / tool).write_text("#!/bin/sh\nexit 0\n")
        (stub / tool).chmod(0o755)
    env = {**os.environ, "PATH": f"{stub}:/usr/sbin:/sbin:{os.environ['PATH']}"}
    for _ in range(2):  # idempotent
        result = subprocess.run(["sh", str(script)], capture_output=True, text=True, env=env)
        assert result.returncode == 0, result.stdout + result.stderr
    assert open("/etc/ssh/sshd_config").read().count("Match User ai-web") == 1

    def effective(user_name):
        out = subprocess.run(
            [SSHD, "-T", "-C", f"user={user_name},host=localhost,addr=127.0.0.1"],
            capture_output=True, text=True, check=True,
        ).stdout
        return dict(line.split(" ", 1) for line in out.splitlines() if " " in line)

    ai, root = effective(user), effective("root")
    assert ai["authorizedkeysfile"] == "none"
    assert ai["trustedusercakeys"] == f"/etc/ssh/sezam_ai_ca_{user}.pub"
    assert ai["allowagentforwarding"] == "no" and ai["allowtcpforwarding"] == "no"
    assert root["trustedusercakeys"] == "none"  # the CA is trusted for the AI account only
    assert os.stat("/var/www/site").st_gid == int(subprocess.check_output(["id", "-g", user]))
    assert user in open("/etc/cron.deny").read().split()
    reaper = f"/usr/local/sbin/sezam-ai-reap-{user}"
    assert open(f"/etc/cron.d/sezam-ai-reap-{user}").read() == f"* * * * * root {reaper}\n"
    assert os.stat(reaper).st_mode & 0o777 == 0o700

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    log = open(tmp_path / "sshd.log", "w")
    sshd = subprocess.Popen(
        [SSHD, "-D", "-e", "-p", str(port), "-o", "ListenAddress=127.0.0.1", "-o", "UsePAM=no"],
        stdout=log, stderr=log,
    )
    vault = Vault.create(tmp_path / "vault", "test", FAST_PARAMS)
    host_pub = open("/etc/ssh/ssh_host_ed25519_key.pub").read().split()
    host_blob = base64.b64decode(host_pub[1])
    folder = vault.create_node("Servers")
    fields = _entry(ca_pem, cert_ttl_minutes="1")["fields"]
    fields[0]["value"] = "127.0.0.1"
    fields += [{"key": "port", "value": str(port)}, {"key": "host_key_sha256", "value": host_key_fingerprint(host_blob)}]
    vault.create_entry(folder, "Web-AI", fields, tier=0, allowed_actions=["ssh_agent"])
    agent = SSHAgentServer(SSHAgentService(MCPBroker(vault, ApprovalManager())), default_endpoint())
    agent.start()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(f"[127.0.0.1]:{port} {host_pub[0]} {host_pub[1]}\n")

    def ssh_args(*options, command="id -un"):
        return [
            SSH, "-F", "/dev/null", "-p", str(port),
            "-o", f"UserKnownHostsFile={known_hosts}", "-o", "StrictHostKeyChecking=yes",
            "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
            "-o", "ConnectTimeout=10", "-o", "IdentityFile=/nonexistent", *options,
            f"{user}@127.0.0.1", command,
        ]

    def ssh(*options, command="id -un", agent_sock=agent.path):
        return subprocess.run(
            ssh_args(*options, command=command),
            env={**os.environ, "SSH_AUTH_SOCK": agent_sock}, capture_output=True, text=True, timeout=60,
        )

    def ai_processes():
        return subprocess.run(["pgrep", "-u", user, "-x", "sleep"], capture_output=True, text=True).stdout.split()

    held = None

    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        result = ssh()
        assert result.returncode == 0, result.stderr + (tmp_path / "sshd.log").read_text()
        assert result.stdout.strip() == user

        # What the AI leaves behind: a detached process and an open session.
        detached = ssh(command="setsid nohup sleep 3600 >/dev/null 2>&1 </dev/null &")
        assert detached.returncode == 0, detached.stderr
        held = subprocess.Popen(
            ssh_args(command="sleep 600"), env={**os.environ, "SSH_AUTH_SOCK": agent.path},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 20
        while len(ai_processes()) < 2 and time.monotonic() < deadline:
            time.sleep(0.2)
        assert len(ai_processes()) == 2
        opened = time.monotonic()

        # A key the AI adds to its own authorized_keys does not work.
        own = tmp_path / "own_key"
        own.write_text(_openssh(ed25519.Ed25519PrivateKey.generate()))
        own.chmod(0o600)
        pub = paramiko.Ed25519Key.from_private_key_file(str(own))
        ssh_dir = f"/home/{user}/.ssh"
        os.makedirs(ssh_dir, exist_ok=True)
        with open(f"{ssh_dir}/authorized_keys", "w") as f:
            f.write(f"ssh-ed25519 {pub.get_base64()}\n")
        subprocess.run(["chown", "-R", f"{user}:{user}", ssh_dir], check=True)
        refused = ssh("-o", f"IdentityFile={own}", "-o", "IdentitiesOnly=yes", agent_sock="/nonexistent")
        assert refused.returncode != 0

        # Kill switch: the CA stops signing.
        ai_access.disable(vault, "test")
        assert ssh().returncode != 0
        # The brake alone does not end them (Sezam cannot reach the server) ...
        assert len(ai_processes()) == 2 and held.poll() is None
        # ... the reaper (cron.d, run here directly) ends both once the
        # session is older than the TTL (1 minute).
        subprocess.run([reaper], check=True)
        assert len(ai_processes()) == 2 and held.poll() is None  # session still young
        time.sleep(max(0.0, 62 - (time.monotonic() - opened)))
        subprocess.run([reaper], check=True)
        held.wait(10)
        assert ai_processes() == []
        assert subprocess.run(["pgrep", "-u", user], capture_output=True).returncode == 1
    finally:
        if held is not None and held.poll() is None:
            held.kill()
        agent.stop()
        vault.lock()
        sshd.terminate()
        sshd.wait(10)
        log.close()
