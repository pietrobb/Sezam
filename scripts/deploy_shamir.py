"""Deploy Shamir Secret Sharing feature to production server.

Uploads changed files (server + web) and rebuilds the sezam-api container.

Usage:
    python scripts/deploy_shamir.py
"""

import os
import shlex
import sys

import paramiko

# Change to project root
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.getcwd())

from scripts.deploy_files import tracked_deploy_files  # noqa: E402

SERVER = os.environ.get("SEZAM_SSH_HOST")
USER = os.environ.get("SEZAM_SSH_USER", "root")
SSH_PASSWORD = os.environ.get("SEZAM_SSH_PASSWORD")
DEPLOY_DIR = os.environ.get("SEZAM_DEPLOY_DIR", "/root/sezam")
PORT = os.environ.get("SEZAM_PORT", "8000")

FILES = tracked_deploy_files(DEPLOY_DIR)


def run_remote(ssh, command: str, timeout: int, input_data: str | None = None) -> str:
    """Run one remote step and abort deployment on any non-zero exit."""
    stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    if input_data is not None:
        stdin.write(input_data)
        stdin.channel.shutdown_write()
    out = stdout.read().decode()
    err = stderr.read().decode()
    exit_code = stdout.channel.recv_exit_status()
    if out.strip():
        print("  STDOUT:", out.strip())
    if err.strip():
        print("  STDERR:", err.strip())
    if exit_code != 0:
        raise RuntimeError(f"Remote command failed with exit {exit_code}: {command}")
    return out.strip()


def main():
    if not SERVER:
        raise RuntimeError("SEZAM_SSH_HOST must explicitly name the deployment target")
    print(f"Connecting to {SERVER}...")
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    if known_hosts := os.environ.get("SEZAM_SSH_KNOWN_HOSTS"):
        ssh.load_host_keys(os.path.expanduser(known_hosts))
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    ssh.connect(
        SERVER, port=22, username=USER, password=SSH_PASSWORD,
        timeout=30, look_for_keys=True, allow_agent=True,
    )
    print("Connected.")

    remote_dirs = sorted({os.path.dirname(path) for path in FILES.values()})
    run_remote(
        ssh,
        "mkdir -p " + " ".join(shlex.quote(path) for path in remote_dirs),
        timeout=30,
    )
    sftp = ssh.open_sftp()

    for local, remote in FILES.items():
        sftp.put(local, remote)
        print(f"  Uploaded: {local} -> {remote}")

    sftp.close()
    print("\nAll files uploaded.")

    print("\nRebuilding and starting the tracked deployment...")
    deploy_dir = shlex.quote(DEPLOY_DIR)
    run_remote(
        ssh,
        f"cd {deploy_dir} && docker compose up -d --build --wait sezam-api",
        timeout=300,
    )

    print("\nVerifying API health...")
    health = run_remote(
        ssh,
        "curl --fail --silent --show-error "
        + shlex.quote(f"http://127.0.0.1:{PORT}/health"),
        timeout=30,
    )
    print(f"  Health: {health}")

    ssh.close()
    print("\nDeploy complete!")


if __name__ == "__main__":
    main()
