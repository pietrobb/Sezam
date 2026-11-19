"""AI broker TODO section 6/5 (F1): the shared ``remote_root`` policy.

Every SFTP (and later FTP) path of an entry with ``remote_root`` must lie
under it: relative paths are taken relative to it, ``..`` is refused, and a
symbolic link below the root is never followed. Runs against the real
paramiko SFTP server from the P1 tests.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp import ssh as ssh_mod
from sezam.mcp.ssh import SSHBrokerError, SSHManager, _fingerprint
from sezam.vault.crud import Vault
from tests.test_ai_p1_local_root import (  # noqa: F401  (fixtures)
    FAST_PARAMS,
    MASTER,
    SSH_PASSWORD,
    _policy,
    cli_vault,
    home,
    no_user_known_hosts,
    sftp,
)


def _broker(tmp_path: Path, sftp, remote_root, actions=("ssh_download", "ssh_upload")):
    vault = Vault.create(tmp_path / "home" / ".sezam", MASTER, FAST_PARAMS)
    entry_id = vault.create_entry(
        vault.create_node("Servers"),
        "web",
        [
            {"key": "host", "value": "127.0.0.1"},
            {"key": "port", "value": str(sftp.port)},
            {"key": "username", "value": "deploy"},
            {"key": "password", "value": SSH_PASSWORD, "sensitive": True},
            {"key": "host_key_sha256", "value": _fingerprint(sftp.host_key)},
        ],
        tier=0,
        allowed_actions=list(actions),
    )
    vault.update_entry(entry_id, remote_root=remote_root)
    transfers = tmp_path / "transfers"
    return MCPBroker(vault, ApprovalManager(), SSHManager(transfer_root=transfers)), vault, transfers


def _symlink(link: Path, target: Path, is_dir: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")


# ── validation ──


def test_remote_root_policy_is_an_absolute_posix_path_without_dotdot():
    for bad in ("var/www", "", "/var/../etc", "/var/www/..", "C:\\www", "/a\nb", "/a\x00", 7, ["/a"]):
        with pytest.raises(SSHBrokerError) as exc:
            ssh_mod.validate_remote_root(bad)
        assert exc.value.code == "policy_invalid", bad
    assert ssh_mod.validate_remote_root("/var/www/./site/") == "/var/www/site"
    assert ssh_mod.validate_remote_root("//srv//site") == "/srv/site"
    assert ssh_mod.validate_remote_root("/") == "/"


def test_paths_are_confined_under_the_root():
    root = "/var/www/site"
    assert ssh_mod.confine_remote_path(root, "index.html") == "/var/www/site/index.html"
    assert ssh_mod.confine_remote_path(root, "./a//b/") == "/var/www/site/a/b"
    assert ssh_mod.confine_remote_path(root, "/var/www/site") == root
    assert ssh_mod.confine_remote_path(root, "/var/www/site/css/x.css") == "/var/www/site/css/x.css"
    for bad in ("/etc/passwd", "../site2/x", "a/../../x", "/var/www/site/../x", "/var/www/site2/x", "a\\..\\x"):
        with pytest.raises(SSHBrokerError) as exc:
            ssh_mod.confine_remote_path(root, bad)
        assert exc.value.code == "remote_path_denied", bad
    assert ssh_mod.confine_remote_path("/", "/etc/x") == "/etc/x"
    # Without a policy nothing changes.
    assert ssh_mod.confine_remote_path(None, "../x") == "../x"


# ── real SFTP ──


def test_download_outside_remote_root_is_refused(home, tmp_path, sftp):
    (sftp.root / "site").mkdir()
    (sftp.root / "site" / "index.html").write_bytes(b"<h1>ok</h1>")
    (sftp.root / "secret.txt").write_bytes(b"db password")
    broker, vault, transfers = _broker(tmp_path, sftp, "/site")

    ok = broker.ssh_download("Servers/web", "index.html", "index.html", agent_name="t")
    outside = broker.ssh_download("Servers/web", "/secret.txt", "secret.txt", agent_name="t")
    dotdot = broker.ssh_download("Servers/web", "../secret.txt", "secret2.txt", agent_name="t")

    assert ok["status"] == "ok", ok
    assert (transfers / "index.html").read_bytes() == b"<h1>ok</h1>"
    for result in (outside, dotdot):
        assert result["status"] == "error" and result["code"] == "remote_path_denied", result
    assert not (transfers / "secret.txt").exists() and not (transfers / "secret2.txt").exists()
    vault.lock()


def test_upload_outside_remote_root_is_refused(home, tmp_path, sftp):
    (sftp.root / "site").mkdir()
    broker, vault, transfers = _broker(tmp_path, sftp, "/site")
    transfers.mkdir()
    (transfers / "app.py").write_bytes(b"print(1)")

    ok = broker.ssh_upload("Servers/web", "app.py", "app.py", agent_name="t")
    outside = broker.ssh_upload("Servers/web", "app.py", "/cron/app.py", agent_name="t")
    sibling = broker.ssh_upload("Servers/web", "app.py", "/site2/app.py", agent_name="t")

    assert ok["status"] == "ok", ok
    assert (sftp.root / "site" / "app.py").read_bytes() == b"print(1)"
    for result in (outside, sibling):
        assert result["status"] == "error" and result["code"] == "remote_path_denied", result
    assert not (sftp.root / "cron").exists() and not (sftp.root / "site2").exists()
    vault.lock()


def test_symlink_below_remote_root_is_not_followed(home, tmp_path, sftp):
    (sftp.root / "site").mkdir()
    (sftp.root / "keys").mkdir()
    (sftp.root / "keys" / "id").write_bytes(b"PRIVATE")
    _symlink(sftp.root / "site" / "link", sftp.root / "keys", is_dir=True)
    broker, vault, transfers = _broker(tmp_path, sftp, "/site")
    transfers.mkdir()
    (transfers / "x").write_bytes(b"attacker")

    down = broker.ssh_download("Servers/web", "link/id", "id", agent_name="t")
    up = broker.ssh_upload("Servers/web", "x", "link/x", agent_name="t")

    assert down["status"] == "error" and down["code"] == "symlink_denied", down
    assert up["status"] == "error" and up["code"] == "symlink_denied", up
    assert not (transfers / "id").exists()
    assert not (sftp.root / "keys" / "x").exists()
    vault.lock()


def test_upload_never_overwrites_through_a_remote_symlink(home, tmp_path, sftp):
    (sftp.root / "authorized_keys").write_bytes(b"original")
    _symlink(sftp.root / "config", sftp.root / "authorized_keys")
    broker, vault, transfers = _broker(tmp_path, sftp, None)
    transfers.mkdir()
    (transfers / "config").write_bytes(b"ssh-ed25519 ATTACKER")

    result = broker.ssh_upload("Servers/web", "config", "/config", overwrite=True, agent_name="t")

    assert result["status"] == "error" and result["code"] == "symlink_denied", result
    assert (sftp.root / "authorized_keys").read_bytes() == b"original"
    vault.lock()


def test_invalid_remote_root_policy_fails_closed(home, tmp_path, sftp):
    (sftp.root / "secret.txt").write_bytes(b"db password")
    broker, vault, transfers = _broker(tmp_path, sftp, "site/../..")

    result = broker.ssh_download("Servers/web", "/secret.txt", "secret.txt", agent_name="t")

    assert result["status"] == "error" and result["code"] == "policy_invalid", result
    assert not (transfers / "secret.txt").exists()
    assert {r["path"]: r for r in broker.access_overview()}["Servers/web"]["remote_root"] == "invalid"
    vault.lock()


# ── CLI and overview ──


def test_cli_mcp_policy_sets_validates_and_clears_remote_root(cli_vault):
    run = lambda *args: CliRunner().invoke(  # noqa: E731
        cli.main, ["mcp-policy", "Servers/web", *args], input=MASTER + "\n"
    )

    assert run("--remote-root", "/var/www/./site/").exit_code == 0
    assert _policy(cli_vault)["remote_root"] == "/var/www/site"

    for bad in ("var/www", "/var/www/../../etc", "C:\\www"):
        result = run("--remote-root", bad)
        assert result.exit_code != 0, bad
        assert _policy(cli_vault)["remote_root"] == "/var/www/site"

    assert run("--remote-root", "/a", "--clear-remote-root").exit_code != 0
    assert run("--clear-remote-root").exit_code == 0
    assert _policy(cli_vault)["remote_root"] is None


def test_overview_and_ai_status_show_remote_root(cli_vault, monkeypatch):
    vault = Vault(cli_vault)
    vault.unlock(MASTER)
    try:
        entry = vault.find_entry_by_path("Servers/web")
        vault.update_entry(
            entry["id"], tier=0, allowed_actions=["ssh_upload"], remote_root="/srv/site"
        )
        rows = {r["path"]: r for r in MCPBroker(vault, ApprovalManager()).access_overview()}
    finally:
        vault.lock()
    assert rows["Servers/web"]["remote_root"] == "/srv/site"

    stored: dict = {}
    monkeypatch.setitem(
        sys.modules,
        "keyring",
        types.SimpleNamespace(
            set_password=lambda s, a, p: stored.update({(s, a): p}),
            get_password=lambda s, a: stored.get((s, a)),
            delete_password=lambda s, a: stored.pop((s, a), None),
        ),
    )
    monkeypatch.setattr(cli, "_attempt_tracker_path", lambda: cli_vault / "attempts.json")
    assert CliRunner().invoke(cli.main, ["unlock"], input=MASTER + "\n").exit_code == 0
    out = CliRunner().invoke(cli.main, ["ai", "status"]).output
    assert "REMOTE_ROOT" in out
    assert "/srv/site" in next(ln for ln in out.splitlines() if "Servers/web" in ln)
