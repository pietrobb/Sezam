"""AI broker TODO section 6 (F2): FTPManager against a real pyftpdlib server.

TLS is mandatory unless the entry says ``allow_plain_ftp: true``: explicit
FTPS (AUTH TLS before USER/PASS, PROT P), implicit FTPS, certificate and
host name verification. Whenever TLS cannot be set up the password is never
sent. Paths share the transfer policies of the SSH tools.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import socket
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

pytest.importorskip("OpenSSL")
pyftpdlib = pytest.importorskip("pyftpdlib")

from pyftpdlib.authorizers import DummyAuthorizer  # noqa: E402
from pyftpdlib.handlers import FTPHandler, ThrottledDTPHandler, TLS_FTPHandler  # noqa: E402
from pyftpdlib.servers import ThreadedFTPServer  # noqa: E402

from sezam.mcp import ftp as ftp_mod  # noqa: E402
from sezam.mcp.ssh import SSHBrokerError  # noqa: E402

FTP_PASSWORD = "f2-ftp-password"


# ── certificates ──


def _certificate(tmp_path: Path, name: str, *, san_ip: str = "127.0.0.1", dns: str = "localhost"):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)])
    now = datetime.datetime.now(datetime.timezone.utc)
    alt = [x509.DNSName(dns)]
    if san_ip:
        alt.append(x509.IPAddress(ipaddress.ip_address(san_ip)))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path = tmp_path / f"{name}.pem"
    path.write_bytes(cert_pem + key_pem)
    return path, cert_pem.decode()


# ── server ──


class _Server:
    def __init__(
        self, tmp_path: Path, mode: str, certfile: Path | None = None, *, mlst: bool = True,
        throttle: int = 0,
    ):
        self.home = tmp_path / f"ftp-{mode}-{mlst}"
        self.home.mkdir()
        self.commands: list[tuple[str, bool]] = []
        commands = self.commands
        authorizer = DummyAuthorizer()
        authorizer.add_user("deploy", FTP_PASSWORD, str(self.home), perm="elradfmwMT")

        if mode == "plain":
            base = FTPHandler
        else:
            base = TLS_FTPHandler

        class Handler(base):
            def process_command(self, cmd, *args, **kwargs):
                commands.append((cmd, bool(getattr(self, "_ssl_established", False))))
                return super().process_command(cmd, *args, **kwargs)

            def ftp_MLST(self, path):
                # Like ProFTPD/Pure-FTPd: a directory named "link" is
                # reported as the symbolic link it stands for.
                if os.path.basename(path) == "link":
                    name = self.fs.fs2ftp(path)
                    self.push(f'250-Listing "{name}":\r\n type=OS.unix=slink:/private; {name}\r\n')
                    self.respond("250 End MLST.")
                    return None
                return super().ftp_MLST(path)

        if throttle:
            dtp = type("SlowDTP", (ThrottledDTPHandler,), {"read_limit": throttle, "write_limit": throttle})
            Handler.dtp_handler = dtp
        if not mlst:  # like vsftpd
            Handler.proto_cmds = {
                k: v for k, v in base.proto_cmds.items() if k not in ("MLST", "MLSD")
            }
        Handler.authorizer = authorizer
        Handler.banner = "sezam test ftp"
        if mode != "plain":
            Handler.certfile = str(certfile)
            Handler.ssl_context = None
            Handler.tls_control_required = True
            Handler.tls_data_required = True
        handler = Handler
        if mode == "implicit":

            class Implicit(Handler):
                """TLS from the first byte, then the usual 220 banner."""

                def handle(self):
                    self.secure_connection(self.ssl_context)

                def handle_ssl_established(self):
                    Handler.handle(self)

            handler = Implicit

        self.server = ThreadedFTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.socket.getsockname()[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"timeout": 0.2, "handle_exit": False}, daemon=True
        )
        self.thread.start()

    def saw(self, cmd: str) -> bool:
        return any(c == cmd for c, _ in self.commands)

    def close(self):
        self.server.close_all()


@pytest.fixture
def cert(tmp_path):
    return _certificate(tmp_path, "server")


@pytest.fixture
def explicit(tmp_path, cert):
    server = _Server(tmp_path, "explicit", cert[0])
    yield server
    server.close()


@pytest.fixture
def implicit(tmp_path, cert):
    server = _Server(tmp_path, "implicit", cert[0])
    yield server
    server.close()


@pytest.fixture
def plain(tmp_path):
    server = _Server(tmp_path, "plain")
    yield server
    server.close()


@pytest.fixture
def transfers(tmp_path):
    root = tmp_path / "transfers"
    root.mkdir()
    return root


def _entry(server: _Server, *, ca: str | None = None, **extra) -> dict:
    fields = [
        {"key": "host", "value": "127.0.0.1"},
        {"key": "port", "value": str(server.port)},
        {"key": "username", "value": "deploy"},
        {"key": "password", "value": FTP_PASSWORD, "sensitive": True},
    ]
    if ca:
        fields.append({"key": "tls_ca_cert", "value": ca})
    fields += [{"key": k, "value": v} for k, v in extra.items()]
    return {"id": "e1", "name": "web", "fields": fields}


def _manager(transfers: Path, **kwargs) -> ftp_mod.FTPManager:
    return ftp_mod.FTPManager(transfer_root=transfers, connect_timeout=5, operation_timeout=5, **kwargs)


def _code(call) -> str:
    with pytest.raises(SSHBrokerError) as exc:
        call()
    return exc.value.code


# ── TLS ──


def test_explicit_ftps_round_trip_encrypts_login_and_data(explicit, cert, transfers):
    manager = _manager(transfers)
    entry = _entry(explicit, ca=cert[1])
    (transfers / "index.html").write_bytes(b"<h1>site</h1>")

    up = manager.upload(entry, "index.html", "site/index.html")
    listing = manager.list(entry, "site")
    down = manager.download(entry, "site/index.html", "copy.html")

    assert up == {"status": "ok", "files": 1, "bytes": 13}
    assert (explicit.home / "site" / "index.html").read_bytes() == b"<h1>site</h1>"
    assert listing["entries"] == [
        {**listing["entries"][0], "name": "index.html", "type": "file", "size": 13}
    ]
    assert down["status"] == "ok" and (transfers / "copy.html").read_bytes() == b"<h1>site</h1>"
    assert "warning" not in up
    # AUTH came first; USER and PASS only on the encrypted control channel.
    assert explicit.commands[0] == ("AUTH", False)
    assert all(tls for cmd, tls in explicit.commands if cmd in ("USER", "PASS"))
    assert explicit.saw("PROT")


def test_implicit_ftps(implicit, cert, transfers):
    manager = _manager(transfers)
    entry = _entry(implicit, ca=cert[1], ftps_mode="implicit")
    (transfers / "a.txt").write_bytes(b"a")

    assert manager.upload(entry, "a.txt", "a.txt")["status"] == "ok"
    assert (implicit.home / "a.txt").read_bytes() == b"a"
    assert not implicit.saw("AUTH")
    assert all(tls for cmd, tls in implicit.commands if cmd == "PASS")


def test_server_without_tls_is_refused_before_the_password(plain, transfers):
    code = _code(lambda: _manager(transfers).list(_entry(plain), "/"))

    assert code == "tls_unavailable"
    assert not plain.saw("USER") and not plain.saw("PASS")


def test_untrusted_certificate_is_refused_before_the_password(explicit, transfers):
    code = _code(lambda: _manager(transfers).list(_entry(explicit), "/"))

    assert code == "tls_verify_failed"
    assert not explicit.saw("PASS")


def test_certificate_for_another_host_is_refused(tmp_path, transfers):
    certfile, ca = _certificate(tmp_path, "other", san_ip="", dns="other.example")
    server = _Server(tmp_path, "explicit", certfile)
    try:
        code = _code(lambda: _manager(transfers).list(_entry(server, ca=ca), "/"))
    finally:
        server.close()

    assert code == "tls_verify_failed"
    assert not server.saw("PASS")


def test_implicit_mode_against_an_explicit_server_fails_closed(explicit, cert, transfers):
    entry = _entry(explicit, ca=cert[1], ftps_mode="implicit")

    assert _code(lambda: _manager(transfers).list(entry, "/")) in {
        "tls_failed", "connection_failed", "timeout"
    }
    assert not explicit.saw("PASS")


def test_plain_ftp_only_with_allow_plain_ftp_and_always_warned(plain, transfers):
    manager = _manager(transfers)
    (transfers / "a.txt").write_bytes(b"a")

    result = manager.upload(_entry(plain, allow_plain_ftp="true"), "a.txt", "a.txt")

    assert result["status"] == "ok"
    assert result["warning"] == ftp_mod.PLAIN_FTP_WARNING
    assert "unencrypted" in result["warning"]


@pytest.mark.parametrize(
    "extra",
    [
        {"allow_plain_ftp": "true", "ftps_mode": "explicit"},
        {"allow_plain_ftp": "maybe"},
        {"ftps_mode": "none"},
        {"ftps_mode": "plain"},
        {"tls_ca_cert": "not a certificate"},
    ],
)
def test_malformed_tls_settings_refuse_the_entry(explicit, transfers, extra):
    assert _code(lambda: _manager(transfers).list(_entry(explicit, **extra), "/")) == "invalid_entry"
    assert explicit.commands == [] or not explicit.saw("PASS")


def test_credentials_with_line_breaks_are_refused(explicit, cert, transfers):
    entry = _entry(explicit, ca=cert[1])
    entry["fields"][3]["value"] = FTP_PASSWORD + "\r\nDELE x"

    assert _code(lambda: _manager(transfers).list(entry, "/")) == "invalid_entry"
    assert repr(ftp_mod.FTPCredentials.from_entry(_entry(explicit))).count(FTP_PASSWORD) == 0


def test_paths_with_line_breaks_cannot_inject_commands(explicit, cert, transfers):
    entry = _entry(explicit, ca=cert[1])

    assert _code(lambda: _manager(transfers).delete(entry, "a.txt\r\nRMD /")) == "invalid_request"
    assert not explicit.saw("RMD")


def test_connect_times_out_when_the_server_never_answers(transfers):
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen(1)
    entry = {
        "fields": [
            {"key": "host", "value": "127.0.0.1"},
            {"key": "port", "value": str(silent.getsockname()[1])},
            {"key": "username", "value": "deploy"},
            {"key": "password", "value": FTP_PASSWORD},
        ]
    }
    started = time.monotonic()
    try:
        code = _code(lambda: ftp_mod.FTPManager(transfer_root=transfers, connect_timeout=1).list(entry, "/"))
    finally:
        silent.close()

    assert code == "timeout"
    assert time.monotonic() - started < 5


# ── operations and shared policies ──


def test_mkdir_rename_delete(explicit, cert, transfers):
    manager = _manager(transfers)
    entry = _entry(explicit, ca=cert[1])
    (transfers / "a.txt").write_bytes(b"a")

    assert manager.mkdir(entry, "/site/css/old")["status"] == "ok"
    assert (explicit.home / "site" / "css" / "old").is_dir()
    manager.upload(entry, "a.txt", "/site/a.txt")
    manager.upload(entry, "a.txt", "/site/b.txt")

    assert _code(lambda: manager.rename(entry, "/site/a.txt", "/site/b.txt")) == "destination_exists"
    assert manager.rename(entry, "/site/a.txt", "/site/c.txt")["status"] == "ok"
    assert (explicit.home / "site" / "c.txt").exists() and not (explicit.home / "site" / "a.txt").exists()

    assert manager.delete(entry, "/site/c.txt") == {
        "status": "ok", "deleted": "/site/c.txt", "type": "file"
    }
    assert manager.delete(entry, "/site/css/old")["type"] == "dir"
    # Never recursive: a non-empty directory stays.
    assert _code(lambda: manager.delete(entry, "/site")) == "ftp_refused"
    assert (explicit.home / "site" / "b.txt").exists()
    assert _code(lambda: manager.delete(entry, "/missing")) == "remote_not_found"


def test_upload_never_overwrites_without_overwrite(explicit, cert, transfers):
    manager = _manager(transfers)
    entry = _entry(explicit, ca=cert[1])
    (explicit.home / "a.txt").write_bytes(b"original")
    (transfers / "a.txt").write_bytes(b"new")

    assert _code(lambda: manager.upload(entry, "a.txt", "a.txt")) == "destination_exists"
    assert (explicit.home / "a.txt").read_bytes() == b"original"
    assert manager.upload(entry, "a.txt", "a.txt", overwrite=True)["status"] == "ok"
    assert (explicit.home / "a.txt").read_bytes() == b"new"


def test_recursive_transfers(explicit, cert, transfers):
    manager = _manager(transfers)
    entry = _entry(explicit, ca=cert[1])
    (transfers / "site" / "css").mkdir(parents=True)
    (transfers / "site" / "index.html").write_bytes(b"i")
    (transfers / "site" / "css" / "a.css").write_bytes(b"cc")

    assert _code(lambda: manager.upload(entry, "site", "/site")) == "recursive_required"
    up = manager.upload(entry, "site", "/site", recursive=True)
    down = manager.download(entry, "/site", "back", recursive=True)

    assert up == {"status": "ok", "files": 2, "bytes": 3}
    assert down == {"status": "ok", "files": 2, "bytes": 3}
    assert (transfers / "back" / "css" / "a.css").read_bytes() == b"cc"


def test_remote_root_confines_every_operation(explicit, cert, transfers):
    manager = _manager(transfers)
    entry = _entry(explicit, ca=cert[1])
    (explicit.home / "site").mkdir()
    (explicit.home / "secret.txt").write_bytes(b"db password")
    (transfers / "a.txt").write_bytes(b"a")
    root = "/site"

    for call in (
        lambda: manager.download(entry, "/secret.txt", "s.txt", remote_root=root),
        lambda: manager.download(entry, "../secret.txt", "s.txt", remote_root=root),
        lambda: manager.upload(entry, "a.txt", "/a.txt", remote_root=root),
        lambda: manager.delete(entry, "/secret.txt", remote_root=root),
        lambda: manager.mkdir(entry, "/other", remote_root=root),
        lambda: manager.rename(entry, "a.txt", "/moved.txt", remote_root=root),
        lambda: manager.list(entry, "/", remote_root=root),
        lambda: manager.delete(entry, "/site", remote_root=root),
    ):
        assert _code(call) == "remote_path_denied"
    assert not (transfers / "s.txt").exists()
    assert (explicit.home / "secret.txt").exists() and not (explicit.home / "other").exists()

    assert manager.upload(entry, "a.txt", "a.txt", remote_root=root)["status"] == "ok"
    assert (explicit.home / "site" / "a.txt").read_bytes() == b"a"


def test_link_reported_by_the_server_below_remote_root_is_refused(explicit, cert, transfers):
    (explicit.home / "site" / "link").mkdir(parents=True)
    (explicit.home / "site" / "link" / "key").write_bytes(b"PRIVATE")
    (transfers / "x").write_bytes(b"x")
    manager = _manager(transfers)
    entry = _entry(explicit, ca=cert[1])

    for call in (
        lambda: manager.download(entry, "link/key", "key", remote_root="/site"),
        lambda: manager.upload(entry, "x", "link/x", remote_root="/site"),
        lambda: manager.delete(entry, "link/key", remote_root="/site"),
        lambda: manager.list(entry, "link", remote_root="/site"),
    ):
        assert _code(call) == "symlink_denied"
    assert not (transfers / "key").exists()
    assert sorted(p.name for p in (explicit.home / "site" / "link").iterdir()) == ["key"]


def test_server_without_mlst_falls_back_to_size_and_cwd(tmp_path, cert, transfers):
    server = _Server(tmp_path, "explicit", cert[0], mlst=False)
    try:
        manager = _manager(transfers)
        entry = _entry(server, ca=cert[1])
        (transfers / "site" / "css").mkdir(parents=True)
        (transfers / "site" / "index.html").write_bytes(b"i")
        (transfers / "site" / "css" / "a.css").write_bytes(b"cc")

        assert manager.upload(entry, "site", "/site", recursive=True)["files"] == 2
        assert _code(lambda: manager.upload(entry, "site/index.html", "/site/index.html")) == (
            "destination_exists"
        )
        listing = {e["name"]: e["type"] for e in manager.list(entry, "/site")["entries"]}
        down = manager.download(entry, "/site", "back", recursive=True)
        deleted = manager.delete(entry, "/site/css/a.css")
    finally:
        server.close()

    assert server.saw("NLST") and server.saw("SIZE")
    assert listing == {"index.html": "file", "css": "dir"}
    assert down == {"status": "ok", "files": 2, "bytes": 3}
    assert deleted["type"] == "file" and not (server.home / "site" / "css" / "a.css").exists()


def test_close_all_cuts_a_running_transfer(tmp_path, transfers):
    server = _Server(tmp_path, "plain", throttle=32 * 1024)
    (server.home / "big.bin").write_bytes(b"z" * (2 * 1024 * 1024))
    manager = _manager(transfers)
    outcome: dict = {}

    def download():
        try:
            outcome["result"] = manager.download(
                _entry(server, allow_plain_ftp="true"), "big.bin", "big.bin"
            )
        except SSHBrokerError as exc:
            outcome["code"] = exc.code

    worker = threading.Thread(target=download)
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while not (transfers / "big.bin").exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(0.3)
        assert manager.active_count() == 1
        started = time.monotonic()
        manager.close_all()
        worker.join(5)
    finally:
        server.close()

    assert not worker.is_alive()
    assert time.monotonic() - started < 5
    assert "result" not in outcome
    assert outcome["code"] == "cut_off"
    assert manager.active_count() == 0


def test_local_paths_stay_inside_the_transfer_root(explicit, cert, transfers, tmp_path):
    manager = _manager(transfers)
    entry = _entry(explicit, ca=cert[1])
    (explicit.home / "a.txt").write_bytes(b"a")

    assert _code(lambda: manager.download(entry, "a.txt", "../evil.txt")) == "local_path_denied"
    assert _code(lambda: manager.download(entry, "a.txt", str(tmp_path / "x"))) == "local_path_denied"
    assert not (tmp_path / "evil.txt").exists()
    (transfers / "a.txt").write_bytes(b"local")
    assert _code(lambda: manager.download(entry, "a.txt", "a.txt")) == "destination_exists"
    assert (transfers / "a.txt").read_bytes() == b"local"


def test_size_limit_applies_both_ways(explicit, cert, transfers):
    manager = _manager(transfers, max_transfer_bytes=10)
    entry = _entry(explicit, ca=cert[1])
    (transfers / "big.bin").write_bytes(b"x" * 11)
    (explicit.home / "big.bin").write_bytes(b"y" * 4096)

    assert _code(lambda: manager.upload(entry, "big.bin", "up.bin")) == "transfer_too_large"
    assert not (explicit.home / "up.bin").exists()
    assert _code(lambda: manager.download(entry, "big.bin", "down.bin")) == "transfer_too_large"
    assert (transfers / "down.bin").stat().st_size <= 10
