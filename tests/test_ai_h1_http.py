"""AI broker TODO section 9 (H1): HTTPManager against a real local HTTPS server.

The broker inserts the entry's auth header, calls only the base URL's host
with an allowed method and path prefix, never follows a redirect, limits
size and time, verifies TLS and redacts the entry's secrets from what the
agent gets back.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sezam.mcp import http_api
from sezam.mcp.http_api import HTTPManager, HTTPTarget
from sezam.mcp.ssh import SSHBrokerError

TOKEN = "h1-api-token-7f3c9a"
APP_PASSWORD = "abcd EFGH 1234 ijkl"


def _certificate(tmp_path: Path, name: str, dns: str = "localhost", ip: str = "127.0.0.1"):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)])
    now = datetime.datetime.now(datetime.timezone.utc)
    alt = [x509.DNSName(dns)] + ([x509.IPAddress(ipaddress.ip_address(ip))] if ip else [])
    cert = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    path = tmp_path / f"{name}.pem"
    path.write_bytes(cert_pem + key_pem)
    return path, cert_pem.decode()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _record(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.seen.append({
            "method": self.command, "path": self.path,
            "headers": dict(self.headers.items()), "body": body,
        })
        return body

    def _send(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        self._record()
        path = self.path.split("?")[0]
        auth = self.headers.get("Authorization", "")
        if path.endswith("/echo"):
            body = json.dumps({"path": self.path, "auth": auth, "method": self.command}).encode()
            self._send(200, body, [("Content-Type", "application/json"), ("Set-Cookie", "sid=" + TOKEN),
                                   ("X-Internal", TOKEN), ("ETag", '"v1"')])
        elif path.endswith("/redirect"):
            self._send(302, b"", [("Location", f"https://evil.example/steal?t={TOKEN}")])
        elif path.endswith("/big"):
            self._send(200, b"a" * 5000 + TOKEN.encode() + b"z" * 100)
        elif path.endswith("/short"):
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"only ten b")
            self.close_connection = True
        elif path.endswith("/slow"):
            time.sleep(3)
            self._send(200, b"late")
        elif path.endswith("/trickle-header"):
            # Every byte comes well within the socket timeout, the whole
            # response does not come within the deadline.
            self._trickle(b"HTTP/1.1 200 OK\r\nX-A: ", b"a", b"\r\nContent-Length: 0\r\n\r\n")
        elif path.endswith("/trickle-chunk"):
            self._trickle(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;x=", b"a",
                          b"\r\nz\r\n0\r\n\r\n")
        else:
            self._send(404, b"nope")

    def _trickle(self, head, byte, tail, seconds=4.0):
        self.close_connection = True
        try:
            self.wfile.write(head)
            end = time.monotonic() + seconds
            while time.monotonic() < end:
                time.sleep(0.2)
                self.wfile.write(byte)
            self.wfile.write(tail)
        except OSError:
            pass  # client gave up: what the deadline is for

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = _handle


class _Server:
    def __init__(self, tmp_path: Path, tls: bool = True, cert=None):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.daemon_threads = True
        self.httpd.handle_error = lambda *args: None  # client gone (timeout / cut-off tests)
        self.httpd.seen = []
        self.ca_pem = None
        if tls:
            certfile, self.ca_pem = cert or _certificate(tmp_path, "srv")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile)
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.scheme = "https" if tls else "http"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def seen(self):
        return self.httpd.seen

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def https(tmp_path):
    server = _Server(tmp_path)
    yield server
    server.close()


def _entry(server, **extra):
    fields = {
        "base_url": f"{server.scheme}://127.0.0.1:{server.port}/wp-json",
        "auth_header": "Authorization: Bearer {token}",
        "token": TOKEN,
        "allowed_methods": "GET, POST",
        "allowed_path_prefixes": "/wp/v2 /sezam",
    }
    if server.ca_pem:
        fields["tls_ca_cert"] = server.ca_pem
    fields.update(extra)
    return {"fields": [{"key": k, "value": v} for k, v in fields.items() if v is not None]}


def _no_secret(result) -> None:
    text = json.dumps(result)
    assert TOKEN not in text and APP_PASSWORD not in text


def _manager(**kwargs) -> HTTPManager:
    return HTTPManager(**kwargs)


# ── requests ──


def test_get_inserts_the_auth_header_and_redacts_it_from_the_response(https):
    result = _manager().request(_entry(https), "GET", "/wp/v2/echo?page=2")
    assert result["http_status"] == 200
    assert https.seen[0]["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert https.seen[0]["path"] == "/wp-json/wp/v2/echo?page=2"
    body = json.loads(result["body"])
    assert body["auth"] == "[REDACTED]"
    # Only allowlisted response headers; never Set-Cookie or unknown ones.
    assert result["headers"]["ETag"] == '"v1"'
    assert "Set-Cookie" not in result["headers"] and "X-Internal" not in result["headers"]
    _no_secret(result)


def test_basic_auth_from_username_and_application_password(https):
    entry = _entry(https, auth_header="Authorization: Basic {basic}", token=None)
    entry["fields"] += [{"key": "username", "value": "editor"},
                        {"key": "password", "value": APP_PASSWORD}]
    result = _manager().request(entry, "GET", "/wp/v2/echo")
    sent = https.seen[0]["headers"]["Authorization"]
    import base64
    assert base64.b64decode(sent.split()[1]).decode() == f"editor:{APP_PASSWORD}"
    assert json.loads(result["body"])["auth"] == "[REDACTED]"
    assert sent.split()[1] not in json.dumps(result)
    _no_secret(result)


def test_post_body_and_agent_headers(https):
    result = _manager().request(
        _entry(https), "POST", "/wp/v2/echo", body='{"title":"x"}',
        headers={"content-type": "application/json", "Accept": "application/json"},
    )
    seen = https.seen[0]
    assert result["http_status"] == 200 and seen["body"] == b'{"title":"x"}'
    assert seen["headers"]["Content-Type"] == "application/json"


@pytest.mark.parametrize("name", ["Authorization", "Host", "Cookie", "X-Forwarded-For"])
def test_agent_cannot_set_other_headers(https, name):
    with pytest.raises(SSHBrokerError) as err:
        _manager().request(_entry(https), "GET", "/wp/v2/echo", headers={name: "x"})
    assert err.value.code == "header_denied" and https.seen == []


def test_method_outside_the_allowlist_is_refused_before_connecting(https):
    with pytest.raises(SSHBrokerError) as err:
        _manager().request(_entry(https), "DELETE", "/wp/v2/echo")
    assert err.value.code == "method_denied" and https.seen == []


def test_default_methods_are_get_only(https):
    entry = _entry(https, allowed_methods=None)
    assert _manager().request(entry, "GET", "/wp/v2/echo")["http_status"] == 200
    with pytest.raises(SSHBrokerError, match="POST"):
        _manager().request(entry, "POST", "/wp/v2/echo")


@pytest.mark.parametrize("path", [
    "/wp/v2x/echo", "/admin/echo", "/wp/v2/../../admin", "/wp/v2/%2e%2e/admin",
    "/wp/v2/%2fadmin", "/wp//v2/echo", "wp/v2/echo", "/wp/v2/echo#x", "/wp/v2\\echo",
    "/wp/v2/ echo", "/wp/v2/./echo", "", "/wp/v2/echo?a=\r\nX: y",
])
def test_paths_outside_the_prefixes_or_ambiguous_are_refused(https, path):
    with pytest.raises(SSHBrokerError) as err:
        _manager().request(_entry(https), "GET", path)
    assert err.value.code in ("path_denied", "invalid_path")
    assert https.seen == []


def test_prefix_slash_allows_everything_below_the_base(https):
    entry = _entry(https, allowed_path_prefixes="/")
    assert _manager().request(entry, "GET", "/any/echo")["http_status"] == 200
    assert https.seen[0]["path"] == "/wp-json/any/echo"


def test_redirect_is_not_followed_and_its_location_is_redacted(https):
    result = _manager().request(_entry(https), "GET", "/wp/v2/redirect")
    assert result["http_status"] == 302 and result["redirect_not_followed"]
    assert result["headers"]["Location"] == "https://evil.example/steal?t=[REDACTED]"
    assert len(https.seen) == 1
    _no_secret(result)


def test_response_is_cut_at_the_limit_with_a_secret_on_the_cut(https):
    manager = _manager(max_response_bytes=5000 + len(TOKEN) // 2)
    result = manager.request(_entry(https), "GET", "/wp/v2/big")
    assert result["truncated"]
    assert result["body"].endswith("a[REDACTED]")
    _no_secret(result)
    full = _manager().request(_entry(https), "GET", "/wp/v2/big")
    assert not full["truncated"] and "[REDACTED]" in full["body"]


def test_request_body_limit(https):
    with pytest.raises(SSHBrokerError) as err:
        _manager(max_request_bytes=10).request(_entry(https), "POST", "/wp/v2/echo", body="x" * 11)
    assert err.value.code == "request_too_large" and https.seen == []


def test_timeout(https):
    with pytest.raises(SSHBrokerError) as err:
        _manager(timeout=0.5).request(_entry(https), "GET", "/wp/v2/slow")
    assert err.value.code == "timeout"


def _assert_deadline(call, seconds=1.0):
    started = time.monotonic()
    with pytest.raises(SSHBrokerError) as err:
        call()
    elapsed = time.monotonic() - started
    assert err.value.code == "timeout", err.value.code
    assert elapsed < seconds + 0.7, f"call ran {elapsed:.1f} s past a {seconds} s deadline"


@pytest.mark.parametrize("path", ["/wp/v2/trickle-header", "/wp/v2/trickle-chunk"])
def test_deadline_covers_a_trickled_response(https, path):
    # One byte per 0.2 s never trips the 1 s socket timeout; the deadline
    # for the whole call must still end it.
    manager = _manager(timeout=1.0)
    _assert_deadline(lambda: manager.request(_entry(https), "GET", path))
    assert manager.active_count() == 0


def test_deadline_covers_a_trickled_tls_handshake(tmp_path):
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        conn, _ = listener.accept()
        with conn:
            try:
                conn.sendall(b"\x16\x03\x03\x40\x00")  # a 16 KiB handshake record...
                while not stop.wait(0.2):
                    conn.sendall(b"\x00")  # ...arriving one byte at a time
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    server = type("S", (), {"scheme": "https", "port": port, "ca_pem": _certificate(tmp_path, "hs")[1]})
    try:
        _assert_deadline(lambda: _manager(timeout=1.0).request(_entry(server), "GET", "/wp/v2/echo"))
    finally:
        stop.set()
        listener.close()
        thread.join(3)


def test_close_all_cuts_a_running_request(https):
    manager = _manager(timeout=10)
    errors = []

    def run():
        try:
            manager.request(_entry(https), "GET", "/wp/v2/slow")
        except SSHBrokerError as exc:
            errors.append(exc.code)

    thread = threading.Thread(target=run)
    thread.start()
    deadline = time.monotonic() + 5
    while not https.seen and time.monotonic() < deadline:
        time.sleep(0.02)
    started = time.monotonic()
    manager.close_all()
    thread.join(5)
    # Promptly, not when the server answers after 3 s (Windows: shutdown()
    # alone does not wake a blocked recv).
    assert time.monotonic() - started < 1.5
    assert errors == ["cut_off"] and manager.active_count() == 0


def test_response_ending_before_content_length_is_an_error(https):
    with pytest.raises(SSHBrokerError) as err:
        _manager().request(_entry(https), "GET", "/wp/v2/short")
    assert err.value.code == "connection_failed"


# ── TLS ──


def test_untrusted_certificate_fails_before_the_request(https):
    entry = _entry(https, tls_ca_cert=None)
    with pytest.raises(SSHBrokerError) as err:
        _manager().request(entry, "GET", "/wp/v2/echo")
    assert err.value.code == "tls_verify_failed" and https.seen == []


def test_certificate_for_another_host_name_is_refused(tmp_path):
    server = _Server(tmp_path, cert=_certificate(tmp_path, "other", dns="other.example", ip=""))
    try:
        with pytest.raises(SSHBrokerError) as err:
            _manager().request(_entry(server), "GET", "/wp/v2/echo")
        assert err.value.code == "tls_verify_failed" and server.seen == []
    finally:
        server.close()


def test_plain_http_needs_the_explicit_opt_in(tmp_path):
    server = _Server(tmp_path, tls=False)
    try:
        with pytest.raises(SSHBrokerError, match="allow_plain_http"):
            _manager().request(_entry(server), "GET", "/wp/v2/echo")
        result = _manager().request(_entry(server, allow_plain_http="true"), "GET", "/wp/v2/echo")
        assert result["http_status"] == 200
        assert result["warning"] == http_api.PLAIN_HTTP_WARNING
        assert len(server.seen) == 1
    finally:
        server.close()


# ── entry validation ──


@pytest.mark.parametrize("fields, needle", [
    ({"allowed_path_prefixes": None}, "allowed_path_prefixes"),
    ({"allowed_methods": "GET, TRACE"}, "allowed_methods"),
    ({"base_url": "ftp://localhost/x"}, "https"),
    ({"base_url": "https://u:p@localhost/x"}, "credentials"),
    ({"base_url": "https://localhost/x?a=1"}, "query"),
    ({"base_url": None}, "base_url"),
    ({"auth_header": "Authorization Bearer {token}"}, "auth_header"),
    ({"auth_header": "Authorization: Bearer {missing}"}, "missing"),
    ({"auth_header": "Host: {token}"}, "Host"),
    ({"token": "x\r\nX-Evil: 1"}, "line break"),
    ({"allowed_path_prefixes": "/a/../b"}, "allowed_path_prefixes"),
])
def test_invalid_entries_are_refused(https, fields, needle):
    with pytest.raises(SSHBrokerError) as err:
        HTTPTarget.from_entry(_entry(https, **fields))
    assert err.value.code == "invalid_entry" or needle in str(err.value)
    assert needle.lower() in str(err.value).lower()
    assert TOKEN not in str(err.value)


def test_target_repr_and_errors_never_show_the_credential(https):
    target = HTTPTarget.from_entry(_entry(https))
    assert TOKEN not in repr(target) and TOKEN not in str(target)
    assert target.origin == f"https://127.0.0.1:{https.port}"
