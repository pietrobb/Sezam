"""AI broker TODO section 7 (S7): the entry's secrets never come back to the
agent in ``ssh_execute`` / ``ssh_session_read`` output.

Sensitive fields, the password, the passphrase and the private key (and its
lines) become ``[REDACTED]``, also base64 (any alignment, both alphabets)
and URL-encoded; a secret split across two session reads is redacted too.
The SSH tests run a real in-process SSH server that echoes what it is told.
"""

from __future__ import annotations

import base64
import socket
import threading
import time
from urllib.parse import quote

import paramiko
import pytest

from sezam.mcp.redact import Redactor, RedactingStream
from sezam.mcp.ssh import SSHManager, _fingerprint

PASSWORD = "Pw-9f3!kq+Lz/77"
API_TOKEN = "tok_5Zx81Qa0rT"


def _entry(port: int, fingerprint: str, **extra) -> dict:
    fields = [
        {"key": "host", "value": "127.0.0.1"},
        {"key": "port", "value": str(port)},
        {"key": "username", "value": "deploy"},
        {"key": "password", "value": PASSWORD},
        {"key": "host_key_sha256", "value": fingerprint},
        {"key": "deploy token", "value": API_TOKEN, "sensitive": True},
    ]
    fields += [{"key": k, "value": v} for k, v in extra.items()]
    return {"id": "e1", "fields": fields}


# --- unit ---------------------------------------------------------------


def _redactor() -> Redactor:
    return Redactor.for_entry(_entry(22, "x"))


def test_plain_sensitive_and_password_are_redacted_other_fields_not():
    out = _redactor().redact(f"pw={PASSWORD} t={API_TOKEN} host=127.0.0.1 user=deploy".encode())
    assert out == b"pw=[REDACTED] t=[REDACTED] host=127.0.0.1 user=deploy"


@pytest.mark.parametrize("prefix", [b"", b"a", b"ab", b"abc"])
@pytest.mark.parametrize("encode", [base64.b64encode, base64.urlsafe_b64encode])
def test_base64_at_any_alignment_is_redacted(prefix, encode):
    blob = encode(prefix + PASSWORD.encode() + b"\n tail")
    out = _redactor().redact(b"data: " + blob)
    assert out != b"data: " + blob
    assert base64.b64decode(blob).find(PASSWORD.encode()) >= 0
    # what is left decodes to no more than a few bytes of the secret
    for part in out.split(b"[REDACTED]"):
        assert PASSWORD.encode()[2:-2] not in _try_b64(part.replace(b"data: ", b""))


def _try_b64(data: bytes) -> bytes:
    data = data.replace(b"-", b"+").replace(b"_", b"/")
    try:
        return base64.b64decode(data + b"=" * (-len(data) % 4))
    except Exception:
        return b""


def test_url_encoded_is_redacted():
    out = _redactor().redact(b"GET /login?p=" + quote(PASSWORD, safe="").encode())
    assert out == b"GET /login?p=[REDACTED]"


def test_private_key_and_passphrase_and_each_key_line_are_redacted():
    pem = "-----BEGIN KEY-----\n" + "\n".join(["A" * 30 + str(i) for i in range(3)]) + "\n-----END KEY-----"
    redactor = Redactor.for_entry(
        {"fields": [{"key": "private_key", "value": pem}, {"key": "Key-Passphrase", "value": "horse battery"}]}
    )
    out = redactor.redact(f"cat: {'A' * 30}1\r\nphrase horse battery".encode())
    assert out == b"cat: [REDACTED]\r\nphrase [REDACTED]"


def test_short_values_are_not_redacted():
    redactor = Redactor.for_entry({"fields": [{"key": "password", "value": "abc"}]})
    assert redactor.redact(b"abc abcdef") == b"abc abcdef"


def test_stream_redacts_a_secret_split_at_every_position():
    secret = PASSWORD.encode()
    for split in range(1, len(secret)):
        stream = RedactingStream(_redactor())
        out = stream.feed(b"x " + secret[:split]) + stream.feed(secret[split:] + b" y$ ", final=False)
        assert secret not in out and secret[:split] not in out
        assert out == b"x [REDACTED] y$ "


def test_stream_holds_a_short_secret_that_starts_a_longer_one():
    redactor = Redactor.for_entry(
        {"fields": [{"key": "password", "value": "abcdwxyz"}, {"key": "pin", "value": "abcd", "sensitive": True}]}
    )
    stream = RedactingStream(redactor)
    out = stream.feed(b"> abcd") + stream.feed(b"wxyz <")
    assert out == b"> [REDACTED] <"
    assert b"wxyz" not in out


def test_stream_returns_a_prompt_at_once_and_flushes_at_the_end():
    stream = RedactingStream(_redactor())
    assert stream.feed(b"deploy@web:~$ ") == b"deploy@web:~$ "
    assert stream.feed(b"x " + PASSWORD.encode()[:5]) == b"x "
    assert stream.feed(b"", final=True) == PASSWORD.encode()[:5]


# --- real SSH server ----------------------------------------------------


class _Server(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if password == PASSWORD else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=_echo_shell, args=(channel,), daemon=True).start()
        return True

    def check_channel_exec_request(self, channel, command):
        def answer():
            # The client closes stdin only after the exec reply arrived;
            # answering earlier races the reply ("Channel closed").
            while channel.recv(1024):
                pass
            text = bytes(command).decode()
            if text.startswith("echo "):
                channel.sendall(text[5:].encode() + b"\n")
            elif text.startswith("err "):
                channel.sendall_stderr(text[4:].encode() + b"\n")
            elif text.startswith("b64 "):
                channel.sendall(base64.b64encode(b"x" + text[4:].encode()) + b"\n")
            channel.send_exit_status(0)
            channel.close()

        threading.Thread(target=answer, daemon=True).start()
        return True


def _echo_shell(channel):
    """Echoes each line it receives, one byte per packet."""
    channel.sendall(b"$ ")
    buf = b""
    while True:
        data = channel.recv(1024)
        if not data:
            return
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if line.startswith(b"bye "):
                # Prints the rest at once and hangs up: the client sees the
                # channel closed while that output is still buffered.
                if line.startswith(b"bye err "):
                    channel.sendall_stderr(line[8:])
                else:
                    channel.sendall(line[4:])
                channel.send_exit_status(0)
                channel.close()
                return
            for byte in line + b"\r\n":
                channel.sendall(bytes([byte]))
                time.sleep(0.002)
            channel.sendall(b"$ ")


class _SSHServer:
    def __init__(self):
        self.host_key = paramiko.ECDSAKey.generate()
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        self._keep: list = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.host_key)
            self._keep.append(transport)
            try:
                transport.start_server(server=_Server())
            except Exception:
                continue
            threading.Thread(target=self._accept, args=(transport,), daemon=True).start()

    def _accept(self, transport):
        while transport.is_active():
            channel = transport.accept(1)
            if channel is not None:
                self._keep.append(channel)

    def close(self):
        self._sock.close()
        for item in self._keep:
            item.close()


@pytest.fixture
def srv(monkeypatch):
    monkeypatch.setattr(paramiko.SSHClient, "load_system_host_keys", lambda self, filename=None: None)
    server = _SSHServer()
    yield server
    server.close()


def test_execute_echo_password_does_not_return_it(srv):
    entry = _entry(srv.port, _fingerprint(srv.host_key))
    ssh = SSHManager()

    out = ssh.execute(entry, f"echo {PASSWORD} and {API_TOKEN}", timeout=10)
    assert out["stdout"] == "[REDACTED] and [REDACTED]\n"

    err = ssh.execute(entry, f"err {quote(PASSWORD, safe='')}", timeout=10)
    assert err["stderr"] == "[REDACTED]\n"

    encoded = ssh.execute(entry, f"b64 {PASSWORD}", timeout=10)
    assert "[REDACTED]" in encoded["stdout"]
    assert PASSWORD.encode() not in _try_b64(encoded["stdout"].strip().encode())


def test_execute_output_truncated_inside_the_secret_does_not_leak_its_start(srv):
    entry = _entry(srv.port, _fingerprint(srv.host_key))
    cut = len("echo-") + 6
    out = SSHManager(max_output_bytes=cut).execute(entry, f"echo echo-{PASSWORD}", timeout=10)
    assert out["truncated"] is True
    assert out["stdout"] == "echo-[REDACTED]"


def test_session_read_never_returns_the_secret_split_across_reads(srv):
    entry = _entry(srv.port, _fingerprint(srv.host_key))
    ssh = SSHManager()
    session_id = ssh.open_session(entry, owner="a")["session_id"]
    try:
        ssh.write_session(session_id, f"echo {PASSWORD}\n", owner="a")
        seen = ""
        deadline = time.monotonic() + 10
        reads = 0
        while time.monotonic() < deadline and "\r\n$ " not in seen:
            seen += ssh.read_session(session_id, owner="a", max_bytes=3, wait_ms=50)["stdout"]
            reads += 1
        assert reads > 3
        assert seen == "$ echo [REDACTED]\r\n$ "
        assert PASSWORD[:4] not in seen
    finally:
        ssh.close_session(session_id, owner="a")


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_session_read_after_remote_close_keeps_the_tail_while_output_is_buffered(srv, stream):
    entry = _entry(srv.port, _fingerprint(srv.host_key))
    ssh = SSHManager()
    session_id = ssh.open_session(entry, owner="a")["session_id"]
    channel = ssh._sessions[session_id].channel
    try:
        assert ssh.read_session(session_id, owner="a", wait_ms=2000)["stdout"] == "$ "
        command = "bye err " if stream == "stderr" else "bye "
        ssh.write_session(session_id, f"{command}xxxxxx{PASSWORD}yyyy\n", owner="a")
        deadline = time.monotonic() + 10
        while not channel.closed and time.monotonic() < deadline:
            time.sleep(0.02)
        time.sleep(0.2)
        # The remote side hung up, its output is still waiting to be read.
        ready = channel.recv_stderr_ready() if stream == "stderr" else channel.recv_ready()
        assert channel.closed and ready

        reads = []
        while len(reads) < 20:
            out = ssh.read_session(session_id, owner="a", max_bytes=12)
            assert out["closed"] is True
            reads.append(out[stream])
            if not out[stream] and not (channel.recv_ready() or channel.recv_stderr_ready()):
                break
        seen = "".join(reads)
        assert len([r for r in reads if r]) > 1
        assert seen == "xxxxxx[REDACTED]yyyy"
        assert PASSWORD[:4] not in seen
    finally:
        ssh.close_session(session_id, owner="a")
