"""Review main@7c10379 (R7-H, AI table; d615826 2291239 bypassed for FTP).

'sezam ai off' cuts a running FTP transfer by shutting the control
connection. ftplib moves the data on a second socket and reads the control
connection only at the end, so against a server that lets the data channel
run on without its control connection a download went on to the end after
the cut: the whole file landed in the transfer directory, only the final
reply said cut_off. Every block now checks the cut, and nothing of a cut
download is kept.
"""

from __future__ import annotations

import threading
import time

import pytest
from pyftpdlib.handlers import FTPHandler

from sezam.mcp.ssh import SSHBrokerError
from tests.test_ai_f2_ftp import _entry, _manager, _Server, transfers  # noqa: F401  (fixture)

SIZE = 2 * 1024 * 1024


@pytest.fixture
def server_keeps_data_channel(monkeypatch):
    close = FTPHandler.close

    def keep_data_channel(self):
        if not self._closed:
            self.data_channel = None  # the transfer goes on without its control connection
        close(self)

    monkeypatch.setattr(FTPHandler, "close", keep_data_channel)


@pytest.mark.parametrize("direction", ["download", "upload"])
def test_ai_off_stops_a_transfer_the_server_would_finish(
    tmp_path, transfers, server_keeps_data_channel, direction  # noqa: F811
):
    server = _Server(tmp_path, "plain", throttle=64 * 1024)  # ~32 s for the whole file
    (server.home / "big.bin").write_bytes(b"z" * SIZE)
    (transfers / "up.bin").write_bytes(b"u" * SIZE)
    manager = _manager(transfers)
    entry = _entry(server, allow_plain_ftp="true")
    outcome: dict = {}

    def transfer():
        try:
            if direction == "download":
                outcome["result"] = manager.download(entry, "big.bin", "big.bin")
            else:
                outcome["result"] = manager.upload(entry, "up.bin", "up.bin")
        except SSHBrokerError as exc:
            outcome["code"] = exc.code

    worker = threading.Thread(target=transfer)
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while manager.active_count() == 0 and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(1.0)
        assert manager.active_count() == 1
        manager.close_all()
        worker.join(5)
        stopped = not worker.is_alive()
        worker.join(60)
    finally:
        server.close()

    assert stopped, "the transfer ran on after the cut"
    assert outcome == {"code": "cut_off"}
    if direction == "download":
        local = transfers / "big.bin"
        assert not local.exists() or local.stat().st_size == 0
    else:
        remote = server.home / "up.bin"
        assert not remote.exists() or remote.stat().st_size < SIZE
