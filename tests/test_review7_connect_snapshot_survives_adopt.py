"""Review 7c10379 (desktop core, medium): the 'server-connect' snapshot survives.

A device whose vault has its own salt takes the account KEK over when it
connects ('adopt_account_kek'). That dropped every snapshot of the old salt,
the 'server-connect' one the connect had taken a moment before included, so
the connect could not be undone as the documentation promises. The snapshot
of this connect now stays (it opens with the device's previous password);
older ones of the old password still go, and a later password change drops it.
"""

from __future__ import annotations

import sys

import pytest

from sezam import cli
from sezam.vault.crud import Vault
from sezam.vault.snapshots import list_snapshots, take_snapshot
from tests.test_ai_r1_snapshots import _opens_with
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    NEW_PASSWORD,
    PASSWORD,
    _vault,
    server,
)


def _reasons(vault_dir) -> list[str]:
    return [s.reason for s in list_snapshots(vault_dir)]


def _second_device(tmp_path, url):
    """The account exists (device A); device B has its own vault and salt."""
    first = _vault(tmp_path / "a", "admin")
    cli._server_connect_flow(url, first, PASSWORD)
    first.lock()
    second = _vault(tmp_path / "b", "admin")
    second.create_entry(second.create_node("Local"), "before-connect", [])
    take_snapshot(second.db, "import")  # older, of the same old password
    return second, second.db.get_meta("argon2_salt")


def _check_way_back(tmp_path, device, old_salt) -> None:
    vault_dir = tmp_path / "b"
    assert device.db.get_meta("argon2_salt") != old_salt  # the account KEK was taken over
    assert _reasons(vault_dir) == ["server-connect"]
    connect_snapshot = list_snapshots(vault_dir)[0].path
    assert _opens_with(connect_snapshot, tmp_path, PASSWORD)

    # It is no key-change spare: unlocking with the account password keeps it.
    device.lock()
    reopened = Vault(vault_dir)
    reopened.unlock(PASSWORD)
    assert _reasons(vault_dir) == ["server-connect"]

    # A real password change still drops it.
    reopened.change_password(PASSWORD, NEW_PASSWORD)
    assert "server-connect" not in _reasons(vault_dir)
    reopened.lock()


def test_cli_connect_keeps_its_snapshot_after_taking_the_account_kek(server, tmp_path):  # noqa: F811
    url, _db = server
    device, old_salt = _second_device(tmp_path, url)
    cli._server_connect_flow(url, device, PASSWORD)
    assert device.db.get_meta("server_url") == url
    _check_way_back(tmp_path, device, old_salt)


@pytest.fixture
def qapp():
    QApplication = pytest.importorskip("PySide6.QtWidgets").QApplication
    return QApplication.instance() or QApplication(sys.argv)


def test_gui_connect_keeps_its_snapshot_after_taking_the_account_kek(server, tmp_path, qapp):  # noqa: F811
    from sezam.gui.server_connect_dialog import ServerConnectWorker

    url, _db = server
    device, old_salt = _second_device(tmp_path, url)
    worker = ServerConnectWorker(url, device, PASSWORD)
    errors: list[str] = []
    worker.finished_error.connect(errors.append)
    worker.run()
    assert not errors, errors
    _check_way_back(tmp_path, device, old_salt)
