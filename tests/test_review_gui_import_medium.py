"""Regressions for code review HEAD 2c7e809, medium GUI/import/script items G1-G7."""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sezam.crypto.kdf import Argon2Params
from sezam.totp import parse_totp
from sezam.vault.crud import Vault

ROOT = Path(__file__).resolve().parents[1]
FAST = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)


@pytest.fixture
def vault(tmp_path):
    v = Vault.create(tmp_path, "TestHeslo123!", FAST)
    yield v
    if v.is_unlocked:
        v.lock()


@pytest.fixture
def qapp():
    QApplication = pytest.importorskip("PySide6.QtWidgets").QApplication

    return QApplication.instance() or QApplication(sys.argv)


def _pump_until(condition, timeout=5.0):
    from PySide6.QtWidgets import QApplication

    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.01)
    QApplication.processEvents()


def _entries(vault):
    found = {}

    def walk(node_id):
        for entry in vault.list_entries(node_id):
            found[entry["name"]] = vault.read_entry(entry["id"])
        for node in vault.list_nodes(node_id):
            walk(node["id"])

    walk(vault.db.get_meta("root_node_id"))
    return found


# -- G1: clipboard ---------------------------------------------------------


def test_g1_clipboard_clear_spares_newer_content_and_runs_on_quit(qapp, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QApplication
    from sezam.gui import main_window

    w = main_window.MainWindow(tmp_path)
    clipboard = QApplication.clipboard()

    w._on_field_copied("s3cret")
    clipboard.setText("copied later in another app")
    w._clear_clipboard()
    assert clipboard.text() == "copied later in another app"

    w._on_field_copied("s3cret")
    w._clear_clipboard()
    assert clipboard.text() == ""

    monkeypatch.setattr(main_window.QApplication, "quit", lambda: None)
    w._on_field_copied("s3cret")
    w._quit()
    assert clipboard.text() == ""
    assert not w._clipboard_timer.isActive()


# -- G2: KeePass -----------------------------------------------------------


def _group(name, parent=None):
    return SimpleNamespace(name=name, parentgroup=parent, uuid=f"uuid-{name}")


def _kp_entry(title, group, otp=None, custom=None):
    return SimpleNamespace(
        title=title, group=group, username="u", password="p", url=None, notes=None,
        custom_properties=custom or {}, otp=otp,
    )


def test_g2_keepass_keeps_otp_and_skips_recycle_bin(vault):
    from sezam.importers.keepass import _import_database

    root = _group("Root")
    work = _group("Work", root)
    bin_group = _group("Recycle Bin", root)
    deleted_sub = _group("Old", bin_group)
    kp = SimpleNamespace(
        recyclebin_group=bin_group,
        entries=[
            _kp_entry("XC", work, otp="otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=30"),
            _kp_entry("Native", work, custom={
                "TimeOtp-Secret-Base32": "JBSWY3DPEHPK3PXP",
                "TimeOtp-Algorithm": "HMAC-SHA-256",
                "TimeOtp-Length": "8",
                "TimeOtp-Period": "60",
                "Pin": "1234",
            }),
            _kp_entry("Gone", bin_group),
            _kp_entry("Gone deeper", deleted_sub),
        ],
    )

    assert _import_database(vault, kp, None, "duplicate") == 2
    entries = _entries(vault)
    assert set(entries) == {"XC", "Native"}

    def field(entry, key):
        return next(f for f in entry["fields"] if f["key"] == key)

    xc = field(entries["XC"], "totp_secret")
    assert xc["field_type"] == "totp"
    assert parse_totp(xc["value"]).key == b"Hello!\xde\xad\xbe\xef"

    native = parse_totp(field(entries["Native"], "totp_secret")["value"])
    assert (native.algorithm, native.digits, native.period) == ("sha256", 8, 60)
    keys = {f["key"] for f in entries["Native"]["fields"]}
    assert "Pin" in keys
    assert not any(k.startswith("TimeOtp-") for k in keys)


# -- G3: Bitwarden ---------------------------------------------------------


def test_g3_bitwarden_import_tolerates_json_nulls(vault, tmp_path):
    from sezam.importers.bitwarden import import_bitwarden

    export = {
        "folders": None,
        "items": [
            {
                "type": 1, "name": "Nully", "folderId": None, "notes": None,
                "fields": [{"name": None, "value": None, "type": None}],
                "login": {"username": "a", "password": "b", "uris": None, "totp": None},
            },
            {"type": 1, "name": None, "login": None, "fields": None},
        ],
    }
    source = tmp_path / "bw.json"
    source.write_text(json.dumps(export), encoding="utf-8")

    assert import_bitwarden(vault, source) >= 1
    assert "Nully" in _entries(vault)


# -- G5: deploy file list --------------------------------------------------


def test_g5_deploy_uploads_every_tracked_server_and_web_file():
    sys.path.insert(0, str(ROOT))
    try:
        from scripts.deploy_files import tracked_deploy_files
    finally:
        sys.path.remove(str(ROOT))

    files = tracked_deploy_files("/srv/sezam")
    tracked = subprocess.run(
        ["git", "ls-files", "--", "server", "web"], cwd=ROOT,
        check=True, capture_output=True, text=True,
    ).stdout.split()
    assert set(tracked) <= set(files)
    for required in ("server/app/auth.py", "server/app/routers/users.py", "Dockerfile"):
        assert files[required] == f"/srv/sezam/{required}"
    for script in ("deploy_shamir.py", "deploy_audit_rebuild.py"):
        source = (ROOT / "scripts" / script).read_text(encoding="utf-8")
        assert "FILES = tracked_deploy_files(DEPLOY_DIR)" in source
        assert "server/app/main.py" not in source


# -- G6: setup_demo --------------------------------------------------------


def test_g6_setup_demo_is_transactional_and_has_no_real_targets():
    source = (ROOT / "scripts" / "setup_demo.py").read_text(encoding="utf-8")

    start = source.index("START TRANSACTION")
    assert start < source.index("DELETE FROM vault_objects") < source.index("COMMIT;")
    assert "'{USERNAME}'" not in source and "'{uid}'" not in source
    assert "_hex_text(USERNAME)" in source

    for literal in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", source):
        address = ipaddress.ip_address(literal)
        documentation = any(
            address in ipaddress.ip_network(net)
            for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
        )
        assert documentation or address.is_private or address.is_loopback, literal
    assert "gmail.com" not in source
    assert "bezemek" not in source.lower()
    assert "firma.sk" not in source


def test_g6_hex_text_keeps_quotes_out_of_sql():
    namespace: dict = {}
    source = (ROOT / "scripts" / "setup_demo.py").read_text(encoding="utf-8")
    helper = source[source.index("def _hex_text"):source.index("uid = str(ULID())")]
    exec(helper, namespace)
    literal = namespace["_hex_text"]("x'); DROP TABLE users; --")
    assert "'" not in literal.replace("X'", "").replace("' USING", "")
    assert bytes.fromhex(literal.split("'")[1]) == "x'); DROP TABLE users; --".encode()


# -- G7: network off the GUI thread ----------------------------------------


class _BlockingClient:
    def __init__(self):
        self.release = threading.Event()
        self.calls = 0

    def poll_share_notifications(self):
        self.calls += 1
        assert self.release.wait(5)
        return [{"share_id": "share-1"}]


class _Tray:
    def __init__(self):
        self.messages = []

    def showMessage(self, *args):
        self.messages.append(args)

    def setToolTip(self, *_):
        pass


def _window_with_server(vault, tmp_path):
    from sezam.gui.main_window import MainWindow

    vault.db.set_meta("server_url", "https://sync.invalid")
    vault.db.set_meta("user_id", "OWNER000000000000000000001")
    w = MainWindow(tmp_path)
    w._vault = vault
    w._tray = _Tray()
    return w


def test_g7_share_poll_does_not_block_and_never_overlaps(qapp, vault, tmp_path):
    w = _window_with_server(vault, tmp_path)
    client = _BlockingClient()
    w._notification_client = client

    started = time.monotonic()
    w._poll_share_notifications()
    w._poll_share_notifications()  # still in flight: must not queue a second call
    assert time.monotonic() - started < 1
    assert w._tray.messages == []

    client.release.set()
    _pump_until(lambda: w._tray.messages)
    assert len(w._tray.messages) == 1
    assert client.calls == 1
    assert not w._notification_poll_running


def test_g7_share_poll_result_is_dropped_after_lock(qapp, vault, tmp_path):
    w = _window_with_server(vault, tmp_path)
    client = _BlockingClient()
    w._notification_client = client

    w._poll_share_notifications()
    w._vault = None  # locked while the request was in flight
    client.release.set()
    _pump_until(lambda: not w._notification_poll_running)

    assert w._tray.messages == []


def test_g7_background_helper_reports_errors_on_gui_thread(qapp):
    from PySide6.QtCore import QObject
    from sezam.gui.background import run_in_background

    owner = QObject()
    seen = []
    gui_thread = threading.current_thread()

    def boom():
        raise RuntimeError("offline")

    run_in_background(
        owner, boom, seen.append,
        lambda exc: seen.append((threading.current_thread() is gui_thread, str(exc))),
    )
    _pump_until(lambda: seen)
    assert seen == [(True, "offline")]


def test_g7_team_dialog_has_no_synchronous_server_calls():
    source = (ROOT / "src" / "sezam" / "gui" / "team_dialog.py").read_text(encoding="utf-8")
    calls = re.findall(r"^.*_get_server_client\(\)\.\w+\(.*$", source, flags=re.M)
    assert calls
    assert all("lambda:" in line for line in calls), calls
