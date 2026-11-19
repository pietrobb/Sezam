"""Regressions for code review HEAD 2c7e809, section 3 (CLI/MCP C1, C2, C5; import G4)."""

from __future__ import annotations

import csv
import json
import os
import stat

import pytest

from sezam import autotype
from sezam.cli import _export_bitwarden, _export_csv
from sezam.importers.csv_import import import_csv
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.securefile import csv_escape, csv_unescape
from tests.test_mcp_ssh import FakeSSHManager, ssh_vault  # noqa: F401  (fixture)

POSIX = os.name == "posix"


# ── C1: exports are private, never follow a planted symlink, no formulas ──


@pytest.fixture
def export_vault(ssh_vault):
    node = ssh_vault.create_node("Sheet")
    ssh_vault.create_entry(node, '=HYPERLINK("evil")', [
        {"key": "password", "value": "-2+3", "sensitive": True},
        {"key": "note", "value": "'quoted"},
        {"key": "plain", "value": "hello"},
    ])
    return ssh_vault


@pytest.mark.parametrize("exporter", [_export_csv, _export_bitwarden])
def test_export_replaces_planted_symlink_instead_of_following_it(export_vault, tmp_path, exporter):
    target = tmp_path / "victim.txt"
    target.write_text("keep me")
    dest = tmp_path / "export.out"
    try:
        dest.symlink_to(target)
    except OSError:
        pytest.skip("Symbolic links are unavailable on this platform")

    exporter(export_vault, str(dest))

    assert target.read_text() == "keep me"
    assert not dest.is_symlink()


@pytest.mark.skipif(not POSIX, reason="POSIX permission bits")
@pytest.mark.parametrize("exporter", [_export_csv, _export_bitwarden])
def test_export_is_owner_only(export_vault, tmp_path, exporter):
    dest = tmp_path / "export.out"
    exporter(export_vault, str(dest))
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600


def test_backup_and_key_export_are_owner_only(export_vault, tmp_path):
    from sezam.crypto.kdf import Argon2Params
    from sezam.crypto.keys import export_sezam_key

    backup = tmp_path / "backup.db"
    export_vault.db.backup(backup)
    key_file = tmp_path / "me.sezam-key"
    export_sezam_key(
        export_vault.keypair,
        export_vault.current_kek,
        key_file,
        bytes.fromhex(export_vault.db.get_meta("argon2_salt")),
        Argon2Params.from_dict(export_vault.db.get_meta_json("argon2_params")),
    )
    assert backup.stat().st_size > 0 and key_file.stat().st_size > 0
    assert [p.name for p in tmp_path.iterdir() if p.suffix == ".tmp"] == []
    if POSIX:
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600


def test_csv_export_has_no_live_formulas_and_round_trips(export_vault, tmp_path):
    dest = tmp_path / "export.csv"
    _export_csv(export_vault, str(dest))

    with open(dest, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))[1:]
    for row in rows:
        for cell in row[:4]:
            assert not cell.startswith(("=", "+", "-", "@"))

    from sezam.vault.crud import Vault
    from tests.test_mcp_ssh import FAST_PARAMS

    target = Vault.create(tmp_path / "re", "pw", FAST_PARAMS)
    try:
        assert import_csv(target, dest) >= 1
        entry = target.find_entry_by_path('Sheet/=HYPERLINK("evil")')
        values = {f["key"]: f["value"] for f in entry["fields"]}
        assert values == {"password": "-2+3", "note": "'quoted", "plain": "hello"}
    finally:
        target.lock()


@pytest.mark.parametrize("value", ["=1+1", "+x", "-x", "@x", "\tx", "'x", "''=x", "plain", ""])
def test_csv_escape_is_reversible(value):
    assert csv_unescape(csv_escape(value)) == value


# ── G4: CSV tier is validated ──


@pytest.mark.parametrize("tier", ["3", "-1", "two", "1.5"])
def test_csv_import_rejects_invalid_tier(ssh_vault, tmp_path, tier):
    src = tmp_path / "in.csv"
    src.write_text(
        "folder,name,field_key,field_value,sensitive,tier\n"
        f"x,Entry,password,secret,true,{tier}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="tier"):
        import_csv(ssh_vault, src)
    assert ssh_vault.search("Entry") == []


# ── C2: SSH audit is written before the side effect and on any failure ──


def _record_audit(vault, monkeypatch):
    records = []
    original = vault._audit_log

    def spy(action, detail=None, *, strict=False):
        if action == "mcp_ssh":
            records.append(json.loads(detail)["operation"])
        return original(action, detail, strict=strict)

    monkeypatch.setattr(vault, "_audit_log", spy)
    return records


def test_ssh_execute_audits_intent_before_running(ssh_vault, monkeypatch):
    records = _record_audit(ssh_vault, monkeypatch)

    class Spy(FakeSSHManager):
        def execute(self, entry, command, **kwargs):
            assert records == ["execute_start"]
            return super().execute(entry, command, **kwargs)

    broker = MCPBroker(ssh_vault, ApprovalManager(), ssh_manager=Spy())
    assert broker.ssh_execute("Servers/Production", "id")["status"] == "ok"
    assert records == ["execute_start", "execute"]


def test_ssh_unexpected_error_is_audited(ssh_vault, monkeypatch):
    records = _record_audit(ssh_vault, monkeypatch)

    class Boom(FakeSSHManager):
        def upload(self, *a, **k):
            raise OSError("disk")

    broker = MCPBroker(ssh_vault, ApprovalManager(), ssh_manager=Boom())
    with pytest.raises(OSError):
        broker.ssh_upload("Servers/Production", "local", "/remote")
    assert records == ["upload_start", "upload_failed"]


def test_ssh_does_not_run_when_audit_cannot_be_written(ssh_vault, monkeypatch):
    fake = FakeSSHManager()
    broker = MCPBroker(ssh_vault, ApprovalManager(), ssh_manager=fake)

    def broken(*a, **k):
        raise OSError("audit disk full")

    monkeypatch.setattr(ssh_vault._audit, "append", broken)
    with pytest.raises(OSError):
        broker.ssh_execute("Servers/Production", "rm -rf /tmp/x")
    with pytest.raises(OSError):
        broker.ssh_session_open("Servers/Production")
    assert fake.calls == []


def test_fresh_vault_audits_actions(ssh_vault):
    before = ssh_vault.db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"]
    ssh_vault.create_node("Audited")
    assert ssh_vault.db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"] == before + 1


# ── C5: autotype never puts the secret in argv ──


@pytest.mark.parametrize("system, fn", [("Darwin", "_autotype_macos"), ("Linux", "_autotype_linux")])
def test_autotype_keeps_secret_out_of_argv(monkeypatch, system, fn):
    calls = []
    monkeypatch.setattr(
        autotype.subprocess, "run", lambda argv, **kw: calls.append((argv, kw.get("input")))
    )
    secret = "S3cr3t-TAB-RETURN"
    assert getattr(autotype, fn)(f"alice\t{secret}\nTAB", 0) is True

    assert all(secret not in " ".join(argv) for argv, _ in calls)
    assert any(stdin and secret.encode() in stdin for _, stdin in calls)
    if system == "Linux":
        keys = [argv[2] for argv, _ in calls if argv[1] == "key"]
        typed = [stdin for argv, stdin in calls if argv[1] == "type"]
        assert keys == ["Tab", "Return"]
        assert typed == [b"alice", secret.encode(), b"TAB"]

