"""P6: every broker operation writes an intent record before it runs and an
outcome record however it ends; without a writable audit nothing runs."""

import json

import pytest

from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.ssh import SSHBrokerError
from tests.test_mcp_ssh import FakeSSHManager, ssh_vault  # noqa: F401  (fixture)

TOTP_SEED = "JBSWY3DPEHPK3PXP"


@pytest.fixture
def vault(ssh_vault):  # noqa: F811
    node = ssh_vault.resolve_path("Servers")[0]
    ssh_vault.create_entry(
        node,
        "Readable",
        [{"key": "token", "value": "raw-token-value", "sensitive": True}],
        tier=0,
        ai_read_secret=True,
    )
    ssh_vault.create_entry(
        node,
        "Otp",
        [{"key": "totp_secret", "value": TOTP_SEED, "field_type": "totp"}],
        tier=0,
        allowed_actions=["totp_code"],
    )
    return ssh_vault


def _records(vault, monkeypatch):
    records = []
    original = vault._audit_log

    def spy(action, detail=None, *, strict=False):
        if action.startswith("mcp_"):
            records.append((action, json.loads(detail)))
        return original(action, detail, strict=strict)

    monkeypatch.setattr(vault, "_audit_log", spy)
    return records


def _ops(records):
    return [detail["operation"] for _, detail in records]


def _open(vault, manager):
    broker = MCPBroker(vault, ApprovalManager(), ssh_manager=manager)
    session_id = broker.ssh_session_open("Servers/Production")["session_id"]
    return broker, session_id


SESSION_CALLS = {
    "session_read": ("read_session", lambda b, s: b.ssh_session_read(s)),
    "session_resize": ("resize_session", lambda b, s: b.ssh_session_resize(s, 80, 24)),
    "session_close": ("close_session", lambda b, s: b.ssh_session_close(s)),
}


@pytest.mark.parametrize("operation", SESSION_CALLS)
def test_session_operation_audits_intent_before_running(vault, monkeypatch, operation):
    method, call = SESSION_CALLS[operation]
    seen = []

    class Spy(FakeSSHManager):
        pass

    def spying(self, *a, **k):
        seen.append(list(_ops(records)))
        return getattr(FakeSSHManager, method)(self, *a, **k)

    setattr(Spy, method, spying)
    broker, session_id = _open(vault, Spy())
    records = _records(vault, monkeypatch)

    assert call(broker, session_id)["status"] == "ok"
    assert seen == [[f"{operation}_start"]]
    assert _ops(records) == [f"{operation}_start", operation]


@pytest.mark.parametrize("operation", SESSION_CALLS)
@pytest.mark.parametrize(
    "error, code",
    [(OSError("socket"), "internal_error"), (SSHBrokerError("timeout", "t"), "timeout")],
)
def test_session_operation_failure_is_audited(vault, monkeypatch, operation, error, code):
    method, call = SESSION_CALLS[operation]

    class Boom(FakeSSHManager):
        pass

    def boom(self, *a, **k):
        raise error

    setattr(Boom, method, boom)
    broker, session_id = _open(vault, Boom())
    records = _records(vault, monkeypatch)

    if isinstance(error, SSHBrokerError):
        assert call(broker, session_id)["code"] == code
    else:
        with pytest.raises(OSError):
            call(broker, session_id)
    assert _ops(records) == [f"{operation}_start", f"{operation}_failed"]
    assert records[-1][1]["code"] == code


@pytest.mark.parametrize("operation", SESSION_CALLS)
def test_session_operation_does_not_run_unaudited(vault, monkeypatch, operation):
    method, call = SESSION_CALLS[operation]
    fake = FakeSSHManager()
    broker, session_id = _open(vault, fake)
    fake.calls.clear()

    def broken(*a, **k):
        raise OSError("audit disk full")

    monkeypatch.setattr(vault._audit, "append", broken)
    with pytest.raises(OSError):
        call(broker, session_id)
    assert fake.calls == []


def test_policy_revoked_close_is_audited_before_closing(vault, monkeypatch):
    seen = []

    class Spy(FakeSSHManager):
        def close_session(self, session_id, **kwargs):
            seen.append(list(_ops(records)))
            return super().close_session(session_id, **kwargs)

    broker, session_id = _open(vault, Spy())
    entry = vault.find_entry_by_path("Servers/Production")
    vault.update_entry(entry["id"], allowed_actions=["ssh_execute"])
    records = _records(vault, monkeypatch)

    assert broker.ssh_session_read(session_id)["code"] == "policy_revoked"
    assert seen == [["session_policy_revoked_start"]]
    assert _ops(records) == ["session_policy_revoked_start", "session_policy_revoked"]


def test_secret_release_is_audited_without_the_value(vault, monkeypatch):
    records = _records(vault, monkeypatch)
    broker = MCPBroker(vault, ApprovalManager(), ssh_manager=FakeSSHManager())

    assert broker.vault_read("Servers/Readable", "token")["value"] == "raw-token-value"
    assert records and {kind for kind, _ in records} == {"mcp_secret"}
    assert _ops(records) == ["read_secret_start", "read_secret"]
    assert records[0][1]["field"] == "token"
    assert "raw-token-value" not in json.dumps([d for _, d in records])


def test_secret_is_not_released_when_audit_cannot_be_written(vault, monkeypatch):
    broker = MCPBroker(vault, ApprovalManager(), ssh_manager=FakeSSHManager())

    def broken(*a, **k):
        raise OSError("audit disk full")

    monkeypatch.setattr(vault._audit, "append", broken)
    with pytest.raises(OSError):
        broker.vault_read("Servers/Readable", "token")
    with pytest.raises(OSError):
        broker.vault_use("Servers/Otp", "totp_code")


def _break_audit_dek(vault, monkeypatch, how):
    if how == "missing":
        original = vault._db.fetchone

        def fetchone(sql, *a, **k):
            if "scope = 'audit'" in sql:
                return None
            return original(sql, *a, **k)

        monkeypatch.setattr(vault._db, "fetchone", fetchone)
    else:
        audit_dek_id = vault._db.fetchone("SELECT id FROM deks WHERE scope = 'audit'")["id"]
        original = vault._dek_mgr.unlock_dek

        def unlock_dek(dek_id, *a, **k):
            if dek_id == audit_dek_id:
                raise ValueError("audit DEK cannot be unwrapped")
            return original(dek_id, *a, **k)

        monkeypatch.setattr(vault._dek_mgr, "unlock_dek", unlock_dek)


def _mcp_rows(vault):
    return vault._db.fetchall(
        "SELECT action, encrypted_details FROM audit_log WHERE action LIKE 'mcp_%'"
    )


@pytest.mark.parametrize("how", ["missing", "unlock_fails"])
def test_nothing_runs_when_the_intent_record_would_lose_its_details(vault, monkeypatch, how):
    """Entry and operation live only in the encrypted details: an intent record
    without them does not say what is about to happen, so it does not count."""
    fake = FakeSSHManager()
    broker = MCPBroker(vault, ApprovalManager(), ssh_manager=fake)
    before = len(_mcp_rows(vault))
    _break_audit_dek(vault, monkeypatch, how)

    with pytest.raises(Exception):
        broker.ssh_execute("Servers/Production", "id")
    assert fake.calls == []
    with pytest.raises(Exception):
        broker.vault_read("Servers/Readable", "token")
    with pytest.raises(Exception):
        broker.vault_use("Servers/Otp", "totp_code")
    assert len(_mcp_rows(vault)) == before


def test_stored_intent_record_carries_the_details(vault):
    broker = MCPBroker(vault, ApprovalManager(), ssh_manager=FakeSSHManager())
    broker.ssh_execute("Servers/Production", "id")
    rows = _mcp_rows(vault)
    assert rows and all(row["encrypted_details"] for row in rows)


def test_vault_use_is_audited(vault, monkeypatch):
    records = _records(vault, monkeypatch)
    broker = MCPBroker(vault, ApprovalManager(), ssh_manager=FakeSSHManager())

    result = broker.vault_use("Servers/Otp", "totp_code")
    assert result["status"] == "ok"
    assert _ops(records) == ["use_start", "use"]
    assert records[-1][1]["result"] == "ok"
    assert TOTP_SEED not in json.dumps([d for _, d in records])
    assert result["output"] not in json.dumps([d for _, d in records])
