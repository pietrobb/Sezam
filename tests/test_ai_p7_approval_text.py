"""P7: the approval dialog cannot be disguised and shows the real target
(entry, host, port, username) taken from the vault entry, not from the agent."""

import pytest

from sezam.mcp.approval import ApprovalManager, ApprovalRequest, approval_message
from sezam.mcp.broker import MCPBroker
from tests.test_mcp_ssh import FakeSSHManager, ssh_vault  # noqa: F401  (fixture)


class _Capture(ApprovalManager):
    def __init__(self):
        super().__init__()
        self.seen: list[ApprovalRequest] = []
        self.set_on_request(self._deny)

    def _deny(self, request):
        self.seen.append(request)
        self.deny(request.request_id)


def _broker(vault):
    approvals = _Capture()
    fake = FakeSSHManager()
    return MCPBroker(vault, approvals, ssh_manager=fake), approvals, fake


def test_ssh_approval_shows_real_host_port_and_user(ssh_vault):  # noqa: F811
    broker, approvals, fake = _broker(ssh_vault)

    assert broker.ssh_execute("Servers/Approval", "uptime")["status"] == "denied"
    message = approval_message(approvals.seen[0])
    assert "Entry: Approval\n" in message
    assert "Host: approval.example.test\n" in message
    assert "Port: 22\n" in message
    assert "User: root\n" in message
    assert message.index("Host:") < message.index("Details:")
    assert fake.calls == []


def test_target_from_a_synced_entry_is_escaped(ssh_vault):  # noqa: F811
    entry = ssh_vault.find_entry_by_path("Servers/Approval")
    ssh_vault.update_entry(
        entry["id"],
        fields=[
            {"key": "host", "value": "evil\u202etset.elpmaxe"},
            {"key": "port", "value": "2200"},
            {"key": "username", "value": "ro\u200bot"},
            {"key": "password", "value": "approval-secret", "sensitive": True},
        ],
    )
    broker, approvals, _ = _broker(ssh_vault)

    broker.ssh_execute("Servers/Approval", "uptime")
    message = approval_message(approvals.seen[0])
    assert "\u202e" not in message and "\u200b" not in message
    assert "Host: evil\\u202etset.elpmaxe\n" in message
    assert "Port: 2200\n" in message
    assert "User: ro\\u200bot\n" in message
    assert "approval-secret" not in message


def test_unusable_ssh_entry_is_refused_without_a_prompt(ssh_vault):  # noqa: F811
    entry = ssh_vault.find_entry_by_path("Servers/Approval")
    ssh_vault.update_entry(
        entry["id"], fields=[{"key": "host", "value": "approval.example.test"}]
    )
    broker, approvals, fake = _broker(ssh_vault)

    assert broker.ssh_execute("Servers/Approval", "uptime")["code"] == "invalid_entry"
    assert approvals.seen == [] and fake.calls == []


def test_read_secret_approval_names_the_entry(ssh_vault):  # noqa: F811
    node = ssh_vault.resolve_path("Servers")[0]
    ssh_vault.create_entry(
        node, "Token", [{"key": "token", "value": "t", "sensitive": True}],
        tier=1, ai_read_secret=True,
    )
    broker, approvals, _ = _broker(ssh_vault)

    assert broker.vault_read("Servers/Token", "token")["status"] == "denied"
    assert "Entry: Token\n" in approval_message(approvals.seen[0])


@pytest.mark.parametrize(
    "hidden, shown",
    [
        ("\u00a0", "\\u00a0"),  # no-break space
        ("\u3000", "\\u3000"),  # ideographic space
        ("\u3164", "\\u3164"),  # hangul filler
        ("\u2800", "\\u2800"),  # braille blank
        ("\u034f", "\\u034f"),  # combining grapheme joiner
        ("\ufe0f", "\\ufe0f"),  # variation selector
        ("\U000e0101", "\\U000e0101"),  # variation selector supplement
        ("\U000e0041", "\\U000e0041"),  # tag character (Cf, above the BMP)
    ],
)
def test_invisible_characters_are_escaped(hidden, shown):
    request = ApprovalRequest(
        request_id="r",
        path=f"Servers/{hidden}prod",
        action="ssh_execute",
        agent_name="agent",
        details={"command": f"rm{hidden}-rf /tmp/x"},
        target={"host": f"h{hidden}ost"},
    )

    message = approval_message(request)
    assert hidden not in message
    assert message.count(shown) == 3
