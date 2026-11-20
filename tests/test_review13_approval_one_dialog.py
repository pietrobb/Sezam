"""Review c78fd19 R13-11: parallel agent requests are asked one at a time.

Each request's dialog (and its grant question) must be answered before the
next one opens, and a request that expired or was cleared while it waited
for its turn is never shown.
"""

from __future__ import annotations

import threading
import time

from sezam.mcp import approval
from sezam.mcp.approval import ApprovalManager


def _install(monkeypatch, answer):
    open_now = []
    overlap = []
    shown = []

    def ask(message: str) -> bool:
        if open_now:
            overlap.append(message)
        open_now.append(message)
        shown.append(message)
        try:
            time.sleep(0.05)
            return answer(message)
        finally:
            open_now.remove(message)

    monkeypatch.setattr(approval, "_ask", ask)
    return shown, overlap


def test_parallel_requests_never_open_two_dialogs(monkeypatch):
    shown, overlap = _install(monkeypatch, lambda message: True)
    manager = ApprovalManager()
    approval.install_desktop_approval_handler(manager)

    threads = [
        threading.Thread(
            target=manager.request_approval,
            kwargs=dict(
                request_id=f"r{i}", path=f"Servers/{i}", action="use_secret:ssh",
                agent_name="agent", grant_minutes=5,
            ),
        )
        for i in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)

    assert overlap == []
    assert len(shown) == 8  # approval + grant question for each request
    # Each grant question follows its own request's approval directly.
    for first, second in zip(shown[::2], shown[1::2]):
        path = first.split("Vault entry: ", 1)[1].split("\n", 1)[0]
        assert "Also let AI agents" in second and path in second
    assert all(manager.check_and_consume(f"r{i}") == "approved" for i in range(4))


def test_request_cleared_while_waiting_is_not_shown(monkeypatch):
    release = threading.Event()

    def answer(message: str) -> bool:
        if "Servers/first" in message:
            release.wait(5)
        return True

    shown, _ = _install(monkeypatch, answer)
    manager = ApprovalManager()
    approval.install_desktop_approval_handler(manager)

    first = threading.Thread(
        target=manager.request_approval, args=("first", "Servers/first", "use_secret:ssh")
    )
    first.start()
    while not shown:
        time.sleep(0.01)
    second = threading.Thread(
        target=manager.request_approval, args=("second", "Servers/second", "use_secret:ssh")
    )
    second.start()
    time.sleep(0.1)
    manager.deny("second")  # e.g. the broker gave up or the vault locked
    release.set()
    first.join(5)
    second.join(5)

    assert not any("Servers/second" in m for m in shown)
    assert manager.check_and_consume("second") == "denied"
