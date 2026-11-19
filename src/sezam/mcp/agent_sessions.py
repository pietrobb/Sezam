"""SSH logins through ``sezam ssh-agent`` that ``sezam ai off`` cannot close.

Review d615826: the agent only signs the login. Once the AI's own ``ssh`` is
in, the shell on the server lives on after the brake, and nothing said so.
``sezam ai off`` now lists the hosts the agent signed logins for since AI
access was last turned on, and ``--terminate-remote`` logs in with each
plain-key entry and kills every other session of that account. A login with
a Sezam SSH certificate is ended by the reaper ``sezam ai-host-setup``
installs once the certificate's validity has passed; the CA key itself never
logs in, so those hosts are listed only.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import audit_view
from .ssh import SSHBrokerError, SSHManager

if TYPE_CHECKING:
    from ..vault.crud import Vault

DONE_MARK = "sezam-terminated"
KILLED = (
    "sessions killed, as the account reports (its own startup files run "
    "first, so an account the AI could write to can fake this)"
)


def terminate_command(nonce: str) -> str:
    """Every session (SID) of the account except this login's own; its
    processes, the shells and whatever they started, get SIGKILL.

    Review 7c10379: with OpenSSH privilege separation this login's sshd
    process (its parent) runs as the account in a session of its own; killed,
    it took the connection along before the mark came back. The script runs
    in a clean /bin/sh (no aliases, functions or PATH from the account's
    shell), and the mark carries a nonce of this run: a startup file that
    only prints the old fixed mark no longer reads as success.
    """
    script = (
        'me=$(ps -o sid= -p $$ | tr -d " "); '
        'conn=$(ps -o sid= -p $PPID | tr -d " "); '
        'for s in $(ps -o sid= -u "$(id -u)" | tr -d " " | sort -u); do '
        'case "$s" in "$me"|"$conn"|0) ;; *) pkill -KILL -s "$s";; esac; done; '
        f'echo "{DONE_MARK} {nonce}"'
    )
    return f"exec /usr/bin/env -i PATH=/usr/bin:/bin /bin/sh -c '{script}'"


@dataclass(frozen=True)
class AgentLogin:
    entry_id: str
    host: str
    port: int
    username: str
    certificate: bool

    @property
    def target(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"


def agent_logins(vault: "Vault") -> list[AgentLogin]:
    """Logins the agent signed since AI access was last turned on."""
    records = list(audit_view.ai_records(vault))
    last_on = max((r.at_ms for r in records if r.kind == "ai_on"), default=0)
    found: dict[tuple, AgentLogin] = {}
    for record in records:
        d = record.detail or {}
        if record.at_ms < last_on or record.kind != "mcp_ssh" or d.get("operation") != "agent_sign":
            continue
        login = AgentLogin(
            str(d.get("entry_id")), str(d.get("host")), int(d.get("port") or 22),
            str(d.get("username")), bool(d.get("cert_key_id")),
        )
        found[(login.entry_id, login.target)] = login
    return list(found.values())


def terminate(vault: "Vault", login: AgentLogin, manager: SSHManager | None = None) -> str:
    """Kill the account's other sessions on the login's host; the outcome as text."""
    if login.certificate:
        return "certificate login: ended by the host's reaper when the certificate expires"
    try:
        entry = vault.read_entry(login.entry_id)
    except KeyError:
        return "entry no longer exists"
    manager = manager or SSHManager()
    nonce = secrets.token_hex(8)
    try:
        result = manager.execute(entry, terminate_command(nonce), timeout=30)
    except SSHBrokerError as exc:
        return f"FAILED {exc.code}: {exc}"
    finally:
        manager.close_all()
    if f"{DONE_MARK} {nonce}" not in str(result.get("stdout", "")).splitlines():
        return f"FAILED: exit {result.get('exit_code')}, no confirmation from the host"
    return KILLED
