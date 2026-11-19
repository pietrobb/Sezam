"""``sezam broker install-service``: isolation level L2 (AI broker TODO,
section 4).

Prints, never runs, what an administrator needs to run ``sezam ssh-agent``
and ``sezam mcp-serve`` as their own OS user ``sezam-broker``, whose vault
the agent's user cannot read, with the agent's user in the group
``sezam-ai`` that may connect to the sockets and pull the brake. Every name
and path is checked against a strict pattern first, so nothing can be
injected into the printed commands.
"""

from __future__ import annotations

import re

RUN_DIR = "/run/sezam-broker"
HOME_DIR = "/var/lib/sezam-broker"
_LINUX_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_WINDOWS_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,19}")
_LINUX_PATH = re.compile(r"/[A-Za-z0-9_./+-]*")
_WINDOWS_PATH = re.compile(r"[A-Za-z]:\\[A-Za-z0-9_.\\ ()+-]*")

COMMANDS = (
    ("ssh-agent", "SSH agent", "ssh-agent --group {group} --deny-tier1"),
    ("mcp-serve", "MCP server", "mcp-serve --transport socket --group {group} --deny-tier1"),
)


def _check(kind: str, value: str, pattern: re.Pattern) -> str:
    if not pattern.fullmatch(value):
        raise ValueError(f"Unsafe {kind} for the printed commands: {value!r}")
    return value


def systemd(python: str, user: str, group: str, agent_user: str) -> str:
    _check("Python path", python, _LINUX_PATH)
    for kind, name in (("user", user), ("group", group), ("agent user", agent_user)):
        _check(kind, name, _LINUX_NAME)
    sezam = f"{python} -m sezam.cli"
    out = [
        "# Sezam broker as its own OS user (isolation level L2). Run as root.",
        "# Install Sezam outside /home (e.g. a venv in /opt/sezam): the units use ProtectHome=yes.",
    ]
    if python.startswith(("/home/", "/root/")):
        out.append(f"# WARNING: {python} is under a home directory the services cannot read.")
    out += [
        f"groupadd --system {group}",
        f"useradd --system --user-group --create-home --home-dir {HOME_DIR} "
        f"--shell /usr/sbin/nologin {user}",
        f"chmod 0700 {HOME_DIR}",
        f"usermod -aG {group} {user}",
        f"usermod -aG {group} {agent_user}   # the agent's user; log in again for it to apply",
        "",
        f"# The vault belongs to {user} only: create it (or restore a backup) as that user.",
        f"sudo -u {user} -H {sezam} init",
        "",
    ]
    for name, title, args in COMMANDS:
        out += [
            f"# /etc/systemd/system/sezam-{name}.service",
            "[Unit]",
            f"Description=Sezam {title} for AI agents (isolation L2)",
            "After=network-online.target",
            "",
            "[Service]",
            f"User={user}",
            f"Group={user}",
            f"SupplementaryGroups={group}",
            "RuntimeDirectory=sezam-broker",
            "RuntimeDirectoryMode=0750",
            "RuntimeDirectoryPreserve=yes",
            f"Environment=SEZAM_RUN_DIR={RUN_DIR}",
            "UMask=0077",
            f"ExecStart={sezam} {args.format(group=group)}",
            "Restart=on-failure",
            "LimitCORE=0",
            # Review 1141a20 H7: descriptors and threads well above what the
            # endpoints' own bounds can hold, so neither runs out first.
            "LimitNOFILE=4096",
            "TasksMax=512",
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            f"ReadWritePaths={HOME_DIR}",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    out += [
        "systemctl daemon-reload",
        "systemctl enable --now sezam-ssh-agent.service sezam-mcp-serve.service",
        "",
        f"# Unlock as {user} (the session KEK goes to that user's keyring; without a",
        "# keyring backend for it the broker stays locked):",
        f"sudo -u {user} -H env SEZAM_RUN_DIR={RUN_DIR} {sezam} unlock",
        "",
        f"# The agent's user ({agent_user}), e.g. in ~/.profile and ~/.ssh/config:",
        f"export SEZAM_RUN_DIR={RUN_DIR}",
        f"#   IdentityAgent {RUN_DIR}/agent.sock",
        f"#   MCP socket    {RUN_DIR}/sezam_mcp.sock",
        "#   'sezam ai off' and 'sezam ai status' reach the brokers through brake-<pid>.sock;",
        f"#   locking, unlocking and 'sezam ai on' stay with {user}.",
        "# Tier 1 entries are refused (--deny-tier1): a service has no desktop for the dialog.",
    ]
    return "\n".join(out) + "\n"


def windows(python: str, user: str, group: str, agent_user: str) -> str:
    _check("Python path", python, _WINDOWS_PATH)
    for kind, name in (("user", user), ("group", group), ("agent user", agent_user)):
        _check(kind, name, _WINDOWS_NAME)
    out = [
        "REM Sezam broker as its own Windows user (isolation level L2). Run in an elevated cmd.",
        f"net localgroup {group} /add",
        f"net user {user} * /add",
        f"net localgroup {group} {user} /add",
        f"net localgroup {group} {agent_user} /add",
        "",
        f"REM The vault belongs to {user} only: create it (or restore a backup) as that user.",
        f'runas /user:{user} "\\"{python}\\" -m sezam.cli init"',
        "",
        f"REM Start both brokers at boot as {user} (asks for its password).",
    ]
    for name, _, args in COMMANDS:
        out.append(
            f'schtasks /Create /TN "Sezam\\{name}" /SC ONSTART /RL LIMITED /RU {user} /RP * '
            f'/TR "\\"{python}\\" -m sezam.cli {args.format(group=group)}"'
        )
    out += [
        "",
        f"REM Unlock as {user}:",
        f'runas /user:{user} "\\"{python}\\" -m sezam.cli unlock"',
        "",
        f"REM The agent's user ({agent_user}):",
        f"REM   IdentityAgent \\\\.\\pipe\\sezam-ssh-agent-{user}",
        "REM   MCP pipe      \\\\.\\pipe\\sezam_mcp",
        "REM   'sezam ai off' and 'sezam ai status' reach the brokers through their brake pipes;",
        f"REM   locking, unlocking and 'sezam ai on' stay with {user}.",
        "REM Tier 1 entries are refused (--deny-tier1): a task has no desktop for the dialog.",
    ]
    return "\r\n".join(out) + "\r\n"
