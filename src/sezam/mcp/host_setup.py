"""``sezam ai-host-setup``: the commands that prepare a server account for
an AI that logs in only with Sezam SSH certificates (AI broker TODO,
section 3, isolation level L3).

The script is only printed, never run. It holds no secret: the CA's public
key, the account name and fixed paths. Every value that reaches the shell
is validated and quoted.
"""

from __future__ import annotations

import re
import shlex
from typing import Optional

import paramiko

from . import ssh_cert
from .ssh import SSHBrokerError, SSHCredentials, _load_private_key

# POSIX portable user name, as useradd accepts it by default.
_USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
# One sudo command: an absolute program and plain arguments; no wildcards,
# quotes, commas, backslashes or other sudoers syntax. '=' and ':' are
# allowed in arguments only escaped (_sudoers_command): unescaped they end
# the command and start a new rule, e.g. 'x : ALL = NOPASSWD: ALL' (review
# d615826).
_SUDO_COMMAND = re.compile(r"/[A-Za-z0-9._/-]+( [A-Za-z0-9._/=:@+-]+)*")


def _sudoers_command(command: str) -> str:
    """A validated --sudo-command as a sudoers Cmnd: '=' and ':' escaped.

    Review 7c10379: a Cmnd without arguments allows ANY arguments in
    sudoers, so '--sudo-command /usr/bin/systemctl' let the AI run
    'systemctl edit --full ssh' (root). Without arguments it gets '""',
    which sudoers reads as 'no arguments'."""
    escaped = command.replace(":", "\\:").replace("=", "\\=")
    return escaped if " " in command else escaped + ' ""'


# Places an unprivileged account can usually write (review 1141a20): a root
# command there is one the AI can replace.
_WRITABLE_TOPS = ("/home", "/tmp", "/var/tmp", "/dev/shm", "/run/user", "/var/www")


# Programs that run code named by their arguments (or a shell when given
# none): as a sudo command they are only safe with a fixed script file.
_INTERPRETER = re.compile(
    r"(ba|da|k|z|a|c|tc|fi|mk|r)?sh|busybox|env|python[0-9.]*|pypy[0-9.]*|perl[0-9.]*"
    r"|ruby[0-9.]*|node(js)?|php[0-9.]*|lua[0-9.]*|tclsh[0-9.]*|wish[0-9.]*|[gmn]?awk"
    r"|sudo|su|doas|runuser|xargs|nohup|timeout|nice|ionice|setsid|stdbuf|chroot"
    r"|script|expect|pwsh|rscript|julia|guile|sbcl|ghci?|runghc|deno|bun"
)


# Programs that run the program named by their arguments: never a sudo command.
_WRAPPER = re.compile(
    r"busybox|env|sudo|su|doas|runuser|xargs|nohup|timeout|nice|ionice|setsid|stdbuf|chroot|script|expect"
)

# Review 8bc70f7 R14-M4: where the system's programs live. One of them is a
# sudo command only in a shape of _SYSTEM_COMMANDS; a list of what is unsafe
# missed 'make install' (the Makefile where the AI starts sudo), 'git pull'
# (its hooks), 'systemctl status' (a pager: '!sh') and 'tee /etc/sudoers'.
_TOOL_DIRS = (
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/games", "/usr/local/games",
    "/lib", "/lib32", "/lib64", "/usr/lib", "/usr/lib32", "/usr/lib64", "/usr/libexec", "/usr/share", "/snap",
)
_UNIT = r"[A-Za-z0-9_@][A-Za-z0-9_.@-]*"
_APACHE = re.compile(r"graceful|configtest|-k graceful")
# Exact argument shapes, none of which pages, edits or reads the caller's
# directory; the unit is fixed by the operator in the sudoers rule.
_SYSTEM_COMMANDS = {
    "systemctl": re.compile(rf"(restart|reload|try-restart|reload-or-restart|start|stop) {_UNIT}"),
    "service": re.compile(rf"{_UNIT} (restart|reload|start|stop)"),
    "nginx": re.compile(r"-t|-s reload"),
    "apachectl": _APACHE,
    "apache2ctl": _APACHE,
}


# Review 18c300f R16-L1: where the operator's own root scripts live. Any other
# program outside the system directories passed as 'a script', so
# '/opt/conda/bin/ipython' (a root shell) did; now that is an allowlist too.
SCRIPT_DIR = "/usr/local/sbin"


def _system_program(path: str) -> bool:
    return any(path.startswith(top + "/") for top in _TOOL_DIRS)


def _not_listed() -> HostSetupError:
    shapes = (
        "systemctl restart|reload|try-restart|reload-or-restart|start|stop <unit>, "
        "service <unit> restart|reload|start|stop, nginx -t, nginx -s reload, "
        "apachectl|apache2ctl graceful|configtest"
    )
    return HostSetupError(
        f"--sudo-command may run a system program only as one of: {shapes}. For anything else "
        f"write a root-owned script in {SCRIPT_DIR} (e.g. {SCRIPT_DIR}/deploy) "
        f"and give that, or '/bin/sh {SCRIPT_DIR}/deploy'."
    )


def _root_only_path(path: str, what: str, web_root: Optional[str]) -> None:
    parts = path.split("/")[1:]
    if any(p in ("", ".", "..") for p in parts):
        raise HostSetupError(f"--sudo-command must name {what} by a plain absolute path (no '.', '..' or '//').")
    under = [*_WRITABLE_TOPS, *([web_root] if web_root else [])]
    if any(path == top or path.startswith(top + "/") for top in under):
        raise HostSetupError(
            f"--sudo-command must use {what} only root can change, not one in the web root, "
            "a home or a temporary directory."
        )


def _sudo_paths(command: str, web_root: Optional[str]) -> tuple[list[str], Optional[str]]:
    """The program of a --sudo-command and every path among its arguments,
    refused where the AI may rewrite them; the printed script checks each
    of them on the host as well (_ROOT_ONLY). With them the operator's
    script the command runs (None for a listed system command): one in
    SCRIPT_DIR, which the host checks is still there after resolving
    symlinks and, run directly, is a script (_OPERATOR_SCRIPT).

    Review 1141a20: '--web-root /var/www/site --sudo-command
    /var/www/site/deploy.sh' gave root to whatever the AI wrote into
    deploy.sh. Review c78fd19 R13-11: only the program was checked, so
    '/bin/sh /var/www/site/deploy.sh' did the same through an argument,
    '/bin/bash' alone was a root shell and 'python3 -m x' or 'sh deploy.sh'
    ran code from the directory the AI starts sudo in."""
    program, *args = command.split(" ")
    _root_only_path(program, "the program", web_root)
    paths = [program]
    for arg in args:
        if arg.startswith("/"):
            _root_only_path(arg, "a file", web_root)
            paths.append(arg)
        elif "/" in arg:
            raise HostSetupError(
                "--sudo-command arguments that name files must be absolute paths "
                "(a relative one is resolved where the AI runs sudo)."
            )
    name = program.rsplit("/", 1)[1].lower()
    if _INTERPRETER.fullmatch(name):
        if _WRAPPER.fullmatch(name) or not _system_program(program):
            raise _not_listed()
        if not (args and args[0].startswith("/")):
            raise HostSetupError(
                "--sudo-command may run a shell or interpreter only with a script given "
                "by an absolute path as its first argument (e.g. /bin/sh /usr/local/sbin/deploy)."
            )
        script = args[0]
    elif _system_program(program):
        listed = _SYSTEM_COMMANDS.get(name)
        if listed is None or not listed.fullmatch(" ".join(args)):
            raise _not_listed()
        return paths, None
    else:
        script = program
    if not script.startswith(SCRIPT_DIR + "/"):
        raise _not_listed()
    return paths, script


# Shell check run on the host before the sudoers rule is installed: the
# program and every directory above it, also after resolving symlinks,
# belong to root and nobody else may write them.
_ROOT_ONLY = r"""sezam_root_only() {
  for start in "$1" "$(readlink -f -- "$1")"; do
    p=$start
    while :; do
      o=$(stat -c '%u %a' -- "$p") || { echo "Sezam: $p does not exist." >&2; return 1; }
      if [ "${o% *}" != 0 ]; then echo "Sezam: $p does not belong to root." >&2; return 1; fi
      if [ ! -L "$p" ] && [ $(( 0${o#* } & 022 )) -ne 0 ]; then
        echo "Sezam: $p may be changed by others than root." >&2; return 1
      fi
      [ "$p" = / ] && break
      p=$(dirname -- "$p")
    done
  done
}"""

# R14-M4 / R16-L1 on the host: the operator's script resolves to a file in
# SEZAM_SCRIPTS (not a symlink to /usr/bin/make or /opt/conda/bin/ipython)
# and, when sudo runs it directly ($2 = run), is a script, not a program
# copied there.
_OPERATOR_SCRIPT = (
    "sezam_operator_script() {\n"
    '  r=$(readlink -f -- "$1") && [ -f "$r" ] || { echo "Sezam: $1 is not a file." >&2; return 1; }\n'
    '  case "$r" in\n'
    '    "$SEZAM_SCRIPTS"/*) ;;\n'
    '    *) echo "Sezam: $1 is $r, not a script in $SEZAM_SCRIPTS; --sudo-command runs a system program'
    ' only as listed." >&2\n'
    "       return 1;;\n"
    "  esac\n"
    '  if [ "$2" = run ] && [ "$(head -c 2 -- "$r")" != "#!" ]; then\n'
    '    echo "Sezam: $1 has no #! line: a program there is run only by a shell or interpreter." >&2\n'
    "    return 1\n"
    "  fi\n"
    "}"
)


_RESERVED_USERS = {"root", "daemon", "bin", "sys", "nobody", "sshd"}

SSHD_CONFIG = "/etc/ssh/sshd_config"
PRINCIPALS_DIR = "/etc/ssh/principals"


class HostSetupError(ValueError):
    """The entry or an option cannot be turned into a safe setup script."""


def _comment(text: str) -> str:
    """A value safe inside a shell comment line (no line breaks/controls)."""
    return "".join(ch if ch.isprintable() else "?" for ch in text)


_SYSTEM_DIRS = {"bin", "boot", "dev", "etc", "lib", "lib32", "lib64", "proc", "root", "run", "sbin", "sys", "usr"}


def _web_root(value: str) -> str:
    parts = [p for p in value.split("/") if p]
    if (
        not value.startswith("/")
        or not value.isprintable()
        or len(parts) < 2
        or any(p in (".", "..") for p in parts)
        or parts[0] in _SYSTEM_DIRS
    ):
        raise HostSetupError(
            "--web-root must be an absolute directory at least two levels deep, "
            "outside system directories (e.g. /var/www/site)."
        )
    return "/" + "/".join(parts)


def _reaper(user: str, ttl: int) -> list[str]:
    """Root reaper for an already validated account name, run every 30-60 s.

    A session is the root-owned sshd monitor ``sshd: <user> [priv]`` (or
    ``sshd-session: …``), which the account cannot fake; its age counts from
    the TCP connection. Sessions older than the TTL are killed; with no live
    session left, so is every process of the account. If ``ps`` yields
    nothing, nothing counts as live (fail-closed).
    """
    name = f"sezam-ai-reap-{user}"
    path = f"/usr/local/sbin/{name}"
    return [
        "install -d -m 0755 /usr/local/sbin",
        f"cat > {path} <<'SEZAM_EOF'",
        "#!/bin/sh",
        f"# Sezam (ai-host-setup): a session of {user} lives at most {ttl} minutes;",
        "# without a live session no process of the account survives.",
        f"U={user}",
        f"MAX={ttl * 60}",
        "live=0",
        "for s in $(ps -eo pid=,uid=,etimes=,args= | awk -v u=\"$U\" -v max=\"$MAX\" '",
        "  $2 == 0 && ($4 == \"sshd:\" || $4 == \"sshd-session:\") && $5 == u && $6 == \"[priv]\" && NF == 6 {",
        "    print ($3 < max ? \"live\" : $1) }'); do",
        "  if [ \"$s\" = live ]; then live=1; else pkill -KILL -P \"$s\"; kill -KILL \"$s\"; fi",
        "done 2>/dev/null",
        "[ \"$live\" = 1 ] || pkill -KILL -u \"$U\"",
        "exit 0",
        "SEZAM_EOF",
        f"chmod 0700 {path}",
        "if [ -d /run/systemd/system ]; then",
        f"cat > /etc/systemd/system/{name}.service <<'SEZAM_EOF'",
        "[Unit]",
        f"Description=Sezam: end expired sessions of the AI account {user}",
        "[Service]",
        "Type=oneshot",
        f"ExecStart={path}",
        "SEZAM_EOF",
        f"cat > /etc/systemd/system/{name}.timer <<'SEZAM_EOF'",
        "[Timer]",
        "OnBootSec=30s",
        "OnUnitActiveSec=30s",
        "AccuracySec=1s",
        "[Install]",
        "WantedBy=timers.target",
        "SEZAM_EOF",
        "  systemctl daemon-reload",
        f"  systemctl enable --now {name}.timer",
        "elif [ -d /etc/cron.d ]; then",
        f"  printf '%s\\n' '* * * * * root {path}' > /etc/cron.d/{name}",
        f"  chmod 0644 /etc/cron.d/{name}",
        "else",
        "  echo 'Neither systemd nor cron runs the reaper; the account is not set up.' >&2",
        "  exit 1",
        "fi",
    ]


def host_setup_script(
    entry: dict,
    path: str,
    *,
    web_root: Optional[str] = None,
    sudo_command: Optional[str] = None,
) -> str:
    """The setup script for an AI SSH CA entry (see the module docstring)."""
    try:
        credentials = SSHCredentials.from_entry(entry)
    except SSHBrokerError as exc:
        raise HostSetupError(str(exc)) from None
    if not credentials.ssh_ca:
        raise HostSetupError("Not an AI SSH CA entry (needs the field ssh_ca = yes).")
    try:
        ca_key = _load_private_key(credentials.private_key, credentials.passphrase)
    except SSHBrokerError as exc:
        raise HostSetupError(str(exc)) from None
    if not isinstance(ca_key, paramiko.Ed25519Key):
        raise HostSetupError("The SSH CA key must be Ed25519.")
    try:
        ttl = ssh_cert.ttl_minutes(credentials.cert_ttl_minutes)
        ssh_cert.source_addresses(credentials.source_address)
    except ssh_cert.CertificateConfigError as exc:
        raise HostSetupError(str(exc)) from None
    user = credentials.username
    if not _USERNAME.fullmatch(user) or user in _RESERVED_USERS:
        raise HostSetupError(
            "The entry's username must be a dedicated account name "
            "(lowercase letters, digits, '_' or '-', not root)."
        )
    if sudo_command is not None and not _SUDO_COMMAND.fullmatch(sudo_command):
        raise HostSetupError(
            "--sudo-command must be one absolute command with plain arguments "
            "(no wildcards, quotes or sudoers syntax)."
        )
    root = _web_root(web_root) if web_root is not None else None
    sudo_paths, sudo_script = _sudo_paths(sudo_command, root) if sudo_command is not None else ([], None)

    q = shlex.quote
    ca_file = f"/etc/ssh/sezam_ai_ca_{user}.pub"
    principals = f"{PRINCIPALS_DIR}/{user}"
    marker = f"# sezam-ai-host-setup {user}"
    ca_line = f"ssh-ed25519 {ca_key.get_base64()} sezam-ai-ca"

    out = [
        "#!/bin/sh",
        f"# Sezam AI host setup for entry {_comment(path)}",
        f"# (user {user} on {_comment(credentials.host)}:{credentials.port}).",
        "# Printed by 'sezam ai-host-setup'; Sezam never runs it. Review it, then",
        "# run it as root on that host.",
        "#",
        "# The account then accepts only short-lived certificates from this Sezam",
        "# SSH CA: no authorized_keys, so a key the AI adds itself does not work.",
        "# Kill switch: 'sezam ai off' (or the mobile brake) makes the CA stop",
        f"# signing; a certificate already issued expires within {ttl} minutes.",
        "# Sezam cannot reach this server, so open sessions are ended here: a",
        f"# session lives at most {ttl} minutes and, once no session is left,",
        "# every process of the account is killed (step 2). After the brake",
        f"# nothing of the account is left within {ttl} minutes (twice that if",
        "# the AI logs in again with a certificate it still holds) plus one",
        f"# reaper tick. Immediate cut-off: pkill -KILL -u {q(user)}",
        "set -eu",
        "",
        "# 1. A dedicated account without sudo (keep it out of sudo/wheel/adm).",
        f"id -u {q(user)} >/dev/null 2>&1 || useradd --create-home --shell /bin/bash {q(user)}",
        "# '*': no password login, yet not locked ('!' would also refuse",
        "# certificates when sshd runs without PAM).",
        f"usermod -p '*' {q(user)}",
        "",
        "# 2. Nothing that outlives the kill switch: no cron/at jobs, no lingering",
        "#    user services, and a root reaper that ends sessions older than the",
        "#    certificate TTL and every process of the account once no session",
        "#    is left (also what 'setsid nohup' detached).",
        "touch /etc/cron.deny /etc/at.deny",
        f"grep -qxF {q(user)} /etc/cron.deny || echo {q(user)} >> /etc/cron.deny",
        f"grep -qxF {q(user)} /etc/at.deny || echo {q(user)} >> /etc/at.deny",
        f"if command -v loginctl >/dev/null 2>&1; then loginctl disable-linger {q(user)}; fi",
        *_reaper(user, ttl),
        "",
    ]
    if root is not None:
        out += [
            "# 3. The directory the AI may change, through the account's group.",
            f"chgrp -R {q(user)} {q(root)}",
            f"chmod -R g+rwX {q(root)}",
            f"find {q(root)} -type d -exec chmod g+s {{}} +",
            "",
        ]
    if sudo_command is not None:
        sudoers = f"/etc/sudoers.d/sezam-ai-{user}"
        staged = f"/etc/sudoers.d/.sezam-ai-{user}.tmp"  # names with '.' are ignored by sudo
        out += [
            "# 4. Exactly one command as root, checked before it takes effect: only",
            "#    root may change the program and the files it is given, or the AI",
            "#    could rewrite them.",
            _ROOT_ONLY,
            *(f"sezam_root_only {q(p)}" for p in sudo_paths),
            *((f"SEZAM_SCRIPTS={SCRIPT_DIR}", _OPERATOR_SCRIPT,
               f"sezam_operator_script {q(sudo_script)} {'run' if sudo_paths[0] == sudo_script else 'arg'}")
              if sudo_script else ()),
            f"printf '%s\\n' {q(f'{user} ALL=(root) NOPASSWD: {_sudoers_command(sudo_command)}')} > {staged}",
            f"visudo -cf {staged}",
            f"chmod 0440 {staged}",
            f"mv {staged} {sudoers}",
            "",
        ]
    out += [
        "# 5. Trust the Sezam CA for this account only, with its one principal.",
        f"install -d -m 0755 {PRINCIPALS_DIR}",
        f"printf '%s\\n' {q(ca_line)} > {ca_file}",
        f"printf '%s\\n' {q(user)} > {principals}",
        f"chmod 0644 {ca_file} {principals}",
        "",
        "# 6. sshd: certificates only, no forwarding. Appended once at the end of",
        "#    sshd_config, where a Match block cannot capture other settings.",
        f"if ! grep -qxF {q(marker)} {SSHD_CONFIG}; then",
        f"cat >> {SSHD_CONFIG} <<'SEZAM_EOF'",
        "",
        marker,
        f"Match User {user}",
        f"    TrustedUserCAKeys {ca_file}",
        "    AuthorizedKeysFile none",
        f"    AuthorizedPrincipalsFile {PRINCIPALS_DIR}/%u",
        "    PubkeyAuthentication yes",
        "    PasswordAuthentication no",
        "    KbdInteractiveAuthentication no",
        "    AllowAgentForwarding no",
        "    AllowTcpForwarding no",
        "    AllowStreamLocalForwarding no",
        "    X11Forwarding no",
        "    PermitTunnel no",
        "    PermitUserRC no",
        "SEZAM_EOF",
        "fi",
        "sshd -t",
        "systemctl reload ssh 2>/dev/null || systemctl reload sshd",
        "",
    ]
    return "\n".join(out)
