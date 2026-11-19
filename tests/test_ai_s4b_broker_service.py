"""AI broker TODO section 4 (S4b): isolation level L2.

A broker run as its own OS user shares its agent/MCP sockets with a group
(``--group``: 0660 in a 0750 run directory of that group; on Windows a pipe
DACL entry for the group without FILE_CREATE_PIPE_INSTANCE). The group also
gets a brake endpoint that accepts only ai_off and status; the control
endpoint with lock stays owner-only. 'sezam broker install-service' prints
(never runs) the setup.
"""

from __future__ import annotations

import json
import os
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.mcp import control, service
from sezam.mcp.server import SezamMCPServer, bind_unix_socket

SRC = str(Path(__file__).resolve().parents[1] / "src")
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="Unix socket permissions")
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="named pipe DACL")


def _own_group() -> str:
    if sys.platform == "win32":
        return "S-1-5-32-545"  # BUILTIN\Users, which every local user is in
    import grp

    # A sandbox may run the tests under a gid with no group entry; any
    # named group the process is in will do, as the broker needs one.
    for gid in (os.getegid(), *os.getgroups()):
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            continue
    pytest.skip("none of this process's groups has a name in the group database")


def _handlers(calls: list) -> dict:
    def make(name):
        def handler():
            calls.append(name)
            return {"status": "ok", "command": name, "persisted": True}

        return handler

    return {name: make(name) for name in control.COMMANDS}


@pytest.fixture
def endpoints():
    calls: list = []
    pair = control.ControlEndpoints(_handlers(calls), _own_group())
    pair.start()
    try:
        yield pair, calls
    finally:
        pair.stop()


# ── brake endpoint ──


def test_group_endpoint_cannot_be_given_lock():
    with pytest.raises(ValueError, match="lock"):
        control.ControlServer(_handlers([]), control.brake_endpoint(), _own_group())


def test_brake_endpoint_answers_only_ai_off_and_status(endpoints):
    pair, calls = endpoints
    owner, brake = pair.servers
    assert brake.path == control.brake_endpoint()
    assert control.send(brake.path, "status")["command"] == "status"
    assert control.send(brake.path, "ai_off")["command"] == "ai_off"
    assert control.send(brake.path, "lock") == {"status": "error", "code": "unknown_command"}
    assert control.send(brake.path, "ai_on")["code"] == "not_allowed"
    assert calls == ["status", "ai_off"]
    assert control.send(owner.path, "lock")["command"] == "lock"


def test_without_group_there_is_no_brake_endpoint():
    pair = control.ControlEndpoints(_handlers([]))
    pair.start()
    try:
        assert [s.path for s in pair.servers] == [control.endpoint()]
        assert control.brokers() == [[control.endpoint()]]
    finally:
        pair.stop()


def test_brokers_lists_control_first_then_brake(endpoints):
    assert control.brokers() == [[control.endpoint(), control.brake_endpoint()]]


def test_send_all_falls_back_to_the_brake_endpoint(endpoints, monkeypatch):
    """A group member cannot open the owner's control endpoint; the brake
    still reaches the broker, once."""
    pair, calls = endpoints
    real = control.send
    monkeypatch.setattr(
        control, "send", lambda path, *a: None if path == control.endpoint() else real(path, *a)
    )
    replies = control.send_all("ai_off")
    assert [(path, reply["command"]) for path, reply in replies] == [
        (control.brake_endpoint(), "ai_off")
    ]
    assert calls == ["ai_off"]


def test_failed_brake_endpoint_stops_the_control_endpoint(monkeypatch):
    pair = control.ControlEndpoints(_handlers([]), "no-such-group-sezam-test")
    with pytest.raises(OSError, match="no-such-group-sezam-test"):
        pair.start()
    assert control.send(control.endpoint(), "status") is None


def test_run_dir_comes_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("SEZAM_RUN_DIR", str(tmp_path / "shared"))
    assert control.configured_run_dir() == tmp_path / "shared"
    if sys.platform != "win32":
        assert SezamMCPServer.default_socket_path() == str(tmp_path / "shared" / "sezam_mcp.sock")
    monkeypatch.delenv("SEZAM_RUN_DIR")
    assert control.configured_run_dir() == Path.home() / ".sezam" / "run"


# ── Unix permissions ──


@posix_only
def test_group_sockets_are_0660_in_a_0750_group_directory(endpoints, tmp_path):
    import grp

    gid = grp.getgrnam(_own_group()).gr_gid
    pair, _ = endpoints
    owner, brake = (os.lstat(s.path) for s in pair.servers)
    assert stat.S_IMODE(owner.st_mode) == 0o600
    assert stat.S_IMODE(brake.st_mode) == 0o660 and brake.st_gid == gid
    run = os.lstat(control.run_dir())
    assert stat.S_IMODE(run.st_mode) == 0o750 and run.st_gid == gid

    agent = bind_unix_socket(tmp_path / "run" / "agent.sock", _own_group())
    agent.close()
    info = os.lstat(tmp_path / "run" / "agent.sock")
    assert stat.S_IMODE(info.st_mode) == 0o660 and info.st_gid == gid


@posix_only
def test_mcp_socket_takes_the_group(tmp_path):
    path = tmp_path / "run" / "sezam_mcp.sock"
    server = SezamMCPServer.__new__(SezamMCPServer)
    server._server_socket = None
    server._running = False
    thread = threading.Thread(
        target=server._run_unix_socket, args=(str(path), _own_group()), daemon=True
    )
    thread.start()
    deadline = time.time() + 5
    while not (path.exists() and server._running) and time.time() < deadline:
        time.sleep(0.01)
    try:
        assert stat.S_IMODE(os.lstat(path).st_mode) == 0o660
    finally:
        server._running = False
        thread.join(5)


@posix_only
def test_group_writable_run_dir_is_still_refused(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    os.chmod(run, 0o770)
    with pytest.raises(PermissionError, match="writable by other users"):
        bind_unix_socket(run / "agent.sock", _own_group())


def _nobody_child(code: str, extra_groups: list, env: dict) -> dict:
    out = subprocess.run(
        [sys.executable, "-c", code],
        user=65534,
        group=65534,
        extra_groups=extra_groups,
        env={**os.environ, "PYTHONPATH": SRC, **env},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


_PROBE = """
import json
from sezam.mcp import control
result = {"control_lock": control.send(control.endpoint(%(pid)d), "lock"),
          "brake_lock": control.send(control.brake_endpoint(%(pid)d), "lock"),
          "brake_status": control.send(control.brake_endpoint(%(pid)d), "status")}
result["send_all"] = [[p.rsplit("/", 1)[1], r] for p, r in control.send_all("ai_off")]
print(json.dumps(result))
"""


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() != 0, reason="needs root to run a second user"
)
def test_another_user_in_the_group_gets_only_the_brake(monkeypatch):
    """Real permissions: 'nobody' in the group reaches only the brake
    (ai_off, status), never the control endpoint with lock; without the
    group it reaches nothing."""
    import grp

    try:
        group = grp.getgrnam("users")
    except KeyError:
        pytest.skip("no 'users' group")
    base = Path(tempfile.mkdtemp(prefix="sezam-l2-", dir="/tmp"))
    os.chmod(base, 0o755)
    run = base / "run"
    monkeypatch.setattr(control, "run_dir", lambda: run)
    calls: list = []
    pair = control.ControlEndpoints(_handlers(calls), group.gr_name)
    pair.start()
    try:
        env = {"SEZAM_RUN_DIR": str(run)}
        member = _nobody_child(_PROBE % {"pid": os.getpid()}, [group.gr_gid], env)
        assert member["control_lock"] is None
        assert member["brake_lock"] == {"status": "error", "code": "unknown_command"}
        assert member["brake_status"]["command"] == "status"
        assert [(name, r["command"]) for name, r in member["send_all"]] == [
            (f"brake-{os.getpid()}.sock", "ai_off")
        ]
        stranger = _nobody_child(_PROBE % {"pid": os.getpid()}, [], env)
        assert stranger["brake_status"] is None
        assert stranger["send_all"] == []  # cannot even list the run directory
        assert calls == ["status", "ai_off"]
    finally:
        pair.stop()


# ── Windows pipe DACL ──


@windows_only
def test_pipe_dacl_adds_the_group_without_create_instance():
    from sezam.mcp import winpipe

    security = winpipe.OwnerOnlySecurity("S-1-5-32-545")
    try:
        owner = winpipe.current_user_sid()
        assert security.sddl == f"D:P(A;;GA;;;{owner})(A;;0x12019b;;;S-1-5-32-545)"
        assert not int("0x12019b", 16) & 0x4  # FILE_CREATE_PIPE_INSTANCE
    finally:
        security.close()
    assert winpipe.OwnerOnlySecurity().sddl.count("(A;") == 1


@windows_only
@pytest.mark.parametrize("name", ["no-such-group-sezam-test", os.environ.get("USERNAME", "x")])
def test_pipe_group_must_be_a_group(name):
    from sezam.mcp import winpipe

    with pytest.raises(OSError):
        winpipe.OwnerOnlySecurity(name)


# ── sezam ai off / status without a local vault (group member) ──


@pytest.fixture
def no_vault(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_get_vault_path", lambda: tmp_path / "none")


def test_ai_off_without_a_vault_brakes_through_the_brokers(no_vault, endpoints):
    _, calls = endpoints
    result = CliRunner().invoke(cli.main, ["ai", "off"])
    assert result.exit_code == 0, result.output
    assert "1 running broker(s) stopped" in result.output
    assert calls == ["ai_off"]


def test_ai_off_without_a_vault_fails_when_no_broker_confirms(no_vault):
    result = CliRunner().invoke(cli.main, ["ai", "off"])
    assert result.exit_code == 1
    assert "no running broker confirmed" in result.output


def test_ai_status_without_a_vault_lists_the_brokers(no_vault, endpoints):
    _, calls = endpoints
    result = CliRunner().invoke(cli.main, ["ai", "status"])
    assert result.exit_code == 0, result.output
    assert "No vault for this user" in result.output
    assert "Running MCP servers: 1" in result.output
    assert calls == ["status"]


# ── sezam broker install-service ──


def _install(*args: str):
    return CliRunner().invoke(
        cli.main, ["broker", "install-service", "--agent-user", "agent", *args]
    )


def _exec_args(text: str) -> list[list[str]]:
    return [shlex.split(line.split("=", 1)[1])[3:] for line in text.splitlines()
            if line.startswith("ExecStart=")]


def test_systemd_units(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("must not run anything"))
    result = _install("--platform", "linux", "--python", "/opt/sezam/bin/python")
    assert result.exit_code == 0, result.output
    text = result.output
    for line in (
        "useradd --system --user-group --create-home --home-dir /var/lib/sezam-broker "
        "--shell /usr/sbin/nologin sezam-broker",
        "chmod 0700 /var/lib/sezam-broker",
        "usermod -aG sezam-ai agent   # the agent's user; log in again for it to apply",
        "User=sezam-broker",
        "SupplementaryGroups=sezam-ai",
        "RuntimeDirectoryMode=0750",
        "Environment=SEZAM_RUN_DIR=/run/sezam-broker",
        "ProtectHome=yes",
        "LimitCORE=0",
        "ExecStart=/opt/sezam/bin/python -m sezam.cli ssh-agent --group sezam-ai --deny-tier1",
        "ExecStart=/opt/sezam/bin/python -m sezam.cli mcp-serve --transport socket "
        "--group sezam-ai --deny-tier1",
    ):
        assert line in text.splitlines()
    assert "WARNING" not in text


def test_printed_broker_commands_parse():
    """The ExecStart / schtasks arguments are real options of the commands."""
    text = _install("--platform", "linux", "--python", "/opt/sezam/bin/python").output
    commands = _exec_args(text)
    assert [c[0] for c in commands] == ["ssh-agent", "mcp-serve"]
    for command in commands:
        cli.main.commands[command[0]].make_context(command[0], command[1:])


def test_python_under_home_is_flagged():
    text = _install("--platform", "linux", "--python", "/home/u/venv/bin/python").output
    assert "WARNING: /home/u/venv/bin/python is under a home directory" in text


def test_windows_tasks():
    result = _install("--platform", "windows", "--python", r"C:\Program Files\Python311\python.exe")
    assert result.exit_code == 0, result.output
    text = result.output.replace("\r\n", "\n")
    assert "net localgroup sezam-ai agent /add" in text
    assert (
        'schtasks /Create /TN "Sezam\\ssh-agent" /SC ONSTART /RL LIMITED /RU sezam-broker /RP * '
        '/TR "\\"C:\\Program Files\\Python311\\python.exe\\" -m sezam.cli ssh-agent '
        '--group sezam-ai --deny-tier1"'
    ) in text
    assert "IdentityAgent \\\\.\\pipe\\sezam-ssh-agent-sezam-broker" in text


@pytest.mark.parametrize(
    "args",
    [
        ["--platform", "linux", "--python", "/opt/sezam/bin/python", "--group", "ai;rm -rf /"],
        ["--platform", "linux", "--python", "/opt/sezam/bin/python", "--user", "$(id)"],
        ["--platform", "linux", "--python", "/opt/my sezam/python"],
        ["--platform", "linux", "--python", "/opt/sezam/bin/python", "--agent-user", "a b"],
        ["--platform", "windows", "--python", 'C:\\Py\\python.exe" & calc & "'],
        ["--platform", "windows", "--python", "C:\\Py\\%PATH%\\python.exe"],
        ["--platform", "windows", "--python", "C:\\Py\\python.exe", "--group", "a&b"],
    ],
)
def test_unsafe_names_are_refused(args):
    result = _install(*args)
    assert result.exit_code == 1
    assert "Unsafe" in result.output


def test_service_module_never_imports_subprocess():
    assert "subprocess" not in Path(service.__file__).read_text(encoding="utf-8")
