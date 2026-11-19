"""AI broker TODO section 4 (S4a): L1 process hardening.

On Linux 'sezam mcp-serve' and 'sezam ssh-agent' call
prctl(PR_SET_DUMPABLE, 0) before opening the vault and refuse to start when
that fails. The real call is checked in child processes (the conftest keeps
the pytest process itself dumpable).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.mcp import hardening

SRC = str(Path(__file__).resolve().parents[1] / "src")
COMMANDS = [["mcp-serve"], ["ssh-agent"], ["ssh-agent", "--print-config"]]
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="prctl is Linux only")


def _fake_prctl(monkeypatch, set_rc: int = 0, dumpable_after: int = 0) -> list:
    calls = []

    def prctl(option, *args):
        calls.append((option, *args))
        if option == hardening.PR_SET_DUMPABLE:
            return set_rc
        if option == hardening.PR_GET_DUMPABLE:
            return dumpable_after
        return -1

    monkeypatch.setattr(hardening, "_LINUX", True)
    monkeypatch.setattr(hardening, "_prctl", lambda: prctl)
    return calls


# ── harden_process ──


def test_sets_and_confirms_not_dumpable(monkeypatch):
    calls = _fake_prctl(monkeypatch)
    assert hardening.harden_process() is True
    assert calls == [(hardening.PR_SET_DUMPABLE, 0, 0, 0, 0), (hardening.PR_GET_DUMPABLE, 0, 0, 0, 0)]


def test_failing_prctl_raises(monkeypatch):
    _fake_prctl(monkeypatch, set_rc=-1)
    with pytest.raises(hardening.HardeningError, match="PR_SET_DUMPABLE"):
        hardening.harden_process()


def test_still_dumpable_after_prctl_raises(monkeypatch):
    _fake_prctl(monkeypatch, dumpable_after=1)
    with pytest.raises(hardening.HardeningError, match="still dumpable"):
        hardening.harden_process()


def test_missing_prctl_raises(monkeypatch):
    def missing():
        raise AttributeError("prctl")

    monkeypatch.setattr(hardening, "_LINUX", True)
    monkeypatch.setattr(hardening, "_prctl", missing)
    with pytest.raises(hardening.HardeningError, match="cannot call prctl"):
        hardening.harden_process()


def test_other_platforms_do_not_call_prctl(monkeypatch):
    def forbidden():
        raise AssertionError("prctl must not be called")

    monkeypatch.setattr(hardening, "_LINUX", False)
    monkeypatch.setattr(hardening, "_prctl", forbidden)
    assert hardening.harden_process() is False


# ── CLI: hardened before the vault opens, fail closed ──


@pytest.mark.parametrize("args", COMMANDS, ids=" ".join)
def test_cli_hardens_before_opening_the_vault(monkeypatch, args):
    order = []
    calls = _fake_prctl(monkeypatch)
    real = hardening.harden_process
    monkeypatch.setattr(hardening, "harden_process", lambda: (order.append("harden"), real())[1])

    def open_vault():
        order.append("open")
        raise SystemExit(3)

    monkeypatch.setattr(cli, "_open_vault", open_vault)
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == 3
    assert order == ["harden", "open"]
    assert calls[0] == (hardening.PR_SET_DUMPABLE, 0, 0, 0, 0)


@pytest.mark.parametrize("args", COMMANDS, ids=" ".join)
@pytest.mark.parametrize("failure", [{"set_rc": -1}, {"dumpable_after": 1}])
def test_cli_refuses_to_start_when_hardening_fails(monkeypatch, args, failure):
    _fake_prctl(monkeypatch, **failure)
    opened = []
    monkeypatch.setattr(cli, "_open_vault", lambda: opened.append(True))
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == 1
    assert "Refusing to start" in result.output
    assert opened == []


# ── real prctl in child processes ──


def _child(code: str, *args: str) -> subprocess.Popen:
    env = dict(os.environ, PYTHONPATH=SRC + os.pathsep + os.environ.get("PYTHONPATH", ""))
    return subprocess.Popen(
        [sys.executable, "-c", code, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )


def _has_cap_sys_ptrace() -> bool:
    with open("/proc/self/status") as status:
        for line in status:
            if line.startswith("CapEff:"):
                return bool(int(line.split()[1], 16) >> 19 & 1)
    return False


def _readable(pid: int, name: str) -> bool:
    try:
        with open(f"/proc/{pid}/{name}", "rb") as f:
            f.read(1)
        return True
    except PermissionError:
        return False


@linux_only
def test_real_prctl_makes_the_process_not_dumpable():
    child = _child(
        "from sezam.mcp import hardening as h;"
        "print(h.harden_process(), h._prctl()(h.PR_GET_DUMPABLE, 0, 0, 0, 0))"
    )
    out, err = child.communicate(timeout=60)
    assert child.returncode == 0, err
    assert out.split() == ["True", "0"]


_CLI_CHILD = """
import sys, time
from sezam import cli
from sezam.mcp import hardening as h

def open_vault():
    print("dumpable=%d" % h._prctl()(h.PR_GET_DUMPABLE, 0, 0, 0, 0), flush=True)
    time.sleep(60)
    sys.exit(0)

cli._open_vault = open_vault
cli.main(sys.argv[1:])
"""


@linux_only
@pytest.mark.parametrize("args", COMMANDS, ids=" ".join)
def test_real_cli_process_cannot_be_read_by_the_same_user(args):
    """Same user, no CAP_SYS_PTRACE: /proc/<pid>/mem and environ of the
    broker are closed once it reaches the vault; a plain child stays open,
    so the check does detect the difference."""
    control = _child("import time; print('up', flush=True); time.sleep(60)")
    broker = _child(_CLI_CHILD, *args)
    try:
        assert control.stdout.readline().strip() == "up"
        line = broker.stdout.readline().strip()
        assert line == "dumpable=0", broker.stderr.read() if not line else line
        if _has_cap_sys_ptrace():
            pytest.skip("running with CAP_SYS_PTRACE: /proc access is not restricted")
        assert _readable(control.pid, "environ")
        assert not _readable(broker.pid, "environ")
        assert not _readable(broker.pid, "mem")
    finally:
        for child in (control, broker):
            child.kill()
            child.communicate()
