"""Review d615826 (tooling): without PySide6 (the optional ``gui`` extra) the
GUI tests errored instead of skipping: test_gui_full and test_gui_e2e_flow
imported PySide6 in autouse fixtures, and test_ai_r1_snapshots used the
``qapp`` fixture of pytest-qt, which is not a dev dependency.

A PySide6 package that refuses to import stands in for the missing one; the
GUI tests must skip, none may error.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

GUI_TESTS = [
    "tests/test_gui_full.py",
    "tests/test_gui_e2e_flow.py",
    "tests/test_gui_interactive.py",
    "tests/test_gui_autolock_activity_s6_s7.py",
    "tests/test_ai_s1d_gui_switch.py",
    "tests/test_leftover_window_timers.py",
    "tests/test_modal_watchdog.py",
    "tests/test_review_desktop_gui.py",
    "tests/test_review_gui_import_medium.py",
    "tests/test_review2_desktop_crit.py",
    "tests/test_ai_r1_snapshots.py::test_gui_server_connect_snapshots_first_and_fails_closed",
    "tests/test_ai_r1_snapshots.py::test_gui_import_snapshots_first_and_fails_closed",
    # Review c78fd19 R13-12: imported PySide6 in the test body.
    "tests/test_team_log_desktop.py::test_desktop_invitation_dialog_copies_anchor_fragment",
]


def test_gui_tests_skip_without_pyside6(tmp_path):
    blocked = tmp_path / "PySide6"
    blocked.mkdir()
    (blocked / "__init__.py").write_text('raise ImportError("no PySide6 here")\n', encoding="ascii")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp_path) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        # pytest-qt needs Qt too and is no dev dependency: off, as without it.
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:pytest-qt",
         *GUI_TESTS],
        cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=600,
    )
    out = result.stdout + result.stderr
    summary = out.strip().splitlines()[-1]
    assert "error" not in summary and "failed" not in summary, out[-6000:]
    assert "skipped" in summary, out[-6000:]
