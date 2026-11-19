"""Review d615826 (tooling): with a Node older than 24.7 (no crypto.argon2Sync)
the web-client tests failed deep in their harness instead of being skipped.

A fake Node 22 on PATH answers ``--version`` like the real one and fails every
script the way Node 22 does; the web tests must report a skip that names the
required version, and none may fail.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGETS = [
    "tests/test_review_web.py",  # module-level skip
    "tests/test_web_tab.py",  # WebTab harness
    "tests/test_username_normalize_n3b.py",  # per-test skip
    "tests/test_crypto.py::TestPasswordChangeRecovery::"
    "test_web_shamir_split_matches_python_for_every_threshold_combination",
]


def _fake_node(directory: Path) -> None:
    error = "TypeError: crypto.argon2Sync is not a function"
    if os.name == "nt":
        (directory / "node.cmd").write_text(
            "@echo off\r\n"
            'if "%~1"=="--version" (echo v22.12.0& exit /b 0)\r\n'
            f"echo {error} 1>&2\r\nexit /b 1\r\n",
            encoding="ascii",
        )
    else:
        script = directory / "node"
        script.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "--version" ]; then echo v22.12.0; exit 0; fi\n'
            f"echo '{error}' >&2\nexit 1\n",
            encoding="ascii",
        )
        script.chmod(0o755)


def test_web_tests_skip_with_a_reason_under_node_22(tmp_path):
    _fake_node(tmp_path)
    env = dict(os.environ)
    env["PATH"] = str(tmp_path) + os.pathsep + "".join(
        p + os.pathsep for p in env.get("PATH", "").split(os.pathsep) if p
        and not (Path(p) / ("node.exe" if os.name == "nt" else "node")).exists()
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider", *TARGETS],
        cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=600,
    )
    out = result.stdout + result.stderr
    summary = out.strip().splitlines()[-1]
    assert "failed" not in summary and "error" not in summary, out[-6000:]
    assert "skipped" in summary, out[-6000:]
    assert "Node >= 24.7" in out, out[-6000:]
