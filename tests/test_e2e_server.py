"""E2E server tests — wrappers around the standalone E2E scripts.

These tests are DESTRUCTIVE — they clean the entire server DB.
Only run when explicitly requested:

    pytest -m e2e_server -v

Requires:
  - Explicit SEZAM_SERVER; fresh mode accepts only a loopback isolated stack
  - Set SEZAM_E2E=1 to enable
  - Remote SSH reset additionally requires explicit target+host confirmation

Individual test scripts can also be run directly:
    python scripts/test_e2e_real.py
    python scripts/test_multiuser_e2e.py
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

pytestmark = [
    pytest.mark.e2e_server,
    pytest.mark.skipif(
        not os.environ.get("SEZAM_E2E"),
        reason="Set SEZAM_E2E=1 to run E2E server tests (DESTRUCTIVE — cleans DB)",
    ),
]


class TestSingleUserE2E:
    """Single admin: bootstrap, vault CRUD, push/pull, second device verify."""

    def test_full_lifecycle(self):
        """38 checks: bootstrap → create entries → push → pull on second vault → verify."""
        result = subprocess.run(
            [sys.executable, "scripts/test_e2e_real.py"],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        assert result.returncode == 0, f"E2E single-user failed:\n{result.stdout}\n{result.stderr}"
        assert "ALL TESTS PASSED" in result.stdout


class TestMultiUserE2E:
    """Multi-user: admin + colleague, invitations, approval, sync, revocation."""

    def test_full_lifecycle(self):
        """53 checks across 12 phases: bootstrap → invite → approve → sync → revoke."""
        result = subprocess.run(
            [sys.executable, "scripts/test_multiuser_e2e.py"],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        assert result.returncode == 0, f"E2E multi-user failed:\n{result.stdout}\n{result.stderr}"
        assert "ALL 54 TESTS PASSED" in result.stdout or "ALL TESTS PASSED" in result.stdout
