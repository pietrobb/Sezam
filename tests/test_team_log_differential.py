"""R9-A2 (goal #367): the three team-log cores decide seeded random logs alike.

The review's original diverging scenario was not delivered with it, so this test
looks for divergences itself: tests/team_log_differential.py writes logs whose
state, answers or last-record error the Python reference decides, and the web
(node) and phone (Dart) cores must give exactly the same result.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from tests.node_support import node_cmd, requires_node
from tests.team_log_differential import scenarios
from tests.test_team_log_web import HARNESS, JS, JS_NAMES, ROOT

COUNT = 2000
VECTORS = scenarios(COUNT)


def _mismatches(results: list[dict]) -> list[str]:
    bad = []
    for scenario, got in zip(VECTORS["scenarios"], results, strict=True):
        if "error" in scenario:
            want = {"error": scenario["error"]}
        else:
            want = {"state": scenario["state"], "answers": [q["answer"] for q in scenario["questions"]]}
        if got != want:
            bad.append(f"{scenario['name']}: want {json.dumps(want)[:300]} got {json.dumps(got)[:300]}")
    return bad


@requires_node
def test_web_core_matches_python_on_random_logs():
    vendor = JS / "vendor"
    result = subprocess.run(
        [node_cmd(), "-e", HARNESS, str(vendor / "libsodium-sumo.min.js"),
         str(vendor / "libsodium-wrappers.min.js"), str(JS / "teamlog.js")],
        input=json.dumps({"vectors": VECTORS, "names": JS_NAMES}),
        capture_output=True, text=True, encoding="utf-8", timeout=600,
    )
    assert result.returncode == 0, result.stderr
    mismatches = _mismatches(json.loads(result.stdout))
    assert not mismatches, f"{len(mismatches)} divergences, first: " + "\n".join(mismatches[:5])


def test_phone_core_matches_python_on_random_logs(tmp_path):
    from tests.test_cross_client_password_change import _mobile_build_lock

    flutter = shutil.which("flutter")
    if flutter is None:
        if os.environ.get("SEZAM_REQUIRE_FLUTTER") == "1":
            pytest.fail("flutter is not installed but SEZAM_REQUIRE_FLUTTER=1")
        pytest.skip("flutter is not installed")
    path = tmp_path / "team_log_differential.json"
    path.write_text(json.dumps(VECTORS), encoding="utf-8")
    with _mobile_build_lock():
        proc = subprocess.run(
            [flutter, "test", "--reporter", "expanded", "test/team_log_vectors_test.dart"],
            cwd=ROOT / "mobile", env={**os.environ, "SEZAM_TEAM_LOG_VECTORS": str(path)},
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900,
        )
    output = proc.stdout + proc.stderr
    failed = [line for line in output.splitlines() if "[E]" in line][:5]
    assert proc.returncode == 0, "\n".join(failed) + "\n" + output[-4000:]
    assert f"+{COUNT + 1}" in output and "All tests passed" in output, output[-2000:]
