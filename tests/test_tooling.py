"""Tooling regressions for code review HEAD 2c7e809, section 4 (T1, T6)."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _pins(lines) -> dict[str, str]:
    pins = {}
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)(\[[^\]]+\])?==(\S+)", line)
        assert match, f"unpinned requirement: {line!r}"
        pins[match.group(1).lower()] = match.group(3)
    return pins


def test_t1_dev_extras_cover_everything_the_test_suite_imports():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dev = _pins(project["project"]["dependencies"])
    dev.update(_pins(project["project"]["optional-dependencies"]["dev"]))

    for tool in ("pytest", "pytest-asyncio", "httpx", "ruff"):
        assert tool in dev, tool
    server = _pins((ROOT / "server" / "requirements.in").read_text(encoding="utf-8").splitlines())
    for name, version in server.items():
        assert dev.get(name) == version, f"{name}: dev={dev.get(name)} server={version}"


def test_t6_ruff_is_configured_and_clean():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "S110" in project["tool"]["ruff"]["lint"]["select"]

    ruff = [sys.executable, "-m", "ruff"]
    if subprocess.run([*ruff, "--version"], capture_output=True).returncode != 0:
        if not shutil.which("ruff"):
            pytest.skip("ruff is not installed (pip install -e .[dev])")
        ruff = ["ruff"]
    result = subprocess.run(
        [*ruff, "check", "--no-cache", "--output-format", "concise"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# ── AI broker TODO section 11 (O4): CI ──

WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"


def _web_scripts() -> list[Path]:
    return sorted(
        p for p in (ROOT / "web").rglob("*.js") if "vendor" not in p.relative_to(ROOT).parts
    )


def test_o4_ci_runs_ruff_pytest_node_check_and_flutter():
    steps = [line.strip() for line in WORKFLOW.read_text(encoding="utf-8").splitlines()]
    runs = [s.removeprefix("- run: ") for s in steps if s.startswith("- run: ")]
    assert "python -m ruff check" in runs
    assert "python -m pytest -q" in runs
    assert "flutter analyze --no-fatal-infos" in runs and "flutter test" in runs
    node = [r for r in runs if "node --check" in r]
    assert node == ["git ls-files 'web/*.js' ':!:web/static/js/vendor/*' | xargs -n1 node --check"]


def _job(name: str) -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index(f"\n  {name}:\n")
    following = re.search(r"\n  [a-z][a-z-]*:\n", text[start + 1:])
    return text[start:start + 1 + following.start()] if following else text[start:]


def test_the_commit_check_has_flutter_for_phone_red_lines():
    """CI run 45584285599: the red line of 7bd91ce (SM22c) runs a phone test
    through `flutter test`; the commits job had no flutter, so the test skipped,
    pytest exited 0 and the check reported a red line that passes."""
    commits, python = _job("commits"), _job("python")
    version = re.search(r"flutter-version: (\S+)", python).group(1)
    assert "uses: subosito/flutter-action@v2" in commits
    assert f"flutter-version: {version}" in commits
    assert "libsodium-dev libsqlite3-dev" in commits  # the phone harness loads them directly


def test_o4_web_scripts_pass_node_check():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    scripts = _web_scripts()
    assert any(p.name == "app.js" for p in scripts)
    for script in scripts:
        result = subprocess.run([node, "--check", str(script)], capture_output=True, text=True)
        assert result.returncode == 0, f"{script}: {result.stderr}"
