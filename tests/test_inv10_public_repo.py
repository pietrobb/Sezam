"""INV-10 (docs/ROOT_CAUSE_PLAN.md): the public repository gives nothing away
and keeps its dependencies current (review 8bc70f7 H1, M9).

- Whatever a push publishes is scanned before it leaves: every new blob (a
  file added and deleted again within the push too), every path, every commit
  message and identity (property test over where a leak hides).
- Every dependency manifest in the tree has a Dependabot entry, so a new
  ecosystem cannot go unwatched.
- Every container base image is pinned by digest (a tag moves under us).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from scripts import public_hygiene as hygiene

ROOT = Path(__file__).resolve().parents[1]
NOREPLY = "1+dev@users.noreply.github.com"

# Manifest file name -> Dependabot ecosystem.
_ECOSYSTEMS = {
    "uv.lock": "uv",
    "requirements.txt": "pip",
    "Cargo.toml": "cargo",
    "pubspec.yaml": "pub",
    "package.json": "npm",
    "Dockerfile": "docker",
}


def _tracked() -> list[str]:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout")
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return [n for n in out.decode().split("\0") if n]


def _dependabot_entries() -> set[tuple[str, str]]:
    """(ecosystem, directory) pairs, without a YAML parser."""
    text = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    entries = set()
    for block in re.split(r"\n\s*-\s+(?=package-ecosystem:)", text)[1:]:
        eco = re.search(r'package-ecosystem:\s*"?([\w-]+)"?', block).group(1)
        directory = re.search(r'directory:\s*"?([^"\n]+?)"?\s*$', block, re.M).group(1)
        entries.add((eco, "/" + directory.strip("/")))
    return entries


def test_every_dependency_manifest_has_a_dependabot_entry():
    needed = set()
    for name in _tracked():
        path = Path(name)
        if path.name in _ECOSYSTEMS:
            directory = "/" + path.parent.as_posix().strip(".").strip("/")
            needed.add((_ECOSYSTEMS[path.name], directory))
    if any(n.startswith(".github/workflows/") for n in _tracked()):
        needed.add(("github-actions", "/"))
    assert needed, "no manifests found"
    # Every crate keeps its own Cargo.lock, so each needs its own entry.
    assert needed - _dependabot_entries() == set()


def test_every_dependabot_entry_is_one_grouped_monthly_pull_request():
    """A new entry must not open one pull request (and one e-mail) per package."""
    text = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    blocks = re.split(r"\n\s*-\s+(?=package-ecosystem:)", text)[1:]
    assert blocks
    for block in blocks:
        name = block.splitlines()[0]
        assert re.search(r'interval:\s*"?monthly"?', block), name
        assert re.search(r"open-pull-requests-limit:\s*1\b", block), name
        assert re.search(r'groups:\s*\n\s+[\w-]+:\s*\n\s+patterns:\s*\["\*"\]', block), name


def test_every_base_image_is_pinned_by_digest():
    froms = []
    for name in _tracked():
        if Path(name).name.startswith("Dockerfile"):
            for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
                if line.strip().upper().startswith("FROM "):
                    froms.append((name, line.strip()))
    assert froms
    unpinned = [f for f in froms if not re.search(r"@sha256:[0-9a-f]{64}\b", f[1])]
    assert unpinned == []


def test_the_pre_push_hook_runs_the_shared_scan():
    hook = ROOT / ".githooks" / "pre-push"
    text = hook.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh") and "scripts/public_hygiene.py" in text
    mode = subprocess.run(
        ["git", "ls-files", "-s", ".githooks/pre-push"], cwd=ROOT, capture_output=True, check=True,
    ).stdout.decode()
    assert mode.startswith("100755"), "the hook must be executable in the index"
    eol = subprocess.run(
        ["git", "check-attr", "eol", "--", ".githooks/pre-push"], cwd=ROOT, capture_output=True, check=True,
    ).stdout.decode()
    assert eol.strip().endswith(": lf"), "a CRLF shebang does not run"


# ---- property: wherever a leak hides in a push, the scan sees it ----------

def _git(repo: Path, *args: str, env: dict | None = None) -> str:
    return subprocess.run(
        ["git", "-c", "core.autocrlf=false", *args], cwd=repo, capture_output=True, check=True,
        env={**os.environ, **(env or {})},
    ).stdout.decode().strip()


def _commit(repo: Path, message: str, email: str) -> str:
    who = {"GIT_AUTHOR_NAME": "dev", "GIT_AUTHOR_EMAIL": email,
           "GIT_COMMITTER_NAME": "dev", "GIT_COMMITTER_EMAIL": NOREPLY}
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", message, env=who)
    return _git(repo, "rev-parse", "HEAD")


def _leak() -> str:
    # Assembled at run time, so this file itself stays clean.
    return "jana-nas." + "duck" + "dns.org"


WHERE = ["file", "deleted_later", "path", "message", "email", "denylisted_label"]


@settings(max_examples=12, deadline=None, derandomize=True,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(where=st.sampled_from(WHERE), at=st.integers(0, 2), commits=st.integers(1, 3))
def test_a_leak_anywhere_in_a_push_is_refused(tmp_path_factory, where, at, commits):
    if shutil.which("git") is None:
        pytest.skip("needs git")
    at = min(at, commits - 1)
    repo = tmp_path_factory.mktemp("push")
    _git(repo, "init", "-q")
    (repo / "README").write_text("base\n")
    base = _commit(repo, "base", NOREPLY)
    denied = {"jana-nas"} if where == "denylisted_label" else set()
    for i in range(commits):
        (repo / f"f{i}.txt").write_text(f"clean {i}\n")
        message, email = f"change {i}", NOREPLY
        if i == at:
            if where in ("file", "deleted_later"):
                (repo / "leak.txt").write_text(f"host {_leak()}\n")
            elif where == "path":
                (repo / f"{_leak()}.txt").write_text("x\n")
            elif where == "message":
                message = f"deploy to {_leak()}"
            elif where == "email":
                email = "jana@" + "example.com"
            elif where == "denylisted_label":
                (repo / "notes.txt").write_text("server jana-nas.example.org\n")
        head = _commit(repo, message, email)
        if where == "deleted_later" and i == at:
            (repo / "leak.txt").unlink()
            head = _commit(repo, "cleanup", NOREPLY)
    hits = hygiene.findings(hygiene.pushed(repo, base, head), denied)
    assert hits, f"leak in {where} at commit {at} not found"
    # The same history without the leak passes: the scan refuses for the leak.
    clean = repo.parent / (repo.name + "-clean")
    clean.mkdir()
    _git(clean, "init", "-q")
    (clean / "README").write_text("base\n")
    base = _commit(clean, "base", NOREPLY)
    for i in range(commits):
        (clean / f"f{i}.txt").write_text(f"clean {i}\n")
        head = _commit(clean, f"change {i}", NOREPLY)
    assert hygiene.findings(hygiene.pushed(clean, base, head), denied) == {}
