"""Commit discipline (docs/ROOT_CAUSE_PLAN.md section 5.2 and 6, review e443cbc P6).

Every commit after FLOOR carries in its message:

* the checklist of section 6: a line ``Checklist (docs/ROOT_CAUSE_PLAN.md
  section 6)`` followed by answers numbered 1. to 9.;
* either a reproducible red line ``Red on <sha>: <command>`` (the command
  fails on <sha>, the commit before the fix; text after `` -> `` is a note),
  or ``No fix: <reason>`` for a commit that fixes nothing (docs, tooling).

Modes:
  msg FILE                      check one message (the commit-msg hook)
  range BASE HEAD [--verify-red]  check every commit in BASE..HEAD (CI);
                                --verify-red also runs each red command on
                                its <sha>, with the commit's own test files,
                                and requires it to fail there (pytest exit 1;
                                a run past --timeout is no failure)
Enable the hook once per clone: git config core.hooksPath .githooks
"""
from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Commits up to and including this one predate the rule (R15-H3).
FLOOR = "4503b797082576d88b36ba2de0b387c4f3da1dbc"

CHECKLIST = re.compile(r"^Checklist \(docs/ROOT_CAUSE_PLAN\.md section 6\)", re.M)
RED = re.compile(r"^Red on ([0-9a-f]{7,40}): (\S.*)$", re.M)
NO_FIX = re.compile(r"^No fix: \S", re.M)
SKIP_SUBJECT = re.compile(r"^(Merge |Revert \")")


def check_message(text: str) -> list[str]:
    """What the message lacks ([] when it follows the rule)."""
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    text = "\n".join(lines)
    if lines and SKIP_SUBJECT.match(lines[0]):
        return []
    problems = []
    found = CHECKLIST.search(text)
    if not found:
        problems.append("no 'Checklist (docs/ROOT_CAUSE_PLAN.md section 6)' line")
    else:
        after = text[found.end():]
        missing = [n for n in range(1, 10) if not re.search(rf"^{n}\. \S", after, re.M)]
        if missing:
            problems.append(f"checklist answers missing: {', '.join(map(str, missing))}")
    if not RED.search(text) and not NO_FIX.search(text):
        problems.append("no 'Red on <sha>: <command>' line (or 'No fix: <reason>')")
    return problems


def red_lines(text: str) -> list[tuple[str, str]]:
    return [(sha, command.split(" -> ")[0].strip()) for sha, command in RED.findall(text)]


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def commits(base: str, head: str, repo: Path) -> list[str]:
    """BASE..HEAD oldest first, without merges and without FLOOR's history."""
    listed = _git("rev-list", "--reverse", "--no-merges", f"{base}..{head}", cwd=repo).split()
    try:
        _git("cat-file", "-e", f"{FLOOR}^{{commit}}", cwd=repo)
    except subprocess.CalledProcessError:
        return listed  # another history (tests)
    old = set(_git("rev-list", FLOOR, cwd=repo).split())
    return [c for c in listed if c not in old]


def verify_red(commit: str, sha: str, command: str, repo: Path, timeout: int) -> str:
    """'' when ``command`` fails on ``sha`` with the test files as of ``commit``."""
    try:
        full = _git("rev-parse", "--verify", f"{sha}^{{commit}}", cwd=repo).strip()
    except subprocess.CalledProcessError:
        return f"red sha {sha} is not a commit here"
    if _git("merge-base", full, commit, cwd=repo).strip() != full:
        return f"red sha {sha} is not an ancestor of {commit[:12]}"
    argv = shlex.split(command, posix=True)
    if argv[:3] != ["python", "-m", "pytest"]:
        return f"red command is not 'python -m pytest ...': {command}"
    # The commit's tests (added or changed under tests/) on the code before it.
    changed = _git("diff", "--name-only", "--diff-filter=AM", f"{commit}^", commit, "--", "tests", cwd=repo).split()
    work = Path(tempfile.mkdtemp(prefix="sezam-red-"))
    try:
        _git("worktree", "add", "--detach", str(work), full, cwd=repo)
        for path in changed:
            content = subprocess.run(["git", "show", f"{commit}:{path}"], cwd=repo,
                                     check=True, capture_output=True).stdout
            (work / path).parent.mkdir(parents=True, exist_ok=True)
            (work / path).write_bytes(content)
        paths = [str(work / "src"), str(work)]
        if _git("diff", "--name-only", f"{commit}^", commit, "--", "core", cwd=repo).split():
            # The code before a commit to the shared core includes that core:
            # the installed one is the commit's own (CI installs HEAD's).
            subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--no-deps", "--target",
                            str(work / ".sync-core"), str(work / "core" / "py")], check=True,
                           capture_output=True)
            paths.insert(0, str(work / ".sync-core"))
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(paths))
        try:
            done = subprocess.run([sys.executable, *argv[1:]], cwd=work, env=env,
                                  capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            # Slow is not red (capability run 448): a test for a hang bounds it itself.
            return f"'{command}' on {sha}: timed out after {timeout} s, no test failed"
        if done.returncode == 1:
            return ""
        tail = (done.stdout + done.stderr).strip().splitlines()[-3:]
        why = "it passes" if done.returncode == 0 else f"pytest exit {done.returncode} (not a test failure)"
        return f"'{command}' on {sha}: {why}: {' | '.join(tail)}"
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(work)], cwd=repo, capture_output=True)
        shutil.rmtree(work, ignore_errors=True)


def check_range(base: str, head: str, repo: Path, verify: bool, timeout: int) -> list[str]:
    problems = []
    for commit in commits(base, head, repo):
        text = _git("log", "-1", "--format=%B", commit, cwd=repo)
        subject = text.splitlines()[0] if text else ""
        for problem in check_message(text):
            problems.append(f"{commit[:12]} {subject[:60]}: {problem}")
        if verify:
            for sha, command in red_lines(text):
                if why := verify_red(commit, sha, command, repo, timeout):
                    problems.append(f"{commit[:12]} {subject[:60]}: {why}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)
    one = sub.add_parser("msg")
    one.add_argument("file")
    many = sub.add_parser("range")
    many.add_argument("base")
    many.add_argument("head")
    many.add_argument("--verify-red", action="store_true")
    many.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)
    if args.mode == "msg":
        problems = check_message(Path(args.file).read_text(encoding="utf-8"))
    else:
        repo = Path(_git("rev-parse", "--show-toplevel", cwd=Path.cwd()).strip())
        problems = check_range(args.base, args.head, repo, args.verify_red, args.timeout)
    for problem in problems:
        print(f"commit discipline: {problem}", file=sys.stderr)
    if problems:
        print("see docs/ROOT_CAUSE_PLAN.md section 6 and scripts/commit_discipline.py", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
