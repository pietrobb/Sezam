"""scripts/commit_discipline.py and .githooks/commit-msg (review e443cbc P6):
the checklist of docs/ROOT_CAUSE_PLAN.md section 6 and a reproducible red line
in every commit, enforced by the hook and checked again in CI."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import commit_discipline as cd  # noqa: E402

CHECKLIST = "Checklist (docs/ROOT_CAUSE_PLAN.md section 6):\n" + "".join(
    f"{n}. answer {n}\n" for n in range(1, 10))


def _message(red: str = "Red on 1234567: python -m pytest -q tests/test_x.py -> 1 failed",
             checklist: str = CHECKLIST) -> str:
    return f"Fix the thing\n\nWhy.\n\n{red}\n\n{checklist}"


def test_a_message_with_the_checklist_and_a_red_line_passes():
    assert cd.check_message(_message()) == []
    assert cd.check_message(_message(red="No fix: documentation only")) == []


@pytest.mark.parametrize("message, problem", [
    (_message(checklist=""), "no 'Checklist"),
    (_message(checklist=CHECKLIST.replace("7. answer 7\n", "")), "answers missing: 7"),
    (_message(red=""), "no 'Red on"),
    (_message(red="Red on main: python -m pytest"), "no 'Red on"),  # a sha, not a branch
    (_message(red="No fix:"), "no 'Red on"),  # a reason
    ("Subject only\n", "no 'Checklist"),
    # CI run 45104077580: the hook took red lines CI cannot run.
    (_message(red="Red on 1234567: cd mobile && flutter test test/x_test.dart"), "not 'python -m pytest"),
    (_message(red="Red on 1234567: pytest tests/test_x.py"), "not 'python -m pytest"),
    (_message(red="Red on 1234567: tests/test_x.py::test_y (2 failed)"), "not 'python -m pytest"),
    (_message(red="Red on 1234567: none; a comment only."), "not 'python -m pytest"),
    (_message(red="Red on 1234567: SEZAM_X=1 python -m pytest tests/test_x.py"), "not 'python -m pytest"),
    (_message(red="Red on 1234567: python -m pytest \"tests/test_x.py"), "does not parse"),
])
def test_a_message_without_them_is_refused(message, problem):
    problems = cd.check_message(message)
    assert any(problem in p for p in problems), problems


def test_git_comment_lines_do_not_count():
    assert cd.check_message("Fix\n\n# Red on 1234567: python -m pytest\n# " + CHECKLIST) != []


def test_merges_and_reverts_need_no_checklist():
    assert cd.check_message("Merge branch 'x'\n") == []
    assert cd.check_message('Revert "Fix the thing"\n') == []


def test_the_note_after_the_arrow_is_not_part_of_the_command():
    assert cd.red_lines(_message()) == [("1234567", "python -m pytest -q tests/test_x.py")]


# --- a real repository: the hook and the range check ----------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git")


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "core.autocrlf=false",
         "-c", f"core.hooksPath={repo / '.githooks'}", *args],
        cwd=repo, capture_output=True, text=True, check=check,
    )


@pytest.fixture
def repo(tmp_path):
    (tmp_path / ".githooks").mkdir()
    shutil.copy(ROOT / ".githooks" / "commit-msg", tmp_path / ".githooks" / "commit-msg")
    (tmp_path / "scripts").mkdir()
    shutil.copy(ROOT / "scripts" / "commit_discipline.py", tmp_path / "scripts")
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "calc.py").write_text("def double(x):\n    return x + x + 1\n")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "--no-verify", "-m", "base")
    return tmp_path


def _commit(repo: Path, message: str) -> subprocess.CompletedProcess:
    (repo / "msg.txt").write_text(message)
    _git(repo, "add", "src", "tests")
    return _git(repo, "commit", "-q", "-F", str(repo / "msg.txt"), check=False)


def _head(repo: Path, rev: str = "HEAD") -> str:
    return _git(repo, "rev-parse", rev).stdout.strip()


@needs_git
def test_the_hook_refuses_a_commit_without_the_checklist(repo):
    (repo / "src" / "calc.py").write_text("def double(x):\n    return 2 * x\n")
    done = _commit(repo, "Fix double\n")
    assert done.returncode != 0
    assert "commit discipline" in done.stderr
    assert len(_git(repo, "rev-list", "HEAD").stdout.split()) == 1


@needs_git
def test_ci_runs_the_red_line_on_its_sha(repo):
    """A fix whose test fails on the commit before: the range check passes;
    a red line naming a sha where the test passes is refused."""
    base = _head(repo)
    (repo / "src" / "calc.py").write_text("def double(x):\n    return 2 * x\n")
    (repo / "tests" / "test_calc.py").write_text(
        "from calc import double\n\n\ndef test_double():\n    assert double(2) == 4\n")
    assert _commit(repo, _message(red=f"Red on {base[:9]}: python -m pytest -q tests/test_calc.py -> 1 failed")
                   ).returncode == 0
    fixed = _head(repo)
    assert cd.check_range(base, fixed, repo, verify=True, timeout=120) == []

    (repo / "tests" / "test_calc.py").write_text(
        "from calc import double\n\n\ndef test_double():\n    assert double(3) == 6\n")
    assert _commit(repo, _message(red=f"Red on {fixed[:9]}: python -m pytest -q tests/test_calc.py")).returncode == 0
    problems = cd.check_range(fixed, _head(repo), repo, verify=True, timeout=120)
    assert len(problems) == 1 and "it passes" in problems[0], problems


@needs_git
def test_ci_refuses_a_red_sha_that_is_not_an_ancestor(repo):
    base = _head(repo)
    (repo / "tests" / "test_calc.py").write_text("def test_x():\n    assert False\n")
    assert _commit(repo, _message(red="Red on deadbeef: python -m pytest -q tests/test_calc.py")).returncode == 0
    problems = cd.check_range(base, _head(repo), repo, verify=True, timeout=120)
    assert len(problems) == 1 and "not a commit" in problems[0], problems


@needs_git
def test_a_red_line_of_a_core_change_runs_on_the_core_before_it(repo):
    """R15 #428 (43dc4cb): CI installs the head's sync core, so a fix in core/
    ran its red line on the fixed core and passed on the commit before. A
    stand-in core (core/py, one module): its test passes where it is not
    built for the worktree (the installed, fixed core) and fails on the old one."""
    py = repo / "core" / "py"
    (py / "fakecore").mkdir(parents=True)
    (py / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools>=61"]\nbuild-backend = "setuptools.build_meta"\n\n'
        '[project]\nname = "fakecore"\nversion = "0"\n\n[tool.setuptools]\npackages = ["fakecore"]\n')
    (py / "fakecore" / "__init__.py").write_text("ANSWER = 1\n")
    _git(repo, "add", "core")
    _git(repo, "commit", "-q", "--no-verify", "-m", "core")
    base = _head(repo)
    (py / "fakecore" / "__init__.py").write_text("ANSWER = 2\n")
    (repo / "tests" / "test_core.py").write_text(
        "def test_answer():\n    try:\n        import fakecore\n    except ImportError:\n        return\n"
        "    assert fakecore.ANSWER == 2\n")
    _git(repo, "add", "core")
    assert _commit(repo, _message(red=f"Red on {base[:9]}: python -m pytest -q tests/test_core.py")).returncode == 0
    assert cd.check_range(base, _head(repo), repo, verify=True, timeout=120) == []


@needs_git
def test_a_red_line_that_only_runs_long_is_no_red(repo):
    """Capability run 448: a run past the timeout proves no test failed."""
    base = _head(repo)
    (repo / "tests" / "test_calc.py").write_text("import time\n\n\ndef test_slow():\n    time.sleep(30)\n")
    assert _commit(repo, _message(red=f"Red on {base[:9]}: python -m pytest -q tests/test_calc.py")).returncode == 0
    problems = cd.check_range(base, _head(repo), repo, verify=True, timeout=3)
    assert len(problems) == 1 and "timed out" in problems[0], problems
