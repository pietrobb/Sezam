"""scripts/mutants.py (review e443cbc P2): a mutant is killed only by a failing test.

Capability run 448: a pytest run past the timeout counted as a kill, so a
mutant whose tests were merely slow was reported caught.
"""

from __future__ import annotations

from scripts.mutants import MUTANTS, ROOT, Mutant, check


def _mutant(tmp_path, test_body: str) -> Mutant:
    (tmp_path / "mutee.py").write_text("LIMIT = 1\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_mutee.py").write_text(test_body, encoding="utf-8")
    return Mutant("T1", "open", "mutee.py", "LIMIT = 1\n", "LIMIT = 2\n", ("tests/test_mutee.py",), "probe")


def test_a_failing_test_kills_the_mutant(tmp_path):
    mutant = _mutant(tmp_path, "from mutee import LIMIT\n\n\ndef test_limit():\n    assert LIMIT == 1\n")
    assert check(tmp_path, mutant, timeout=120) == ""
    assert (tmp_path / "mutee.py").read_text(encoding="utf-8") == "LIMIT = 1\n"


def test_a_slow_run_is_no_kill(tmp_path):
    mutant = _mutant(tmp_path, "import time\n\n\ndef test_slow():\n    time.sleep(30)\n")
    why = check(tmp_path, mutant, timeout=3)
    assert "timed out" in why and "not proven killed" in why
    assert (tmp_path / "mutee.py").read_text(encoding="utf-8") == "LIMIT = 1\n"


def test_passing_tests_are_a_survivor(tmp_path):
    mutant = _mutant(tmp_path, "def test_nothing():\n    pass\n")
    assert check(tmp_path, mutant, timeout=120).startswith("survived")


def test_every_mutant_still_fits_the_code():
    """The weekly run found mutants of moved code only then (R9 after R17,
    R8/B1-B3 after the team log moved into the core, docs/CORE_UNIFICATION.md)."""
    for mutant in MUTANTS:
        text = (ROOT / mutant.path).read_text(encoding="utf-8")
        assert text.count(mutant.old) == 1, f"{mutant.name}: {mutant.path} no longer holds its code once"
        for test in mutant.tests:
            if mutant.path.startswith("core/"):
                assert (ROOT / "core" / "tests" / f"{test}.rs").is_file(), f"{mutant.name}: {test}"
            else:
                assert (ROOT / test.split("::")[0]).is_file(), f"{mutant.name}: {test}"
