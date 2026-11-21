"""Saved counterexamples of the property tests (review e443cbc P2).

A failing Hypothesis run prints ``@reproduce_failure('<version>', b'<blob>')``.
The nightly CI job (property-deep) runs with many examples and keeps its log
as an artifact; a counterexample it finds, or one a mutant run found, goes as
one line into ``property_seeds.txt``:

    <test file> <target> <version> <blob>  <why, free text>

``target`` is the state machine class, or the ``@given`` test function. Each
module replays its lines in a ``..._saved_counterexample`` test on every push:
the fixed code must pass them. A line whose blob no longer fits the test
(``DidNotReproduce`` with a changed shape) fails too; regenerate or delete it,
a saved case is never skipped silently.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from hypothesis import reproduce_failure
from hypothesis.errors import DidNotReproduce
from hypothesis.stateful import run_state_machine_as_test

SEEDS = Path(__file__).with_name("property_seeds.txt")
PASSED = "completed successfully"  # DidNotReproduce text when the case now passes


@dataclass(frozen=True)
class Seed:
    module: str
    target: str
    version: str
    blob: str
    why: str
    line: int

    def __str__(self) -> str:
        return f"{self.target}@{self.line}"


def load(module: str) -> list[Seed]:
    seeds = []
    for number, raw in enumerate(SEEDS.read_text(encoding="utf-8").splitlines(), 1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        parts = text.split(maxsplit=4)
        if len(parts) < 4:
            raise ValueError(f"{SEEDS.name}:{number}: expected '<file> <target> <version> <blob> [why]'")
        if parts[0] == module:
            seeds.append(Seed(*parts[:4], parts[4] if len(parts) > 4 else "", number))
    return seeds


def _passed(seed: Seed, exc: DidNotReproduce) -> None:
    if PASSED not in str(exc):
        pytest.fail(f"{SEEDS.name}:{seed.line} no longer fits {seed.target} ({exc}); regenerate or delete it")


def replay_machine(machine: type, seed: Seed, settings) -> None:
    replay = reproduce_failure(seed.version, seed.blob.encode())(type(machine.__name__, (machine,), {}))
    try:
        run_state_machine_as_test(replay, settings=settings)
    except DidNotReproduce as exc:
        _passed(seed, exc)


def replay_given(test, seed: Seed, **kwargs) -> None:
    test._hypothesis_internal_use_reproduce_failure = (seed.version, seed.blob.encode())
    try:
        test(**kwargs)
    except DidNotReproduce as exc:
        _passed(seed, exc)
    finally:
        test._hypothesis_internal_use_reproduce_failure = None
