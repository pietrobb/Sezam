"""Review 8bc70f7 #3: the member re-key lost the cross-process lock.

3975939 moved ``@oplock.held`` from ``rekey_after_revocation`` to the new
``rekey_after_handover``. Two removals at once (GUI and CLI) then wrote their
batches over each other; the folder stayed on a key the log does not know and
every push conflicted. The behavioural test pins this method; the scan below
pins the rule for every function, so the next move of a decorator fails here.

Rule: a public function of ``sezam.vault`` that writes a pending batch or a key
change journal (directly, or through private helpers of its module) runs under
``oplock.held`` or ``with oplock.exclusive(...)``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from sezam.vault import oplock
from tests.test_review6_vault_oplock import PASSWORD, _hold_in_another_process, vault  # noqa: F401

VAULT_SRC = Path(__file__).resolve().parents[1] / "src" / "sezam" / "vault"

SINKS = {
    "set_rekey_batch", "clear_rekey_batch", "set_key_change_journal",
    "clear_key_change_journal", "set_org_recovery_registration",
    "set_last_pushed_key_epoch", "rekey_folder",
}

# Public helpers whose every caller holds the lock (checked by hand, keep short).
CALLERS_HOLD = {
    # change_password (held) via _seal_identity_rotation; full_resync (held).
    ("crud.py", "reseal_envelopes_for_rotation"),
    # The sinks themselves.
    ("pending_states.py", "set_rekey_batch"),
}


def _held(fn: ast.FunctionDef) -> bool:
    for dec in fn.decorator_list:
        if isinstance(dec, ast.Attribute) and dec.attr == "held":
            return True
    for node in ast.walk(fn):
        if isinstance(node, ast.With):
            for item in node.items:
                call = item.context_expr
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) \
                        and call.func.attr == "exclusive":
                    return True
    return False


def _called(fn: ast.FunctionDef) -> set[str]:
    names = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name:
                names.add(name)
    return names


def unlocked_writers(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    defs: dict[str, list[ast.FunctionDef]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            defs.setdefault(node.name, []).append(node)

    def reaches(name: str, seen: frozenset) -> bool:
        if name in SINKS:
            return True
        if name in seen or name not in defs or not name.startswith("_"):
            return False  # a public callee is checked on its own
        return any(
            not _held(fn) and any(reaches(n, seen | {name}) for n in _called(fn))
            for fn in defs[name]
        )

    found = []
    for name, fns in defs.items():
        if name.startswith("_") or (path.name, name) in CALLERS_HOLD:
            continue
        for fn in fns:
            if not _held(fn) and any(reaches(n, frozenset({name})) for n in _called(fn)):
                found.append(f"{path.name}:{fn.lineno} {name}")
    return found


def test_every_public_batch_writer_holds_the_lock():
    found = [hit for path in sorted(VAULT_SRC.glob("*.py")) for hit in unlocked_writers(path)]
    assert found == []


def test_the_scan_sees_the_3975939_regression(tmp_path):
    src = (VAULT_SRC / "crud.py").read_text(encoding="utf-8")
    marker = "    @oplock.held  # review 8bc70f7 #3"
    assert marker in src
    regressed = tmp_path / "crud.py"
    regressed.write_text(src.replace(marker, "    # (decorator removed)"), encoding="utf-8")
    assert any("rekey_after_revocation" in hit for hit in unlocked_writers(regressed))


def test_a_member_rekey_waits_for_another_process(vault, monkeypatch):  # noqa: F811
    monkeypatch.setattr(oplock, "DEFAULT_TIMEOUT", 0.3)
    proc = _hold_in_another_process(vault.db.path, 3.0)
    try:
        with pytest.raises(oplock.VaultBusy):
            vault.rekey_after_revocation("01HZZZZZZZZZZZZZZZZZZZZZZZ")
        with pytest.raises(oplock.VaultBusy):
            vault.rekey_after_handover("01HZZZZZZZZZZZZZZZZZZZZZZZ")
    finally:
        proc.wait(10)
    assert vault.rekey_after_revocation("01HZZZZZZZZZZZZZZZZZZZZZZZ") == 0
