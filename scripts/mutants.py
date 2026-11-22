"""Mutation check (review e443cbc P2): every mutant here must be killed.

The review's agent reverted reported fixes and planted similar faults in a copy
of the code; its mutants never reached the repo, so they are rebuilt here from
its description: ``revert`` undoes a fix of a reported finding, ``open`` turns
a refusal into "allow when unsure", ``branch`` breaks the same rule in another
branch of the same code (the other client, append vs restore).

Each mutant replaces one exact piece of code (it must occur once, else the
mutant no longer fits the code and the check fails) and names the tests that
must fail on it. A mutant is killed only when pytest fails (exit 1); passing
tests, a run past the timeout, or an error that is not a test failure, fail the
check. A test for a hang must bound it itself (test_r15_rotation_cycle.py).

    python scripts/mutants.py                 # all, in a scratch worktree of HEAD
    python scripts/mutants.py --only R1 R2    # some
    python scripts/mutants.py --list
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Mutant:
    name: str
    kind: str  # revert | open | branch
    path: str
    old: str
    new: str
    tests: tuple[str, ...]
    why: str


SERVER = "server/app/team_log.py"
CORE = "src/sezam/teamlog.py"
WEB_CORE = "web/static/js/teamlog.js"
# The restore reverts are checked by the INV-2 property test alone: at the
# per-push setting it has to find each of them (the review: 1 of 4); R6 only
# with its scripted tests.
INV2 = ("tests/test_inv2_restore_within_append.py",)
CYCLE = ("tests/test_r15_rotation_cycle.py",)
TEAM_LOG_SM = ("tests/test_sync_state_machine.py::test_sync_state_machine_team_log",)
WEB = ("tests/test_team_log_web.py",)
# The server's own team log tests: the INV-2 property asks the append path
# itself, so a fault in a check both paths share needs these too.
SERVER_TL = (
    "tests/test_team_log_server.py", "tests/test_team_log_server_push.py",
    "tests/test_r15_restore_within_append.py", "tests/test_review13_team_log_restore_admin_only.py",
    "tests/test_review14_team_log_restore_forged_genesis.py", "tests/test_review9_team_log_restore.py",
)

MUTANTS = (
    # Reverts of reported fixes: restore (INV-2) ---------------------------
    Mutant(
        "R1", "revert", SERVER,
        "        await _check_against_users(cur, body, None, step, history=True)\n",
        "",
        INV2, "4503b79 (H3): a restore runs the append's checks on the history it puts back",
    ),
    Mutant(
        "R2", "revert", SERVER,
        "        _refuse_rules_beyond_appends(bodies, steps)\n",
        "        pass\n",
        INV2, "4503b79 (H3): a restore holds the rules an append holds and a replay does not",
    ),
    Mutant(
        "R3", "revert", SERVER,
        "        if not keys <= linked or (member.signing_pk, member.encryption_pk) not in {account, *later}:\n",
        "        if False:\n",
        INV2, "0e96ca2: a restored log ends every member it names on the keys the account signs in with",
    ),
    Mutant(
        "R4", "revert", SERVER,
        'b["data"]["user_id"] for b in bodies if b["type"] in ("genesis", "member.add", "member.keys")',
        'b["data"]["user_id"] for b in bodies if b["type"] in ("member.add", "member.keys")',
        INV2, "7a57501: a restored genesis counts only on its founder's own keys",
    ),
    Mutant(
        "R5", "revert", SERVER,
        "    for first, last in _append_ends(bodies):\n",
        "    for first, last in [span for span in _append_ends(bodies) if span[0] == span[1]]:\n",
        INV2, "200d5e8: the one-admin rule wherever an append has to end, not only at an author change",
    ),
    Mutant(
        "R6", "revert", SERVER,
        "        if later and not uploader_team_admin:\n",
        "        if False:\n",
        # Stricter than the main path (a thief of the identity key appends
        # member.keys as well), so the INV-2 property cannot see it.
        INV2 + ("tests/test_review9_team_log_restore.py", "tests/test_review9_retired_key_after_restore.py"),
        "c78fd19 #2: only the team admin puts back a member's rotation the server lost",
    ),
    # Reverts: rotation walk (H1), one admin per organisation, org recovery --
    Mutant(
        "R7", "revert", SERVER,
        "    while start in rotated and rotated[start] not in seen:\n",
        "    while start in rotated:\n",
        CYCLE, "5ef3ac1 (H1): the server's rotation walk visits each key once",
    ),
    Mutant(
        "R8", "revert", CORE,
        'if kind != "member.keys" and signer.role != "admin":',
        'if False and kind != "member.keys" and signer.role != "admin":',
        TEAM_LOG_SM, "not_admin: only the admin signs records other than its own member.keys",
    ),
    Mutant(
        "R9", "revert", SERVER,
        "    if bytes(row[1]).hex() != pk:\n",
        "    if False:\n",
        ("tests/test_review13_org_recovery_queued_record.py",),
        "215a6ce: an org.recovery naming another key than the admin's stored blob is refused",
    ),
    Mutant(
        "R10", "revert", "src/sezam/vault/oplock.py",
        "    if path is not None and not held_here(path):\n",
        "    if False:\n",
        ("tests/test_review14_oplock_coverage.py",),
        "7500919 (INV-6): pending sync state is written only under the vault lock",
    ),
    # Similar faults: allow when unsure --------------------------------------
    Mutant(
        "O1", "open", SERVER,
        "        if row[2] is None or row[3] is None:\n            raise wrong\n",
        "        if row[2] is None or row[3] is None:\n            continue\n",
        INV2, "an account without keys on the server is taken as fine for a restored member",
    ),
    Mutant(
        "O2", "open", SERVER,
        "            if not (material and material[0]):\n",
        "            if material is None:\n",
        INV2 + SERVER_TL, "a revoked account re-added by a restore with empty key material",
    ),
    Mutant(
        "O3", "open", SERVER,
        # (_refuse_restored_founder's own row-None branch is equivalent: this
        # check runs on every restored genesis.)
        "            if row is None:\n                raise refuse(\"a restored genesis names a founder with no account here\")\n",
        "            if False:\n                raise refuse(\"a restored genesis names a founder with no account here\")\n",
        INV2 + SERVER_TL, "a restored genesis whose founder has no account here",
    ),
    Mutant(
        "O4", "open", SERVER,
        "    return active and (bool(uploader[1]) or core.is_admin(current, user_id))\n",
        "    return uploader is None or active and (bool(uploader[1]) or core.is_admin(current, user_id))\n",
        INV2 + SERVER_TL, "an uploader without a users row counts as the team admin",
    ),
    Mutant(
        "O5", "open", SERVER,
        "        if not (_keys_match(row, data) or pending_identity == new):\n",
        "        if not (_keys_match(row, data) or pending_identity is None or pending_identity == new):\n",
        INV2 + SERVER_TL, "a member.keys append without a pending identity is not checked against the account",
    ),
    Mutant(
        "O6", "open", "server/app/routers/sync.py",
        "                                regrant = await cur.fetchone() is not None\n",
        "                                regrant = True\n",
        ("tests/test_team_log_server_push.py",),
        "b5050d8: a key outside the log goes to another account as if it were a re-seal",
    ),
    Mutant(
        "O7", "open", "src/sezam/vault/outbox.py",
        "LOCKED = frozenset({KEY_CHANGE, REKEY, REVOKE, ORG_RECOVERY})",
        "LOCKED = frozenset({KEY_CHANGE, REKEY, REVOKE})",
        ("tests/test_review14_oplock_coverage.py", "tests/test_sync_s3_outbox.py"),
        "an org recovery outbox row written without the vault lock",
    ),
    # Similar faults: the same rule broken in another branch -----------------
    Mutant(
        "B1", "branch", CORE,
        '    if sum(1 for uid in state.members if is_admin(state, uid)) > 1:\n        return "more than one admin"\n',
        '    if sum(1 for uid in state.members if is_admin(state, uid)) > 2:\n        return "more than one admin"\n',
        # The INV-2 property asks the same core on both paths: it cannot see this.
        INV2 + TEAM_LOG_SM + ("tests/test_team_log_server.py", "tests/test_team_log_vectors.py"),
        "the one-admin rule (TL7) of the shared core: server append and every client",
    ),
    Mutant(
        "B2", "branch", WEB_CORE,
        "if (kind !== 'member.keys' && signer.role !== 'admin') throw new TeamLogError('not_admin', seq);",
        "if (false && kind !== 'member.keys' && signer.role !== 'admin') throw new TeamLogError('not_admin', seq);",
        WEB, "not_admin in the web core",
    ),
    Mutant(
        "B3", "branch", WEB_CORE,
        "    return admins.length > 1 ? 'more than one admin' : null;\n",
        "    return admins.length > 2 ? 'more than one admin' : null;\n",
        WEB, "the one-admin rule in the web core",
    ),
    Mutant(
        "B4", "branch", SERVER,
        '        if any(b.get("author") != user_id for b in bodies):\n',
        '        if all(b.get("author") != user_id for b in bodies):\n',
        ("tests/test_team_log_server.py", "tests/test_r15_append_own_records.py"),
        "an append mixing the uploader's records with another author's",
    ),
)


def _apply(work: Path, mutant: Mutant) -> str:
    """The file's text before the mutant ('' when it no longer fits)."""
    path = work / mutant.path
    text = path.read_text(encoding="utf-8")
    if text.count(mutant.old) != 1:
        return ""
    path.write_text(text.replace(mutant.old, mutant.new), encoding="utf-8")
    return text


def check(work: Path, mutant: Mutant, timeout: int) -> str:
    """'' when the mutant is killed, else why not."""
    original = _apply(work, mutant)
    if not original:
        return f"{mutant.path}: the code to mutate does not occur exactly once (update the mutant)"
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(work / "src"), str(work)]))
    try:
        done = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *mutant.tests],
            cwd=work, env=env, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        # Slow is not red: only a failing test proves the mutant is caught.
        return f"timed out after {timeout} s, not proven killed (no test failed)"
    finally:
        (work / mutant.path).write_text(original, encoding="utf-8")
    if done.returncode == 1:
        return ""
    tail = "\n".join((done.stdout + done.stderr).strip().splitlines()[-3:])
    if done.returncode == 0:
        return f"survived: {' '.join(mutant.tests)} passed\n{tail}"
    return f"pytest exit {done.returncode} (no test failure)\n{tail}"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", nargs="*", default=None)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--here", action="store_true", help="mutate this checkout (CI), not a scratch worktree")
    args = parser.parse_args(argv)
    chosen = [m for m in MUTANTS if args.only is None or m.name in args.only]
    if args.list:
        for m in chosen:
            print(f"{m.name:4} {m.kind:6} {m.path}: {m.why}")
        return 0
    if args.here:
        work, scratch = ROOT, None
    else:
        scratch = Path(tempfile.mkdtemp(prefix="sezam-mutants-"))
        work = scratch / "wt"
        subprocess.run(["git", "worktree", "add", "-q", "--detach", str(work), "HEAD"], cwd=ROOT, check=True)
    problems = []
    # Two runs in one tree restore each other's mutants as the original code.
    lock = work / ".mutants.lock"
    try:
        lock.touch(exist_ok=False)
    except FileExistsError:
        print(f"another mutation run uses {work} ({lock})", file=sys.stderr)
        return 2
    try:
        # Red without a mutant would count every mutant as killed.
        tests = sorted({t for m in chosen for t in m.tests})
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(work / "src"), str(work)]))
        base = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *tests],
                              cwd=work, env=env, capture_output=True, text=True)
        if base.returncode != 0:
            print("the tests fail without a mutant:\n" + (base.stdout + base.stderr)[-3000:], file=sys.stderr)
            return 2
        for mutant in chosen:
            started = time.monotonic()
            why = check(work, mutant, args.timeout)
            took = time.monotonic() - started
            print(f"{mutant.name:4} {'killed' if not why else 'NOT KILLED'} ({took:.0f} s) {mutant.why}", flush=True)
            if why:
                problems.append(f"{mutant.name}: {why}")
    finally:
        lock.unlink()
        if scratch is not None:
            subprocess.run(["git", "worktree", "remove", "--force", str(work)], cwd=ROOT, check=False)
            shutil.rmtree(scratch, ignore_errors=True)
    for problem in problems:
        print(problem, file=sys.stderr)
    print(f"{len(chosen) - len(problems)} of {len(chosen)} mutants killed")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
