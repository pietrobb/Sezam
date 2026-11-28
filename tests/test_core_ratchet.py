"""U8 (docs/CORE_UNIFICATION.md, rule 7): the ratchet. Every rule of
sezam-sync-core is an operation of core/src/json.rs (and the `run`/`ask`
tables it chains to). A function on the desktop, the server, the page or the
phone named after one, in snake_case or camelCase, with or without the
`team_log_`/`authority_` prefix, must be a thin wrapper: its body calls the
core (or a function of the same file that does). A copy of a rule written
again on any side fails here.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent

SIDES = (
    ("src/sezam", "*.py"),
    ("server/app", "*.py"),
    ("web/static/js", "*.js"),
    ("mobile/lib", "*.dart"),
)

# The same name, another thing - never a copy of the core's rule.
NOT_THE_RULE = {
    (
        "src/sezam/vault/sync_rekey.py",
        "current_key",
    ): "walks this device's removal archives to a folder's current key, not the team log's current_key",
}

DEFINITION = {
    ".py": r"^[ \t]*def ({0})\(",
    ".js": r"^[ \t]*(?:async\s+)?function\*?\s+({0})\s*\(|^[ \t]*(?:const|let)\s+({0})\s*=\s*(?:async\s*)?"
    r"(?:\([^)]*\)|\w+)\s*=>",
    ".dart": r"^[ \t]*(?:static\s+)?(?!(?:return|await|new|throw|else|yield|final|var)\b)"
    r"(?:[A-Za-z_][\w<>?,\[\]]*(?:<[^>]*>)?\??\s+)({0})\s*(?:<[^>]*>)?\(",
}

# What a call into the core looks like on each side: sync_core.call /
# SezamSyncCore.call / syncCore, the wrappers' own call/ask/answer helpers,
# the server's _core_message, and the sezam.teamlog wrapper module.
CALLS_CORE = re.compile(
    r"sync_core\.call\(|SezamSyncCore\.call\(|\bcall\(|\bsyncCore\(|\b_?ask\(|\banswer\(|_core\(|_call\("
    r"|_core_message\(|\bteamlog\."
)


def core_operations(root: pathlib.Path = ROOT) -> set[str]:
    ops: set[str] = set()
    for path in (root / "core" / "src").rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        for table in re.finditer(
            r"^(?:pub(?:\(crate\))? )?fn (?:run\(op: &str|ask\(state: &State, name: &str)[^\n]*\n(.*?)^}",
            text,
            re.M | re.S,
        ):
            body = table.group(1)
            for arm in re.findall(
                r'^\s*((?:"[a-z][a-z0-9_]*"\s*\|\s*)*"[a-z][a-z0-9_]*")\s*=>',
                body,
                re.M,
            ):
                ops.update(re.findall(r'"([a-z0-9_]+)"', arm))
            ops.update(re.findall(r'op != "([a-z0-9_]+)"', body))
    return ops


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(word.title() for word in rest)


def rule_names(ops: set[str]) -> dict[str, str]:
    names = {}
    for op in ops:
        for name in {op, op.removeprefix("team_log_"), op.removeprefix("authority_")}:
            names[name] = names[_camel(name)] = op
    return names


def _body(text: str, start: int, suffix: str) -> str:
    if suffix == ".py":
        lines = text[start:].split("\n")
        indent = len(lines[0]) - len(lines[0].lstrip())
        out = [lines[0]]
        for line in lines[1:]:
            if (
                line.strip()
                and len(line) - len(line.lstrip()) <= indent
                and not line.lstrip().startswith((")", "]"))
            ):
                break
            out.append(line)
        return "\n".join(out)
    depth, braced = 0, False
    for i in range(start, len(text)):
        c = text[i]
        if c in "({[":
            depth += 1
            braced = braced or c == "{"
        elif c in ")}]":
            depth -= 1
            if depth == 0 and c == "}" and braced:
                return text[start : i + 1]
        elif c == ";" and depth == 0:
            return text[start : i + 1]
    return text[start:]


def copies_in(path: pathlib.Path, text: str, names: dict[str, str]) -> list[str]:
    """`name (op) line` of each definition in ``text`` named after a core
    rule whose body does not reach the core."""
    pattern = DEFINITION[path.suffix]
    alternatives = "|".join(sorted(map(re.escape, names), key=len, reverse=True))
    found = []
    for m in re.finditer(pattern.format(alternatives), text, re.M):
        name = next(g for g in m.groups() if g)
        body = _body(text, m.start(), path.suffix)
        if CALLS_CORE.search(body):
            continue
        # One step through a helper of the same file (team_key_ids -> _team_key_ids).
        if any(
            (d := re.search(pattern.format(re.escape(callee)), text, re.M))
            and d.start() != m.start()
            and CALLS_CORE.search(_body(text, d.start(), path.suffix))
            for callee in set(
                re.findall(r"\b([A-Za-z_]\w*)\(", body[m.end() - m.start() :])
            )
        ):
            continue
        found.append(
            f"{name} ({names[name]}) line {text[: m.start()].count(chr(10)) + 1}"
        )
    return found


def _sources():
    for side, glob in SIDES:
        for path in sorted((ROOT / side).rglob(glob)):
            if "vendor" not in path.parts:
                yield path


def test_the_core_has_its_operations():
    ops = core_operations()
    # A parser that silently found nothing would pass every side.
    assert len(ops) > 90, len(ops)
    for op in (
        "team_log_replay",
        "authority_write_refusal",
        "key_voucher_vouched",
        "aad",
        "team_log_local_refusal",
        "team_log_anchor_pin",
        "resolve_change",
        "is_admin",
        "may_write",
        "revive_folders",
        "team_log_rotated_seals",
    ):
        assert op in ops, op


def test_no_side_writes_a_core_rule_again():
    names = rule_names(core_operations())
    copies = []
    wrappers = 0
    for path in _sources():
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        wrappers += len(
            re.findall(
                DEFINITION[path.suffix].format("|".join(map(re.escape, names))),
                text,
                re.M,
            )
        )
        copies += [
            f"{rel}: {c}"
            for c in copies_in(path, text, names)
            if (rel, c.split(" ")[0]) not in NOT_THE_RULE
        ]
    assert wrappers > 100, wrappers
    assert not copies, (
        "a core rule is written again outside a thin wrapper:\n" + "\n".join(copies)
    )


def test_every_exception_still_names_a_definition():
    names = rule_names(core_operations())
    for (rel, name), why in NOT_THE_RULE.items():
        assert why
        path = ROOT / rel
        assert any(
            c.startswith(f"{name} ")
            for c in copies_in(path, path.read_text(encoding="utf-8"), names)
        ), rel


# Proof the ratchet bites: a rule written again in a real file of each side.
INSERTED = {
    "src/sezam/vault/team_log_state.py": "\n\ndef is_admin(state, user_id):\n    return user_id in state.admins\n",
    "server/app/auth.py": "\n\ndef auth_challenge_message(challenge, current_key=False):\n"
    "    return b'sezam-auth-v1' + bytes(challenge)\n",
    "web/static/js/app.js": "\nfunction mayWrite(state, userId, folder) {\n"
    "    return state.members[userId]?.level === 'write';\n}\n",
    "web/static/js/teamlog.js": "\nconst forkFollows = (cause) => ['went_back', 'differs'].includes(cause);\n",
    "mobile/lib/services/vault_service.dart": "\nbool localRefusal(String? anchor, String? held) {\n"
    "  return anchor != null && held != null && anchor != held;\n}\n",
    "mobile/lib/services/team_log.dart": "\nString recordHash(Map<String, Object?> record) =>\n"
    "    sha256.convert(utf8.encode(jsonEncode(record))).toString();\n",
}


def test_a_copy_inserted_on_each_side_fails():
    names = rule_names(core_operations())
    for rel, copy in INSERTED.items():
        path = ROOT / rel
        text = path.read_text(encoding="utf-8")
        before = copies_in(path, text, names)
        after = copies_in(path, text + copy, names)
        assert len(after) == len(before) + 1, (rel, after)


# U6j: password_forms and Shamir stay on the platforms (rule 3); one vector
# file holds the copies alike, and each side's test reads it.
SHARED_VECTORS = {
    "tests/vectors/password_forms.json": (
        "tests/test_password_forms_shamir_vectors.py",
        "mobile/test/password_forms_vectors_test.dart",
    ),
    "tests/vectors/shamir.json": ("tests/test_password_forms_shamir_vectors.py",),
}


def test_the_platform_rules_are_held_alike_by_vectors():
    for vectors, readers in SHARED_VECTORS.items():
        assert (ROOT / vectors).is_file(), vectors
        for reader in readers:
            assert pathlib.PurePosixPath(vectors).name in (ROOT / reader).read_text(
                encoding="utf-8"
            ), reader
