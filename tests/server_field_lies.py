"""docs/ROOT_CAUSE_PLAN.md S4 (INV-3), review e443cbc goal #428: a lie in
one field of server/app/unsigned_fields.py.

Every hint the register lists without a lie of its own is changed in the
server's replies by the state machine rule ``server_lies_in_a_field``. Which
replies carry a field comes from the app's routes, as in
tests/test_unsigned_fields.py.
"""

from __future__ import annotations

import re

from fastapi.routing import APIRoute

from server.app.main import app
from server.app.unsigned_fields import FIELDS, HINT
from tests.test_unsigned_fields import _models

# The hints without a rule of their own.
GENERIC = sorted(key for key, entry in FIELDS.items() if entry.trust == HINT and not entry.lies)


def _targets() -> dict[str, list[tuple[str, re.Pattern, frozenset | None, str]]]:
    """Register key -> (method, path pattern, the model's fields or None for a
    top-level key of a plain dict reply, field)."""
    targets: dict[str, list] = {}
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        pattern = re.compile("^" + re.sub(r"\{[^}]+\}", "[^/?]+", route.path) + r"(\?.*)?$")
        methods = sorted(route.methods - {"HEAD"})
        if route.response_model is None:
            for method in methods:
                prefix = f"{method} {route.path} ."
                for key in FIELDS:
                    if key.startswith(prefix):
                        targets.setdefault(key, []).append((method, pattern, None, key[len(prefix):]))
            continue
        models: dict = {}
        _models(route.response_model, models)
        for name, model in models.items():
            for field in model.model_fields:
                for method in methods:
                    targets.setdefault(f"{name}.{field}", []).append(
                        (method, pattern, frozenset(model.model_fields), field))
    return targets


TARGETS = _targets()


def _lie(value, how: int):
    """Another value of the same kind: ``how`` picks which."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return (value + 1000, 0, value - 1)[how]
    if isinstance(value, str):
        if re.fullmatch(r"[0-9a-f]+", value) and value:
            flipped = "0" if value[-1] != "0" else "1"
            return (value[:-1] + flipped, "", value[::-1])[how]
        return (value + "x", "", value[::-1])[how]
    if isinstance(value, list):
        return ([], value[::-1], value[:1] * 2)[how]
    if isinstance(value, dict):
        return ({}, {**value, "x": 1}, {})[how]
    return value


def _walk(node, fields, field, how, top: bool) -> int:
    changed = 0
    if isinstance(node, dict):
        if field in node and (fields is None and top or fields is not None and set(node) <= fields):
            lied = _lie(node[field], how)
            if lied != node[field]:
                node[field] = lied
                changed += 1
        if fields is not None:
            for value in node.values():
                changed += _walk(value, fields, field, how, False)
    elif isinstance(node, list) and fields is not None:
        for value in node:
            changed += _walk(value, fields, field, how, False)
    return changed


def tamper(key: str, method: str, path: str, reply, how: int) -> int:
    """Change ``key`` in ``reply`` (in place) when it answers ``method path``;
    how many values changed."""
    changed = 0
    for want, pattern, fields, field in TARGETS.get(key, ()):
        if want == method and pattern.match(path):
            changed += _walk(reply, fields, field, how, True)
    return changed
