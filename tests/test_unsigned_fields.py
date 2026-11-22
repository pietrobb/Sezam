"""docs/ROOT_CAUSE_PLAN.md S4 (INV-3): every field the server answers is in
``server.app.unsigned_fields``, signed or classified, with the state-machine
rules that lie in it.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pathlib
import textwrap
import typing

import pydantic
import pytest
from fastapi.routing import APIRoute

from server.app.main import app
from server.app.unsigned_fields import DECIDES, FIELDS, HINT, SIGNED, UNREAD

ROOT = pathlib.Path(__file__).resolve().parent.parent
MACHINE = (ROOT / "tests" / "test_sync_state_machine.py").read_text(encoding="utf-8")

# Open INV-3 findings: a client decision rests on these unsigned fields.
# Remove a field here only when its entry stops being DECIDES.
KNOWN_DECIDES = {
    "GET /api/users/{user_id}/keys .archived_keys",
    "OrgRecoveryStatusResponse.configured",
    "OrgRecoveryStatusResponse.created_by",
    "OrgRecoveryStatusResponse.recovery_signing_pk",
    "PullObject.commit_seq",
}


def _models(annotation, found: dict) -> None:
    for arg in typing.get_args(annotation):
        _models(arg, found)
    if isinstance(annotation, type) and issubclass(annotation, pydantic.BaseModel) \
            and annotation.__name__ not in found:
        found[annotation.__name__] = annotation
        for field in annotation.model_fields.values():
            _models(field.annotation, found)


def _dict_keys(fn) -> set[str]:
    """String keys of the dicts ``fn`` returns (``return {...}`` or
    ``return SomeResponse({...})``)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(inspect.unwrap(fn))))
    keys = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and node.value is not None:
            value = node.value
            if isinstance(value, ast.Call) and value.args:
                value = value.args[0]
            if isinstance(value, ast.Dict):
                keys |= {k.value for k in value.keys if isinstance(k, ast.Constant)}
    return keys


def _answered() -> set[str]:
    models: dict = {}
    fields = set()
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.response_model is None:
            methods = " ".join(sorted(route.methods - {"HEAD"}))
            fields |= {f"{methods} {route.path} .{key}" for key in _dict_keys(route.endpoint)}
        else:
            _models(route.response_model, models)
    for name, model in models.items():
        fields |= {f"{name}.{field}" for field in model.model_fields}
    return fields


def _resolve(dotted: str):
    module, _, name = dotted.partition(":")
    obj = importlib.import_module(f"sezam.{module}")
    for part in name.split("."):
        obj = getattr(obj, part)
    return obj


def test_every_answered_field_has_an_entry_and_every_entry_a_field():
    answered = _answered()
    listed = set(FIELDS)
    assert not answered - listed, f"fields without an entry in server/app/unsigned_fields.py: {sorted(answered - listed)}"
    assert not listed - answered, f"entries without a field: {sorted(listed - answered)}"


@pytest.mark.parametrize("key", sorted(FIELDS))
def test_entry_is_complete(key):
    entry = FIELDS[key]
    assert entry.trust in (SIGNED, HINT, UNREAD, DECIDES), key
    if entry.trust == SIGNED:
        assert entry.checks, f"{key}: signed, but no check named"
    if entry.trust in (HINT, DECIDES):
        assert entry.why, f"{key}: {entry.trust} needs the reason"
    for check in entry.checks:
        assert callable(_resolve(check)), f"{key}: {check}"
    for lie in entry.lies:
        rule, _, label = lie.partition(":")
        assert f"def {rule}(" in MACHINE, f"{key}: no state-machine rule {rule}"
        assert not label or f'"{label}"' in MACHINE, f"{key}: rule {rule} has no lie {label!r}"


def test_the_open_findings_are_the_known_ones():
    decides = {key for key, entry in FIELDS.items() if entry.trust == DECIDES}
    assert decides == KNOWN_DECIDES, (
        f"new: {sorted(decides - KNOWN_DECIDES)}; no longer deciding: {sorted(KNOWN_DECIDES - decides)}")
