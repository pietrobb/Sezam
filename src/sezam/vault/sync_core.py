"""The shared sync core (core/, docs/SYNC_SINGLE_SOURCE.md point 4b).

The desktop, web and phone ask the same Rust crate for their sync decisions;
this is the desktop's door to it (the PyO3 binding in core/py).
"""

import json
from typing import Any, Iterable, Optional

import sezam_sync_core

# The rules this client was written for (core/Cargo.toml). Review 782dde8:
# the rules changed under one version, so a stale installed core went on
# answering by the old ones; another version is refused.
from ..teamlog import CORE_VERSION


def _run(op: str, arguments: dict) -> Any:
    out = json.loads(sezam_sync_core.call(op, json.dumps(arguments)))
    if "error" in out:
        raise ValueError(f"sync core {op}: {out['error']}")
    return out["ok"]


def _installed_version() -> str:
    try:
        return _run("version", {})
    except ValueError:
        return "0.1.0"  # no version operation yet


if (_installed := _installed_version()) != CORE_VERSION:
    raise ImportError(
        f"sezam-sync-core {_installed} is installed, this Sezam needs {CORE_VERSION}: "
        "pip install ./core/py"
    )


def call(op: str, **arguments: Any) -> Any:
    """Run one core operation; a refused input raises ValueError."""
    return _run(op, arguments)


def team_input(team: Any, user_id: Optional[str], keys: Optional[Iterable[str]] = None) -> Optional[dict]:
    """The verified team log as the core reads it: each folder's keys, oldest
    first, and the keys the log lets ``user_id`` hold.

    With ``keys``, only the folders that name one of them: the log names a key
    in one folder only, and the core's answer about a key reads that folder
    alone. Review 8bc70f7 M8: every question sent all of a 40 000-folder team.
    """
    if team is None:
        return None
    from .. import teamlog

    if keys is None:
        folders = team.folders
    else:
        named = {team.dek_index[key][0] for key in keys if key in team.dek_index}
        folders = {folder: team.folders[folder] for folder in sorted(named) if folder in team.folders}
    return {
        "folders": {folder: [gen[0] for gen in gens] for folder, gens in folders.items()},
        "may_hold": [
            gen[0] for gens in folders.values() for gen in gens
            if user_id and teamlog.may_hold_key(team, user_id, gen[0])
        ],
    }
