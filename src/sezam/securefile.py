"""Private output files for exports and key backups."""

from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import IO, Iterator


def private_temp_path(dest: str | Path) -> Path:
    """Create an empty owner-only (0600) temp file next to ``dest``."""
    dest = Path(dest)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.", suffix=".tmp")
    os.close(fd)
    return Path(tmp)


def publish(tmp: Path, dest: str | Path) -> None:
    """Atomically move ``tmp`` to ``dest``.

    os.replace swaps the directory entry, so a symlink planted at ``dest``
    is replaced instead of followed to its target.
    """
    os.replace(tmp, dest)


@contextmanager
def private_output(dest: str | Path, mode: str = "w", **open_kwargs) -> Iterator[IO]:
    """Write ``dest`` atomically as an owner-only file."""
    tmp = private_temp_path(dest)
    try:
        with open(tmp, mode, **open_kwargs) as f:
            yield f
        publish(tmp, dest)
    except BaseException:
        with suppress(OSError):
            tmp.unlink()
        raise


# Spreadsheet apps execute cells starting with these characters. A leading
# apostrophe is the escape; an apostrophe already present is doubled so the
# importer can undo exactly one level and round-trips stay lossless.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_escape(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES + ("'",)):
        return "'" + text
    return text


def csv_unescape(text: str) -> str:
    if len(text) > 1 and text[0] == "'" and text[1] in _FORMULA_PREFIXES + ("'",):
        return text[1:]
    return text
