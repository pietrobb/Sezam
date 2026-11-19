"""Upload set for the deploy scripts, derived from git instead of a hand list.

Hand-maintained lists silently missed new modules (server/app/auth.py,
routers/users.py), so a deploy shipped a server that could not import.
The Dockerfile copies the whole server/ and web/ trees, so every tracked file
in them is uploaded, plus the build files compose needs.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_FILES = (".dockerignore", "Dockerfile", "compose.yaml")
TREES = ("server", "web")


def tracked_deploy_files(deploy_dir: str) -> dict[str, str]:
    """``{local relative path: remote path}`` for every tracked deploy file."""
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", *BUILD_FILES, *TREES],
        cwd=ROOT, check=True, capture_output=True,
    ).stdout.decode("utf-8").split("\0")
    files = sorted(path for path in listed if path)
    missing = [path for path in BUILD_FILES if path not in files]
    if missing:
        raise RuntimeError(f"Deploy build files are not tracked: {missing}")
    gone = [path for path in files if not (ROOT / path).is_file()]
    if gone:
        raise RuntimeError(f"Tracked deploy files missing from the working tree: {gone}")
    return {path: f"{deploy_dir}/{path}" for path in files}
