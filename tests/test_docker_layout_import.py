"""R17-N2: the server imports in the layout the Dockerfile builds.

The image has no ``sezam`` package: shared client files are copied into
``server/app`` under another name (``teamlog_core.py``, ``key_vouchers_core.py``).
A relative import inside such a file that only works inside ``src/sezam`` kept
every worker of c02cc47 from booting, and no test noticed. This test rebuilds
the image's /app from the Dockerfile's COPY lines and imports the app there
with ``sezam`` made unimportable.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_COPY = re.compile(r"^COPY\s+(?:--\S+\s+)*(\S+)\s+(\S+)\s*$")


def _image_copies() -> list[tuple[str, str]]:
    copies = []
    for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines():
        m = _COPY.match(line.strip())
        if m and m.group(2).startswith("/app/"):
            copies.append((m.group(1), m.group(2)[len("/app/"):]))
    return copies


def test_the_dockerfile_copies_the_shared_core_files():
    targets = dict((dst, src) for src, dst in _image_copies())
    assert targets["server/app/teamlog_core.py"] == "src/sezam/teamlog.py"
    assert targets["server/app/key_vouchers_core.py"] == "src/sezam/key_vouchers.py"


def test_the_voucher_core_encodes_ids_like_the_models():
    from sezam import key_vouchers, models

    for value in ("01JM0000000000000000000001", "abc", ""):
        assert key_vouchers.ulid_to_bytes(value) == models.ulid_to_bytes(value)
    for bad in ("x" * 27, "a\x00b"):
        for fn in (key_vouchers.ulid_to_bytes, models.ulid_to_bytes):
            try:
                fn(bad)
            except ValueError:
                continue
            raise AssertionError(f"{fn.__module__} took {bad!r}")


def test_the_server_imports_in_the_image_layout_without_sezam(tmp_path):
    app = tmp_path / "app"
    for src, dst in _image_copies():
        source, target = ROOT / src, app / dst
        if source.is_dir():
            shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    probe = (
        "import sys; sys.modules['sezam'] = None\n"
        "import server.app.main, server.app.key_vouchers, server.app.team_log\n"
        "assert server.app.key_vouchers.core.__name__ == 'server.app.key_vouchers_core'\n"
        "assert server.app.team_log.core.__name__ == 'server.app.teamlog_core'\n"
        "print('ok')\n"
    )
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env.update({"SEZAM_DATA_DIR": str(tmp_path / "data"), "PYTHONDONTWRITEBYTECODE": "1"})
    run = subprocess.run([sys.executable, "-c", probe], cwd=app, env=env,
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0 and run.stdout.strip().endswith("ok"), run.stderr[-3000:]
