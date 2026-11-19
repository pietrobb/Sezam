"""AI broker TODO section 11: the public-facing files of the repository."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _readme() -> str:
    return (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_opens_with_the_alpha_warning():
    head = "\n".join(_readme().splitlines()[:8])
    assert "[!WARNING]" in head
    assert "Alpha software" in head
    assert "Do not use Sezam as the only place you keep your passwords" in head


def test_readme_has_the_l1_l2_l3_threat_model():
    text = _readme()
    assert "## Threat model of the AI broker" in text
    rows = re.findall(r"^\| \*\*(L[123])\*\* \|", text, re.MULTILINE)
    assert rows == ["L1", "L2", "L3"]
    # Each level says what it does NOT protect against.
    assert "| Does not protect against |" in text


def test_readme_and_security_local_links_exist():
    for name in ("README.md", "SECURITY.md", "CONTRIBUTING.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        for target in re.findall(r"\]\(([^)#:]+)\)", text):
            assert (ROOT / target).is_file(), f"{name}: {target}"


# The canonical text from https://www.gnu.org/licenses/agpl-3.0.txt.
AGPL_3_SHA256 = "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"


def test_license_is_the_unmodified_agpl_3_text():
    data = (ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n")
    assert data.lstrip().startswith(b"GNU AFFERO GENERAL PUBLIC LICENSE")
    assert hashlib.sha256(data).hexdigest() == AGPL_3_SHA256


def test_package_metadata_declares_the_license():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["license"] == "AGPL-3.0-only"
    assert project["license-files"] == ["LICENSE"]
    assert project["readme"] == "README.md"


CLA_SIGN_PHRASE = "I have read the CLA Document and I hereby sign the CLA"


def test_cla_sign_phrase_matches_the_bot():
    """The bot only reacts to the exact sentence the documents tell people to post."""
    workflow = (ROOT / ".github" / "workflows" / "cla.yml").read_text(encoding="utf-8")
    assert f"github.event.comment.body == '{CLA_SIGN_PHRASE}'" in workflow
    assert "path-to-document: https://github.com/pietrobb/Sezam/blob/main/CLA.md" in workflow
    for name in ("CLA.md", "CONTRIBUTING.md"):
        assert CLA_SIGN_PHRASE in (ROOT / name).read_text(encoding="utf-8"), name
    assert "CONTRIBUTING.md" in _readme() and "CLA.md" in _readme()


def test_the_cla_bot_runs_only_for_signing_comments_on_a_pull_request():
    # Review c78fd19: its token writes to the repository; no pull_request_target
    # and no plain issue comment starts it.
    workflow = (ROOT / ".github" / "workflows" / "cla.yml").read_text(encoding="utf-8")
    on = workflow.split("\non:", 1)[1].split("\npermissions:", 1)[0]
    assert re.findall(r"^  (\w+):", on, re.MULTILINE) == ["issue_comment"]
    assert "github.event.issue.pull_request &&" in workflow
    permissions = re.findall(r"^  ([\w-]+): (\w+)", workflow.split("\npermissions:", 1)[1].split("\njobs:")[0], re.M)
    assert dict(permissions) == {"contents": "write", "pull-requests": "write", "statuses": "write"}


def _install_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if re.search(r"\bpip install\b", line)]


def test_the_sync_core_is_installed_from_source_before_the_package():
    # Review c78fd19 (dependency confusion): neither sezam nor sezam-sync-core
    # is registered on PyPI by the project; an install of the package before
    # ./core/py made pip fetch sezam-sync-core from the index.
    sources = [ROOT / ".github" / "workflows" / "tests.yml", *sorted((ROOT / "scripts").glob("ci_*.sh")),
               ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "docs" / "index.html"]
    for path in sources:
        core_installed = False
        for line in _install_lines(path.read_text(encoding="utf-8")):
            if "./core/py" in line:
                core_installed = True
            elif re.search(r'install[^\n]*(-e\s+)?"?\.(\[|"|\s|$)', line):
                assert core_installed, f"{path.relative_to(ROOT)}: {line.strip()}"
            assert not re.search(r"pip install\s+(-\S+\s+)*sezam(-sync-core)?\b", line), line
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["tool"]["uv"]["sources"]["sezam-sync-core"] == {"path": "core/py"}


def test_security_policy_asks_for_private_reports():
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "Do not open a public issue" in text
    assert "Report a vulnerability" in text and "private vulnerability" in text
    assert "SECURITY.md" in _readme()
