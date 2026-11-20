"""AI broker TODO section 11 (O1): no personal data in the tracked tree.

Before the code goes public, the production server's address and the
author's personal e-mail, logins, network names and home directory must not
appear in any tracked file, the module inlined in the vendored web core
included.

Review c78fd19 (R13): the earlier version of this test listed the SHA-256 of
each forbidden value, and the public repository then carried a hash of the
production IP that a brute force over the IPv4 space reverses in minutes. The
tree now holds no trace of the values themselves. What it checks always:

- every IPv4 address is loopback, private, a documentation range
  (RFC 5737) or one of a few well-known placeholders;
- no absolute home-directory path of a real account (Windows, Linux, macOS),
  also inside the base64 WebAssembly module of sezam-sync-core.js.

The maintainer's own values stay outside the repository: point
SEZAM_PRIVATE_DENYLIST at a local file with one forbidden value per line
(plain text or sha256:<hex> of the lower-case value, '#' starts a comment)
and the test also looks for those.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import public_hygiene as hygiene
from scripts.public_hygiene import WEB_CORE

ROOT = Path(__file__).resolve().parents[1]
_public_ips, _home_paths, _dynamic_dns = hygiene.public_ips, hygiene.home_paths, hygiene.dynamic_dns


def _tracked_files() -> list[str]:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout")
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout
    return [name for name in out.decode("utf-8").split("\0") if name]


def _contents() -> list[tuple[str, bytes]]:
    out = []
    for name in _tracked_files():
        try:
            data = (ROOT / name).read_bytes()
        except OSError:
            continue
        out.extend(hygiene.expand(name, data))
    return out


def test_the_checks_catch_what_they_are_for():
    # Assembled at run time, so this file itself stays clean.
    public = ".".join(["195", "201", "42", "10"]).encode()
    resolver = ".".join(["8"] * 4).encode()
    users, home = b"Use" + b"rs", b"ho" + b"me"
    text = (
        b"server " + public + b" and " + resolver + b"; docs 203.0.113.7, lan 192.168.1.1, v1.2.300.4\n"
        b"C:\\" + users + b"\\jana\\.cargo\\registry and C:\\\\" + users + b"\\\\jana\\\\x, "
        b"/" + home + b"/jana/src, /" + users + b"/jana/Library; placeholders /home/someone/.ssh "
        b"C:\\" + users + b"\\Public\\x /api/users/register"
    )
    assert _public_ips(text) == {public.decode(), resolver.decode()}
    found = _home_paths(text)
    assert len(found) == 4 and all("jana" in path for path in found)  # Windows twice, Linux, macOS
    host = b"jana-nas." + b"duck" + b"dns.org"
    assert _dynamic_dns(b"server " + host + b" and sezam.example.org") == {host.decode()}


def test_the_denylist_matches_any_part_of_a_name():
    """Review 8bc70f7 #1: a denylisted first label, local part or domain
    matches inside the full name, plain or hashed."""
    import hashlib

    host = b"jana-nas.example.org"
    for denied in ("jana-nas", "jana", "example.org", "sha256:" + hashlib.sha256(b"jana-nas").hexdigest()):
        assert hygiene.denied_in(b"see " + host, {denied}), denied
    assert hygiene.denied_in(b"mail jana.k@example.net", {"jana.k"})
    assert not hygiene.denied_in(b"see " + host, {"janak"})


def test_no_public_address_or_home_directory_in_tracked_files():
    hits = {}
    for name, data in _contents():
        found = hygiene.always_found(data)
        if found:
            hits[name] = sorted(found)
    assert hits == {}


def test_the_web_core_module_is_scanned():
    names = [name for name, _ in _contents()]
    assert f"{WEB_CORE} (inlined module)" in names


def test_no_value_of_the_private_denylist_in_tracked_files():
    path = hygiene.denylist_path()
    if path is None:
        pytest.skip("no private denylist (maintainer-only check)")
    denied = hygiene.read_denylist(path)
    assert denied, f"{path} lists no values"
    hits = [name for name, data in _contents() if hygiene.denied_in(data, denied)]
    assert hits == []


def _check_attr(attr: str, names: list[str]) -> dict[str, str]:
    out = subprocess.run(
        ["git", "-c", "core.autocrlf=true", "check-attr", "-z", attr, "--", *names],
        cwd=ROOT, capture_output=True, check=True,
    ).stdout.decode("utf-8").split("\0")
    return {out[i]: out[i + 2] for i in range(0, len(out) - 2, 3)}


def test_checkout_keeps_sri_pinned_scripts_byte_exact_and_shell_scripts_lf():
    # A Windows clone with core.autocrlf=true used to rewrite the vendored
    # scripts with CRLF, so their sha384 no longer matched the SRI hash in
    # index.html and the browser refused to load libsodium/argon2.
    tracked = _tracked_files()
    index_html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    pinned = [
        "web" + src
        for src in re.findall(r'<script src="([^"]+)"\s+integrity=', index_html)
    ]
    assert pinned and all(name in tracked for name in pinned)
    assert set(_check_attr("text", pinned).values()) == {"unset"}

    shell = [name for name in tracked if name.endswith(".sh")]
    assert shell
    assert set(_check_attr("eol", shell).values()) == {"lf"}
