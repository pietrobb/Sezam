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

import base64
import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WEB_CORE = "web/static/js/vendor/sezam-sync-core.js"

_IPV4 = re.compile(rb"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_PLACEHOLDER_IPS = {"1.1.1.1", "1.2.3.4", "5.6.7.8"}
_DOCUMENTATION_NETS = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
# A user's home directory: C:\Users\name\, /home/name/, /Users/name/.
_HOME_PATH = re.compile(
    rb"(?i:[a-z]:(?:\\\\|\\|/)users(?:\\\\|\\|/))(?P<win>[^\\/\s\"'<>|:*?]+)"
    rb"|/home/(?P<linux>[a-z_][\w.-]*)/"
    rb"|/Users/(?P<mac>[A-Za-z_][\w.-]*)/"
)
# Placeholder accounts the tests and docs name on purpose.
_PLACEHOLDER_HOMES = {
    "public", "default", "name", "user", "username", "someone", "u", "ai-web", "runner", "alice", "bob",
}
_TOKEN = re.compile(r"[\w.@-]+")
# Review 8bc70f7 #1: tests/test_deployment.py asserted the production host's
# dynamic-DNS name was absent and so carried it. A name under a dynamic-DNS
# provider is always someone's own machine. Assembled at run time.
_DYNAMIC_DNS = re.compile(
    rb"(?i)[a-z0-9-]+\.(?:" + b"|".join(
        re.escape(p.encode()) for p in (
            "duck" + "dns.org", "no-" + "ip.org", "no-" + "ip.com", "ddns" + ".net",
            "dyn" + "u.net", "dyn" + "dns.org", "free" + "dns.afraid.org", "hopto" + ".org",
            "zap" + "to.org", "sytes" + ".net", "ddns" + "free.com", "my" + "fritz.net",
        )
    ) + rb")"
)


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
        out.append((name, data))
        if name == WEB_CORE:
            for blob in re.findall(rb"[A-Za-z0-9+/]{2000,}={0,2}", data):
                out.append((f"{name} (inlined module)", base64.b64decode(blob)))
    return out


def _public_ips(data: bytes) -> set[str]:
    found = set()
    for match in _IPV4.finditer(data):
        text = match.group(0).decode()
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            continue  # a version number such as 1.2.300.4
        if (
            ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local
            or text in _PLACEHOLDER_IPS
            or any(ip in net for net in _DOCUMENTATION_NETS)
        ):
            continue
        found.add(text)
    return found


def _home_paths(data: bytes) -> set[str]:
    found = set()
    for match in _HOME_PATH.finditer(data):
        account = next(g for g in match.groups() if g is not None).decode(errors="replace")
        if account.lower() not in _PLACEHOLDER_HOMES:
            found.add(match.group(0).decode(errors="replace"))
    return found


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


def _dynamic_dns(data: bytes) -> set[str]:
    return {m.group(0).decode(errors="replace") for m in _DYNAMIC_DNS.finditer(data)}


def test_no_public_address_or_home_directory_in_tracked_files():
    hits = {}
    for name, data in _contents():
        found = _public_ips(data) | _home_paths(data) | _dynamic_dns(data)
        if found:
            hits[name] = sorted(found)
    assert hits == {}


def test_the_web_core_module_is_scanned():
    names = [name for name, _ in _contents()]
    assert f"{WEB_CORE} (inlined module)" in names


def _private_denylist() -> set[str]:
    path = os.environ.get("SEZAM_PRIVATE_DENYLIST")
    if not path:
        pytest.skip("SEZAM_PRIVATE_DENYLIST is not set (maintainer-only check)")
    values = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip().lower()
        if value:
            values.add(value)
    assert values, f"{path} lists no values"
    return values


def _variants(token: str):
    token = token.strip(".-@").lower()
    yield token
    if "@" in token:
        yield token.split("@", 1)[0]


def test_no_value_of_the_private_denylist_in_tracked_files():
    denied = _private_denylist()
    digests = {d[len("sha256:"):] for d in denied if d.startswith("sha256:")}
    hits = []
    for name, data in _contents():
        text = data.decode("utf-8", errors="ignore")
        tokens = {v for t in set(_TOKEN.findall(text)) for v in _variants(t)}
        hashed = {hashlib.sha256(t.encode()).hexdigest() for t in tokens} if digests else set()
        if tokens & denied or hashed & digests or any(" " in d and d in text.lower() for d in denied):
            hits.append(name)
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
