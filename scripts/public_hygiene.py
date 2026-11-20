"""INV-10 (docs/ROOT_CAUSE_PLAN.md): the public repository gives nothing away.

One decision for both places that look: tests/test_open_source_hygiene.py
scans the tracked tree, and the pre-push hook (.githooks/pre-push) scans
everything a push would publish: every new blob (files deleted again in a
later commit too), every file name, every commit message and every author
and committer e-mail.

Always checked: public IPv4 addresses, home-directory paths of real
accounts, host names under dynamic-DNS providers. The maintainer's own
values stay outside the repository (SEZAM_PRIVATE_DENYLIST, or
~/.sezam-private-denylist): one value per line, plain or sha256:<hex> of the
lower-case value; a value matches a whole token or any part of one (review
8bc70f7 #1: the first label of the production host's name matched an old
hash while the full name did not).

    python scripts/public_hygiene.py <old-sha> <new-sha>   # what a push adds
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

WEB_CORE = "web/static/js/vendor/sezam-sync-core.js"
NOREPLY = "users.noreply.github.com"
ZERO = "0" * 40

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
_PARTS = re.compile(r"[.@_-]")
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


def public_ips(data: bytes) -> set[str]:
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


def home_paths(data: bytes) -> set[str]:
    found = set()
    for match in _HOME_PATH.finditer(data):
        account = next(g for g in match.groups() if g is not None).decode(errors="replace")
        if account.lower() not in _PLACEHOLDER_HOMES:
            found.add(match.group(0).decode(errors="replace"))
    return found


def dynamic_dns(data: bytes) -> set[str]:
    return {m.group(0).decode(errors="replace") for m in _DYNAMIC_DNS.finditer(data)}


def always_found(data: bytes) -> set[str]:
    """What no tracked byte may hold, whoever maintains the repository."""
    return public_ips(data) | home_paths(data) | dynamic_dns(data)


def denylist_path() -> Path | None:
    path = os.environ.get("SEZAM_PRIVATE_DENYLIST")
    if path:
        return Path(path)
    default = Path.home() / ".sezam-private-denylist"
    return default if default.exists() else None


def read_denylist(path: Path) -> set[str]:
    values = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip().lower()
        if value:
            values.add(value)
    return values


def variants(token: str):
    """The token, and every part and dot-suffix of it: a host's first label,
    an e-mail's local part, a domain."""
    token = token.strip(".-@_").lower()
    if not token:
        return
    yield token
    yield from (p for p in _PARTS.split(token) if p)
    yield from (p for p in re.split(r"[.@]", token) if p)
    labels = token.split("@")[-1].split(".")
    for i in range(1, len(labels)):
        yield ".".join(labels[i:])
    if "@" in token:
        yield token.split("@", 1)[0]


def denied_in(data: bytes, denied: set[str]) -> bool:
    if not denied:
        return False
    digests = {d[len("sha256:"):] for d in denied if d.startswith("sha256:")}
    text = data.decode("utf-8", errors="ignore").lower()
    tokens = {v for t in set(_TOKEN.findall(text)) for v in variants(t)}
    if tokens & denied or any(" " in d and d in text for d in denied):
        return True
    return bool(digests) and bool({hashlib.sha256(t.encode()).hexdigest() for t in tokens} & digests)


def expand(name: str, data: bytes) -> list[tuple[str, bytes]]:
    """A file, and the WebAssembly module the vendored web core inlines."""
    out = [(name, data)]
    if name == WEB_CORE:
        for blob in re.findall(rb"[A-Za-z0-9+/]{2000,}={0,2}", data):
            out.append((f"{name} (inlined module)", base64.b64decode(blob)))
    return out


def is_noreply(email: str) -> bool:
    """An address nobody reads, so no person's: GitHub's per-user noreply, or a
    noreply@ mailbox (the commits of an AI assistant)."""
    email = email.lower()
    return email.endswith("@" + NOREPLY) or email.split("@", 1)[0] in ("noreply", "no-reply")


def _git(root: Path, *args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=root, input=stdin, capture_output=True, check=True
    ).stdout


def pushed(root: Path, old: str, new: str) -> list[tuple[str, bytes]]:
    """Everything ``git push`` of ``new`` publishes beyond ``old`` (ZERO: a new
    branch, then beyond every remote-tracking ref): new blobs and their paths,
    commit messages, author and committer identities."""
    known = old != ZERO and subprocess.run(
        ["git", "cat-file", "-e", f"{old}^{{commit}}"], cwd=root, capture_output=True
    ).returncode == 0
    since = [f"^{old}"] if known else ["--not", "--remotes"]
    out: list[tuple[str, bytes]] = []
    commits = _git(root, "rev-list", new, *since).decode().split()
    for sha in commits:
        meta = _git(root, "show", "-s", "--format=%an <%ae>%n%cn <%ce>%n%B", sha)
        out.append((f"commit {sha[:12]}", meta))
        for email in _git(root, "show", "-s", "--format=%ae%n%ce", sha).decode().split():
            if not is_noreply(email):
                out.append((f"commit {sha[:12]} e-mail", b"not-noreply " + email.encode()))
    objects = _git(root, "rev-list", "--objects", new, *since).decode().splitlines()
    paths = {}
    for line in objects:
        sha, _, path = line.partition(" ")
        if path:
            paths.setdefault(sha, path)
    if paths:
        batch = _git(root, "cat-file", "--batch-check=%(objectname) %(objecttype)",
                     stdin="\n".join(paths).encode()).decode().splitlines()
        for line in batch:
            sha, kind = line.split()
            path = paths[sha]
            out.append((f"path {path}", path.encode()))
            if kind == "blob":
                out.extend(expand(path, _git(root, "cat-file", "blob", sha)))
    return out


def findings(items: list[tuple[str, bytes]], denied: set[str]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for name, data in items:
        found = sorted(always_found(data))
        if data.startswith(b"not-noreply "):
            found.append("author or committer e-mail is not a GitHub noreply address")
        if denied_in(data, denied):
            found.append("a value of the private denylist")
        if found:
            hits[name] = found
    return hits


def main(argv: list[str]) -> int:
    root = Path(_git(Path.cwd(), "rev-parse", "--show-toplevel").decode().strip())
    if len(argv) == 2:
        refs = [(argv[0], argv[1])]
    else:  # pre-push: "<local ref> <local sha> <remote ref> <remote sha>" per line
        refs = [(f[3], f[1]) for f in (line.split() for line in sys.stdin) if len(f) == 4]
    path = denylist_path()
    denied = read_denylist(path) if path else set()
    if path is None:
        print("public_hygiene: no private denylist (SEZAM_PRIVATE_DENYLIST or "
              "~/.sezam-private-denylist); only the built-in checks ran", file=sys.stderr)
    hits: dict[str, list[str]] = {}
    for old, new in refs:
        if new != ZERO:
            hits.update(findings(pushed(root, old, new), denied))
    for name, found in hits.items():
        # Name what was found by kind only: the hook's output may be shared.
        print(f"public_hygiene: refused: {name}: {len(found)} finding(s)", file=sys.stderr)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
