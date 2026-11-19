# Security policy

Sezam is alpha software (see the warning in [README.md](README.md)). Security
reports are very welcome all the same.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Report it privately through GitHub: on the repository page open
**Security → Advisories → Report a vulnerability** (GitHub private vulnerability
reporting). Only the maintainers see the report.

Please include:

- the affected component (desktop/CLI, AI broker, sync server, web client,
  mobile app) and the commit or version,
- what an attacker can do and what they need for it (for example network
  access to the server, a malicious AI agent on the same machine, a stolen
  device),
- steps or a proof of concept to reproduce it.

Never send real passwords, vault files or keys. Use a throwaway vault.

## What to expect

- Acknowledgement within 7 days.
- An assessment and, for a confirmed issue, a planned fix within 30 days.
  Critical issues (secrets leaving the client, signature or encryption bypass,
  the AI broker releasing a secret or acting without the required approval)
  are handled first.
- Credit in the advisory if you want it, once a fix is released.

## Scope

In scope: everything in this repository, in particular

- the cryptography and sync protocol (encryption, signatures, key rotation,
  revocation, recovery),
- the AI broker (`sezam mcp-serve`, `sezam ssh-agent`): any way for an agent to
  obtain a secret, bypass an entry policy, tier 1 approval or the kill switch,
  or avoid the audit log. The levels L1-L3 in the README's threat model state
  what the broker is designed to withstand; an attack that the threat model
  already lists as not protected against is not a vulnerability by itself.
- the sync server and the web client (authentication, access control, XSS,
  injection).

Out of scope: denial of service through volume alone, and missing hardening of
a particular deployment (TLS settings of your own reverse proxy, for example).
