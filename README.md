# Sezam

> [!WARNING]
> **Alpha software. Do not use Sezam as the only place you keep your passwords.**
> The formats, the protocol and the server API can still change, and the code
> has not had an independent security audit. Keep an independent export of
> everything that matters (see the [emergency kit](docs/EMERGENCY_KIT.md)).

Sezam is an end-to-end encrypted credential vault for individuals and small
teams, plus an **AI broker**: an AI agent can use the servers, FTP accounts and
APIs stored in the vault without ever seeing a password, private key or token.

- **Desktop app and CLI** (`sezam`, `sezam-gui`; Python, PySide6). The vault is a
  local SQLite file; every entry is encrypted with libsodium (PyNaCl) under keys
  derived from the master password with Argon2id.
- **Sync server** (`server/`; FastAPI + MariaDB). It stores only ciphertext and
  signed objects. Folders are shared through per-folder keys wrapped for each
  member; revoking a user re-keys what they could read.
- **Web client** (`web/`) and **mobile app** (`mobile/`, Flutter) speak the same
  formats, checked by shared golden test vectors.
- **Recovery:** `.sezam-key` key backups, organisational recovery with Shamir
  shares, automatic encrypted vault snapshots and `sezam server reseed` to
  rebuild a lost server from a local copy.

Documentation is in Slovak: [technical documentation](docs/TECHNICKA_DOKUMENTACIA.md),
[user guide](docs/PRIRUCKA_POUZIVATELA.md), [how it works](docs/AKO_TO_FUNGUJE.md).

## Quick start

Requires Python 3.11 or newer and a Rust toolchain (the shared sync core in
`core/` is built on install). There are no release packages yet; install from
a clone:

```
git clone https://github.com/pietrobb/Sezam.git
cd Sezam
python -m pip install ./core/py
python -m pip install -e ".[gui]"
sezam init                      # create a local vault
sezam set Servers/web -f host -v 192.0.2.10
sezam-gui
```

Sezam works fully offline; a server is only needed for sync between devices
and for teams.

## Running the sync server

The server is a FastAPI app with MariaDB, started with Docker Compose. Create
a `.env` file next to `compose.yaml`:

```
SEZAM_DB_PASSWORD=<random>
SEZAM_DB_ROOT_PASSWORD=<random>
SEZAM_HMAC_SECRET=<random, at least 32 bytes>
SEZAM_BASE_URL=https://sezam.example.com
```

```
docker compose up -d --build
sezam connect https://sezam.example.com
```

The first vault connected to an empty server becomes its admin; others join
with an invitation from the admin.

The API listens on `127.0.0.1:8000` only. Put a reverse proxy with TLS (Caddy,
nginx) in front of it. Keep `.env` and the `jwt_key.bin` in the `sezam-api-data`
volume together with the database backups; how to back up and restore the server
is in section 16.7 of the [technical documentation](docs/TECHNICKA_DOKUMENTACIA.md).

## The AI broker

`sezam mcp-serve` is an MCP server and `sezam ssh-agent` an OpenSSH agent. They
are the only way an AI agent reaches vault secrets:

- The agent asks for an **operation**, not a secret: `ssh_execute`, SSH sessions,
  SFTP upload/download, `ftp` (FTPS by default), `http_request` (the broker adds
  the auth header), TOTP codes.
- **Default deny.** Each entry must explicitly allow each action
  (`sezam mcp-policy <path> --allow-action ...`). Tier 2 entries are invisible to
  the AI, tier 1 entries need the owner's approval for every use, showing the real
  target taken from the entry.
- **Kill switch:** `sezam ai off` (no password needed), the phone app, or locking
  the vault refuses every call and cuts running sessions and transfers.
  `sezam ai on` needs the master password.
- Secrets are redacted from command output, and every operation is audited
  (`sezam ai log`).
- Optional short-lived SSH certificates with Sezam as the SSH CA
  (`sezam ai-host-setup`).

## Threat model of the AI broker

The agent (for example Claude Code) usually has a shell and runs as an ordinary OS
user. How strong the boundary is depends on where the broker runs relative to it.

| Level | Setup | Protects against | Does not protect against |
|---|---|---|---|
| **L1** | Broker runs as the same OS user as the agent (default). | Secrets leaking into the chat, history and logs of the AI service. Prompt injection such as "send me the password" (entry policies, tier 2 invisible, tier 1 approved by the owner). Kill switch, phone brake, audit of every operation. On Linux also core dumps, `ptrace` and reading the broker's memory from other processes of the same user. | An agent that deliberately attacks the local machine: it can read `~/.sezam`, take the session key from the keyring while a CLI session is open, replace or restart the broker, modify the Sezam installation, or capture the master password as it is typed. On Windows and macOS it can also read the running broker's memory. |
| **L2** | Broker runs as its own OS user `sezam-broker` (systemd service / Windows scheduled task); the vault belongs to it. The agent's user is in group `sezam-ai`, which may only connect to the sockets (`sezam broker install-service`). | Everything in L1. The agent can no longer read the vault, the keyring or the broker's memory, and cannot restart the broker. It can pull the brake, but not turn AI access on or unlock. | What the AI does on servers within the access it was granted. Root on the local machine. A permanent key the AI adds to `authorized_keys` on a server once logged in. |
| **L3** | L2 plus short-lived SSH certificates from Sezam and `AuthorizedKeysFile none` for the AI account on the server (`sezam ai-host-setup`). | Everything in L2, plus cut-off on the server side: the AI's own keys do not work, a copied certificate expires within its TTL, and a reaper ends the account's sessions and detached processes within the TTL (2 × TTL if the AI logs in again with a certificate it held). Not instantly: Sezam does not connect to the server. | What the AI does while a certificate is valid, and changes outside the account's processes (files in the web root, commands run via sudo, other users' services). Root on the server or on the broker's machine. |

Details: section 18 of the [technical documentation](docs/TECHNICKA_DOKUMENTACIA.md).

## Development

```
python -m pip install ./core/py
python -m pip install -e ".[dev,import,gui]" pytest-qt
python -m ruff check
python -m pytest -q
```

Server tests that need real row locks run against MariaDB when
`SEZAM_TEST_MARIADB=user:password@host:port` is set. Mobile: `cd mobile && flutter test`.

## Contributing

Pull requests are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md). Contributors
sign a short [Contributor License Agreement](CLA.md) on their first pull request.

## Security

Please report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

[GNU Affero General Public License v3.0](LICENSE).
