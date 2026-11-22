"""CLI interface for Sezam vault.

Spec 7.4: sezam init/unlock/lock/get/set/list/search/generate/change-password/push/pull/share/export/import
"""

from __future__ import annotations

import logging
import base64
import csv
import getpass
import json
import os
import stat
import struct
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

import click

from .crypto.kdf import benchmark_argon2
from .password import estimate_strength, generate_passphrase, generate_password
from .securefile import csv_escape, private_output
from .usernames import normalize_username
from .vault.crud import Vault, require_usable_password

logger = logging.getLogger(__name__)


# ── Rate limiting for wrong-password attempts ──

_MAX_ATTEMPTS = 5
_LOCKOUT_WINDOW_SECONDS = 15 * 60  # 15 minutes


def _attempt_tracker_path() -> Path:
    """Failed-attempt tracker, kept in the per-user vault directory.

    Never a fixed name in the shared temp dir: there another local user could
    plant the file and lock the owner out (or reset the counter).
    """
    return _get_vault_path() / "auth_attempts.json"


def _load_attempts(tracker: Path, cutoff: float) -> list[float]:
    """Recent attempt timestamps, ignoring files we did not create ourselves."""
    try:
        st = os.lstat(tracker)
    except FileNotFoundError:
        return []
    except OSError as e:
        logger.warning("Cannot stat attempt tracker %s: %s", tracker, e)
        return []
    if not stat.S_ISREG(st.st_mode):
        logger.warning("Ignoring attempt tracker %s: not a regular file", tracker)
        return []
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        logger.warning("Ignoring attempt tracker %s: owned by uid %d", tracker, st.st_uid)
        return []
    try:
        data = json.loads(tracker.read_text())
        return [float(t) for t in data.get("attempts", []) if float(t) > cutoff]
    except (OSError, ValueError, TypeError, AttributeError):
        return []


def _check_rate_limit() -> None:
    """Exit if too many wrong-password attempts were made (max 5 / 15 min)."""
    now = time.time()
    attempts = _load_attempts(_attempt_tracker_path(), now - _LOCKOUT_WINDOW_SECONDS)
    if len(attempts) >= _MAX_ATTEMPTS:
        remaining = int(min(attempts) + _LOCKOUT_WINDOW_SECONDS - now)
        click.echo(
            f"Too many failed attempts. Try again in {remaining} seconds.",
            err=True,
        )
        sys.exit(1)


def _record_failed_attempt() -> None:
    """Record a failed attempt: new 0600 file (O_EXCL) atomically replaced in."""
    tracker = _attempt_tracker_path()
    now = time.time()
    attempts = _load_attempts(tracker, now - _LOCKOUT_WINDOW_SECONDS)
    attempts.append(now)
    tmp_name = None
    try:
        fd, tmp_name = tempfile.mkstemp(dir=tracker.parent, prefix=".auth_attempts.")
        with os.fdopen(fd, "w") as f:
            json.dump({"attempts": attempts}, f)
        os.replace(tmp_name, tracker)
        tmp_name = None
    except OSError as e:
        logger.warning("Cannot record failed attempt in %s: %s", tracker, e)
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def _clear_failed_attempts() -> None:
    """Clear failed attempt history after a successful unlock."""
    try:
        _attempt_tracker_path().unlink()
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.warning("Cannot clear attempt tracker: %s", e)


# ── Vault helpers ──


def _get_vault_path() -> Path:
    """Get vault path from env or default."""
    return Path(os.environ.get("SEZAM_VAULT", Path.home() / ".sezam"))


def _has_local_vault() -> bool:
    return (_get_vault_path() / "sezam.db").exists()


def _open_vault() -> Vault:
    """Open and return the vault (must be unlocked separately)."""
    path = _get_vault_path()
    if not (path / "sezam.db").exists():
        click.echo("Vault not found. Run 'sezam init' first.", err=True)
        sys.exit(1)
    return Vault(path)


def _get_password(prompt: str = "Master password: ") -> str:
    """Get password from stdin or prompt."""
    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if not line:
            # EOF is not an empty answer: an empty new password would lock
            # the vault out of every client that refuses one.
            click.echo(f"No input for '{prompt.strip()}' (end of input).", err=True)
            sys.exit(1)
        # Strip one line ending only: rstrip("\r\n") also ate a \r that is
        # part of the password, so such a password could never be entered.
        for ending in ("\r\n", "\n"):
            if line.endswith(ending):
                return line[: -len(ending)]
        return line
    return getpass.getpass(prompt)


def _username_value(value: str) -> str:
    username = normalize_username(value)
    if not username:
        raise click.BadParameter("Username cannot be empty.")
    return username


def _get_new_password(vault: Optional[Vault] = None) -> str:
    """Read and confirm a new master password; exit on mismatch or empty."""
    new_password = _get_password("New master password: ")
    confirm = _get_password("Confirm new master password: ")
    error = None
    if new_password != confirm:
        error = "Passwords do not match."
    elif not new_password:
        error = "Password cannot be empty."
    else:
        try:
            require_usable_password(new_password)
        except ValueError as exc:
            error = str(exc)
    if error:
        click.echo(error, err=True)
        if vault is not None:
            vault.lock()
        sys.exit(1)
    return new_password


# Session file for keeping vault unlocked between commands.
#
# The session never stores the master password: only the derived KEK plus
# an absolute expiry live in the OS keyring. Commands that change security
# policy or bulk-export key material ignore the session and always require
# the master password to be typed again (see _unlock_vault_fresh).

_SESSION_MARKER = "__keyring_v2__"
DEFAULT_SESSION_TTL_MINUTES = 15
MAX_SESSION_TTL_MINUTES = 8 * 60


def _session_path() -> Path:
    return _get_vault_path() / ".session"


def _save_session(kek: bytes | bytearray, ttl_minutes: int = DEFAULT_SESSION_TTL_MINUTES) -> None:
    """Save a time-limited KEK session in the OS credential store."""
    sp = _session_path()
    record = json.dumps({
        "v": 2,
        "kek": bytes(kek).hex(),
        "expires_at": time.time() + ttl_minutes * 60,
        "vault": str(_get_vault_path().resolve()),
    })
    try:
        import keyring
        keyring.set_password("sezam", "session", record)
    except Exception as exc:
        if sp.exists():
            sp.unlink()
        raise click.ClickException(
            "OS keyring is unavailable; the session was not created."
        ) from exc

    try:
        sp.write_text(_SESSION_MARKER, encoding="ascii")
        os.chmod(str(sp), 0o600)
    except OSError as exc:
        try:
            keyring.delete_password("sezam", "session")
        except Exception:
            logger.debug("Session keyring entry was not removed", exc_info=True)
        if sp.exists():
            sp.unlink()
        raise click.ClickException(
            "Could not create the session marker; the session was not created."
        ) from exc


def _load_session() -> Optional[bytearray]:
    """Return the session KEK if a valid, unexpired session exists.

    Legacy sessions (raw master password without expiry, or XOR-obfuscated
    files) and expired sessions are wiped and refused.
    """
    loaded = _load_session_record()
    return None if loaded is None else loaded[0]


def _load_session_record() -> Optional[tuple[bytearray, float]]:
    """Like _load_session, plus the session's expiry, which identifies it:
    every 'sezam unlock' creates a session with a new expiry."""
    sp = _session_path()
    if not sp.exists():
        return None
    try:
        content = sp.read_text()
    except OSError:
        return None
    if content != _SESSION_MARKER:
        _clear_session()
        return None
    try:
        import keyring
        raw = keyring.get_password("sezam", "session")
    except Exception:
        return None
    try:
        record = json.loads(raw) if raw else None
        valid = (
            isinstance(record, dict)
            and record.get("v") == 2
            and record.get("vault") == str(_get_vault_path().resolve())
            and float(record["expires_at"]) > time.time()
        )
        kek = bytearray.fromhex(record["kek"]) if valid else None
        expires_at = float(record["expires_at"]) if valid else 0.0
    except (ValueError, KeyError, TypeError):
        kek = None
    if kek is None or len(kek) != 32:
        _clear_session()
        return None
    return kek, expires_at


def _clear_session() -> None:
    """Clear session — wipe file and keyring entry."""
    sp = _session_path()
    if sp.exists():
        # Overwrite before deleting
        try:
            size = sp.stat().st_size
            sp.write_bytes(os.urandom(size))
        except OSError:
            logger.debug("Session marker overwrite failed", exc_info=True)
        sp.unlink()
    try:
        import keyring
        keyring.delete_password("sezam", "session")
    except Exception:
        # Usually "no such entry"; the marker is already gone either way.
        logger.debug("Session keyring entry was not removed", exc_info=True)


def _unlock_vault(vault: Vault, password: Optional[str] = None) -> None:
    """Unlock vault with password from session or prompt.

    Enforces rate limiting: max 5 wrong attempts per 15 minutes.
    """
    _check_rate_limit()

    if password is None:
        kek = _load_session()
        if kek is not None:
            try:
                vault.unlock_with_kek(kek)
                return
            except ValueError:
                # Stale session (e.g. password changed elsewhere).
                _clear_session()
            finally:
                kek[:] = b"\x00" * len(kek)
        password = _get_password()

    try:
        vault.unlock(password)
    except ValueError:
        _record_failed_attempt()
        click.echo("Wrong master password.", err=True)
        time.sleep(2)  # Delay on wrong password
        sys.exit(1)

    _clear_failed_attempts()


def _unlock_vault_fresh(vault: Vault, prompt: str = "Master password (required for this command): ") -> str:
    """Unlock for a privileged command: ignore any CLI session.

    Changing MCP policy, plaintext/key export, recovery setup, revocation
    and server connection must not be reachable by an agent that merely
    inherits an unlocked CLI session. Returns the verified password.
    """
    password = _get_password(prompt)
    _unlock_vault(vault, password)
    return password


@click.group()
@click.version_option(version="0.1.0", prog_name="sezam")
def main():
    """Sezam — Encrypted credential vault."""
    pass


def _server_request(server_url: str, method: str, path: str,
                     body: Optional[dict] = None,
                     token: Optional[str] = None) -> dict:
    """Make an HTTP request to the Sezam server. Returns parsed JSON."""
    import urllib.request
    import urllib.error

    url = server_url.rstrip("/") + path
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        from .vault.sync_common import ServerError

        error_body = e.read().decode("utf-8", errors="replace")
        raise ServerError(e.code, error_body, show_detail=True)


def _open_server_keypair(recover_resp: dict, server_kek: bytearray):
    from .vault.crud import open_server_keypair

    return open_server_keypair(recover_resp, server_kek)


def _finish_bootstrap_upload(server_url: str, vault: Vault, password: str) -> None:
    from .vault.onboarding import finish_bootstrap_upload

    click.echo("Dokoncujem nahratie keypairu z preruseneho bootstrapu...")
    result = finish_bootstrap_upload(vault, server_url, password)
    click.echo(f"Push: {len(result.get('accepted', []))} objektov synchronizovanych.")
    if result.get("conflicts"):
        for c in result["conflicts"]:
            click.echo(f"  Neodoslane: {c['id']} — {c.get('error', '')}", err=True)
        click.echo(
            "Si administrator, ale nie vsetky data su na serveri. Skus 'sezam push' znova.",
            err=True,
        )
        return
    click.echo("Hotovo! Si administrator. Data boli synchronizovane.")


def _server_register_and_upload(
    server_url: str, vault: Vault, password: str, is_bootstrap: bool,
    invitation_token: Optional[str] = None,
) -> None:
    """Register with server (bootstrap or invitation) and upload keypair.

    After this function, vault_meta will have server_url, user_id set.
    """
    from .vault import pending_states
    from .vault.onboarding import keypair_upload_body

    kp = vault.keypair
    signing_pk_hex = kp.signing_pk.hex()
    encryption_pk_hex = kp.encryption_pk.hex()

    if is_bootstrap:
        # Bootstrap: first admin, no invitation needed
        username = vault.db.get_meta("username") or "admin"
        click.echo(f"Bootstrapping server as first admin ({username})...")
        resp = _server_request(server_url, "POST", "/api/bootstrap", {
            "username": username,
            "signing_pk": signing_pk_hex,
            "encryption_pk": encryption_pk_hex,
        })
    else:
        # Normal registration via invitation token
        username = vault.db.get_meta("username") or "user"
        click.echo(f"Registering with server as '{username}'...")
        resp = _server_request(server_url, "POST", "/api/users/register", {
            "invitation_token": invitation_token,
            "username": username,
            "signing_pk": signing_pk_hex,
            "encryption_pk": encryption_pk_hex,
        })

    onboarding_token = resp["token"]
    server_user_id = resp["user_id"]
    # encrypted_keypair is AAD-bound to user_id: re-wrap it for the server id
    # before uploading, so this and every other client can still open it.
    vault.rebind_server_identity(server_user_id)
    vault.db.set_meta("server_url", server_url.rstrip("/"))
    if is_bootstrap:
        # The admin account now exists without key material. If the upload
        # below fails, the next connect finishes it (_finish_bootstrap_upload).
        pending_states.mark_bootstrap_upload_pending(vault.db, True)

    # Upload encrypted keypair to server
    click.echo("Uploading encrypted keypair to server...")
    _server_request(
        server_url, "PUT", "/api/me/keypair", keypair_upload_body(vault, password),
        token=onboarding_token,
    )
    pending_states.mark_bootstrap_upload_pending(vault.db, False)

    click.echo("Keypair uploaded successfully.")

    if is_bootstrap:
        click.echo("Admin account created. Server is ready.")
    else:
        # Non-bootstrap users need admin approval
        click.echo("Registration complete. Waiting for admin approval...")
        click.echo("(Polling every 5 seconds. Press Ctrl+C to stop and log in later.)")
        _poll_for_approval(server_url, vault, password)


def _echo_pull_warnings(result: dict) -> None:
    from .vault.sync_client import pull_warnings

    for warning in pull_warnings(result):
        click.echo(warning, err=True)


def _poll_for_approval(server_url: str, vault: Vault, password: str) -> None:
    """Poll the server until admin approves the user, then do initial pull."""
    from .vault.sync_client import SyncClient

    kp = vault.keypair
    user_id = vault.db.get_meta("user_id")

    while True:
        time.sleep(5)
        try:
            # Try challenge-response auth — will fail if user is still pending
            client = SyncClient(vault.db, server_url, kp, user_id)
            client.set_dek_manager(vault.dek_mgr)
            client.authenticate()

            # If authenticate succeeds, user is approved
            click.echo("Approved! Pulling vault...")
            result = client.pull()
            _echo_pull_warnings(result)
            click.echo(
                f"Pull: {result['pulled']} objects, "
                f"commit_seq={result['max_commit_seq']}."
            )
            return

        except RuntimeError as e:
            from .vault.sync_common import server_error

            if server_error(e, 401) or server_error(e, 403):
                # Still pending — continue polling
                click.echo(".", nl=False)
                continue
            # Other error — warn but continue
            click.echo(f"\nPoll error: {e}", err=True)
            continue
        except KeyboardInterrupt:
            click.echo("\nStopped polling. Log in later once approved.")
            return


def _server_connect_flow(
    server_url: str, vault: Vault, password: str, unlock_code: Optional[str] = None
) -> None:
    """Shared server connection logic used by both 'connect' and 'init --server'.

    Handles all scenarios:
    1. Empty server (needs_setup=true) -> bootstrap as admin
    2. Existing server, user has account -> Path B recovery
    3. Existing server, no account -> invitation flow
    4. Server unreachable -> error
    """

    server_url = server_url.rstrip("/")

    # Step 1: Check server bootstrap status
    try:
        bootstrap_resp = _server_request(server_url, "GET", "/api/bootstrap-status")
    except Exception:
        click.echo("Server nie je dostupny.", err=True)
        return

    needs_setup = bootstrap_resp.get("needs_setup", False)

    from .vault.snapshots import take_snapshot

    connect_snapshot = take_snapshot(vault.db, "server-connect")

    from .vault.onboarding import BootstrapKeyMaterialElsewhere, bootstrap_upload_pending

    if not needs_setup and bootstrap_upload_pending(vault, server_url):
        try:
            _finish_bootstrap_upload(server_url, vault, password)
            _org_recovery_after_connect(vault, password)
            return
        except BootstrapKeyMaterialElsewhere as e:
            click.echo(str(e))
        except RuntimeError as e:
            click.echo(f"Dokoncenie bootstrapu zlyhalo: {e}", err=True)
            return

    if needs_setup:
        # Empty server — bootstrap as admin
        click.echo("Server je prazdny. Stanem sa administratorom.")
        _server_register_and_upload(server_url, vault, password, is_bootstrap=True)

        # Push local vault data
        from .vault.sync_client import SyncClient
        user_id = vault.db.get_meta("user_id")
        client = SyncClient(vault.db, server_url, vault.keypair, user_id)
        client.set_dek_manager(vault.dek_mgr)
        synced = False
        try:
            client.authenticate()
            result = client.push()
            accepted = len(result.get("accepted", []))
            click.echo(f"Push: {accepted} objektov synchronizovanych.")
            for c in result.get("conflicts", []):
                click.echo(f"  Neodoslane: {c['id']} — {c.get('error', '')}", err=True)
            synced = not result.get("conflicts")
        except RuntimeError as e:
            click.echo(f"Push zlyhal: {e}", err=True)

        # Review 526419e #1: it said so with nothing on the server.
        if synced:
            click.echo("Hotovo! Si administrator. Data boli synchronizovane.")
        else:
            click.echo(
                "Si administrator, ale nie vsetky data su na serveri. "
                "Skus 'sezam push' znova.",
                err=True,
            )
    else:
        # Existing server — try Path B recovery first
        username = vault.db.get_meta("username") or "admin"
        recovered = False

        try:
            # Check if this user has an account on the server
            meta_resp = _server_request(
                server_url, "GET", f"/api/meta?username={username}"
            )
            if meta_resp and meta_resp.get("argon2_salt"):
                # User exists — try Path B recovery
                from .vault.crud import (
                    recover_refusal,
                    recover_with_password,
                    server_account_kdf,
                )
                argon2_salt = bytes.fromhex(meta_resp["argon2_salt"])
                ap = server_account_kdf(meta_resp, vault.db)

                try:
                    _kek, recover_resp = recover_with_password(
                        lambda body: _server_request(
                            server_url, "POST", "/api/auth/recover", body=body
                        ),
                        username, password, argon2_salt, ap, unlock_code=unlock_code,
                    )
                    try:
                        # /recover returns the account keypair (no token);
                        # open it with the server-salt KEK before zeroizing.
                        server_keypair = _open_server_keypair(recover_resp or {}, _kek)
                        if server_keypair is not None:
                            vault.adopt_account_kek(
                                _kek, argon2_salt, ap,
                                key_epoch=int((recover_resp or {}).get("key_epoch") or 0),
                                connect_snapshot=connect_snapshot,
                            )
                    finally:
                        _kek[:] = b"\x00" * len(_kek)
                    if server_keypair is not None:
                        # Recovery succeeded — adopt the account identity, then sync
                        vault.rebind_server_identity(
                            recover_resp.get("user_id", ""), server_keypair
                        )
                        vault.db.set_meta("server_url", server_url)

                        from .vault.sync_client import SyncClient
                        user_id = vault.db.get_meta("user_id")
                        client = SyncClient(vault.db, server_url, vault.keypair, user_id)
                        client.set_dek_manager(vault.dek_mgr)

                        try:
                            client.authenticate()
                            result = client.pull()
                            _echo_pull_warnings(result)
                            click.echo(
                                f"Pull: {result['pulled']} objektov, "
                                f"commit_seq={result['max_commit_seq']}."
                            )
                        except RuntimeError as e:
                            click.echo(f"Sync zlyhal: {e}", err=True)

                        click.echo("Pripojeny k serveru.")
                        recovered = True
                except RuntimeError as exc:
                    refusal = recover_refusal(exc)
                    if refusal is not None:
                        # The account exists; an invitation would make a second one.
                        click.echo(refusal, err=True)
                        return
                    # Recovery failed — fall through to invitation flow
        except RuntimeError:
            pass  # User not found — fall through to invitation flow

        if not recovered:
            # No account on this server — need invitation
            click.echo("Na tomto serveri nemas ucet.")
            if sys.stdin.isatty():
                invitation_token = click.prompt("Zadaj invitation token (od admina)")
            else:
                invitation_token = sys.stdin.readline().rstrip("\n")

            if not invitation_token:
                click.echo("Invitation token je povinny.", err=True)
                return

            _server_register_and_upload(
                server_url, vault, password, is_bootstrap=False,
                invitation_token=invitation_token,
            )
            # _server_register_and_upload handles polling for approval

    # Save server URL to vault_meta (may already be set by helper functions)
    vault.db.set_meta("server_url", server_url)
    _org_recovery_after_connect(vault, password)


def _org_recovery_after_connect(vault: Vault, password: str) -> None:
    """Org recovery set up before connecting reaches the server now
    (capability review run 91), or the user learns it did not."""
    from .vault.sync_client import SyncClient

    message = SyncClient.org_recovery_after_connect(vault, password)
    if message:
        click.echo(message, err=message.startswith("Warning"))


@main.command()
@click.option("--path", type=click.Path(), help="Vault path (default: ~/.sezam)")
@click.option("--server", "-s", help="Server URL (e.g. https://sezam.example.com)")
def init(path: Optional[str], server: Optional[str]):
    """Create a new vault (first run wizard)."""
    vault_path = Path(path) if path else _get_vault_path()

    if (vault_path / "sezam.db").exists():
        click.echo(f"Vault already exists at {vault_path}")
        sys.exit(1)

    # If server is provided, ask for username first
    username = None
    if server:
        if sys.stdin.isatty():
            # N3: " alice" is the server account "alice".
            username = click.prompt(
                "Username", default="admin", value_proc=_username_value
            )
        else:
            username = "admin"

    click.echo("Welcome to Sezam. Create your master password.")
    click.echo("WARNING: Forgotten password = data loss. There is no recovery.")
    click.echo()

    password = _get_new_password()

    strength = estimate_strength(password)
    click.echo(f"Password strength: {strength['label']} ({strength['entropy_bits']} bits)")
    if strength["score"] < 2:
        click.echo("WARNING: Your password is weak. Consider using a stronger one.", err=True)

    click.echo()
    click.echo("Benchmarking Argon2id...")
    params = benchmark_argon2(target_seconds=1.0)
    click.echo(
        f"  Parameters: time={params.time_cost}, "
        f"memory={params.memory_cost // 1024}MB, "
        f"parallelism={params.parallelism}"
    )

    click.echo("Creating vault...")
    vault = Vault.create(vault_path, password, params)

    # Store username in vault_meta if provided
    if username:
        vault.db.set_meta("username", username)

    click.echo(f"Vault created at {vault_path}")
    click.echo("Fingerprint: " + vault.keypair.fingerprint)

    # Offer .sezam-key backup
    if sys.stdin.isatty():
        if click.confirm("Export a .sezam-key backup file? (recommended)", default=True):
            from .crypto.keys import export_sezam_key

            key_path = vault_path / "sezam-key.backup"
            export_sezam_key(
                vault.keypair,
                vault.current_kek,
                key_path,
                bytes.fromhex(vault.db.get_meta("argon2_salt")),
                params,
            )
            click.echo(f"Key backup saved to {key_path}")
            click.echo("Move this file to a secure location (USB drive, safe, etc.).")

    # Server registration (if --server provided)
    if server:
        click.echo()
        try:
            _server_connect_flow(server, vault, password)
        except Exception as e:
            click.echo(f"Server registration failed: {e}", err=True)
            click.echo("Vault created locally. You can register later.", err=True)

    vault.lock()


@main.command()
@click.argument("server_url")
@click.option(
    "--unlock-code", default=None,
    help="One-time code from an admin's 'sezam unlock-recovery' (account locked "
    "after wrong passwords).",
)
def connect(server_url: str, unlock_code: Optional[str]):
    """Connect an existing local vault to a server.

    Usage: sezam connect https://sezam.firma.sk

    Handles all scenarios:
    - Empty server: bootstraps as admin and pushes local data
    - Existing account: recovers session via Path B
    - No account: prompts for invitation token, waits for approval
    - Unreachable server: shows error
    """
    vault = _open_vault()
    # Server registration needs the password itself; never taken from a session.
    password = _unlock_vault_fresh(vault)

    try:
        _server_connect_flow(server_url, vault, password, unlock_code=unlock_code)
    except Exception as e:
        click.echo(f"Pripojenie zlyhalo: {e}", err=True)
    finally:
        vault.lock()


@main.group("server")
def server_group():
    """Server-side recovery from this vault."""


@server_group.command("reseed")
@click.argument("server_url", required=False)
def server_reseed(server_url: Optional[str]):
    """Rebuild an EMPTY server (wiped or new) from this vault.

    The server gets this vault's existing account (same id, keys and key
    epoch, proven by the identity key) and then every object the account
    owns. SERVER_URL defaults to the server the vault was connected to.
    An interrupted reseed continues when the command is run again.
    """
    from .vault.reseed import ReseedError, reseed_server

    vault = _open_vault()
    # Uploads the account key material: needs the password itself.
    password = _unlock_vault_fresh(vault)
    try:
        url = server_url or vault.db.get_meta("server_url")
        if not url:
            raise ReseedError("No server URL: pass SERVER_URL.")
        result = reseed_server(vault, url, password)
    except ReseedError as exc:
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:
        raise click.ClickException(
            f"Reseed interrupted ({exc}); run 'sezam server reseed' again to continue."
        ) from exc
    finally:
        vault.lock()
    if result["conflicts"]:
        raise click.ClickException(
            f"Pushed {result['pushed']} objects, {len(result['conflicts'])} rejected; "
            "run 'sezam server reseed' again to retry them."
        )
    click.echo(f"Server reseeded: {result['pushed']} objects pushed.")


@server_group.command("rejoin")
@click.argument("server_url", required=False)
@click.option(
    "--username", default=None,
    help="Come back under this name (another account took the old one after the backup).",
)
def server_rejoin(server_url: Optional[str], username: Optional[str]):
    """Bring this member account back on a server restored from a backup
    older than the account.

    The team log names the account's id and keys; the server takes them back
    only with a proof by those keys, then gets the key material and every
    object the account owns. An interrupted rejoin continues when run again.
    """
    from .vault.reseed import ReseedError, rejoin_server

    vault = _open_vault()
    password = _unlock_vault_fresh(vault)  # the key material upload needs it
    try:
        url = server_url or vault.db.get_meta("server_url")
        if not url:
            raise ReseedError("No server URL: pass SERVER_URL.")
        result = rejoin_server(vault, url, password, username)
    except ReseedError as exc:
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:
        raise click.ClickException(
            f"Rejoin interrupted ({exc}); run 'sezam server rejoin' again to continue."
        ) from exc
    finally:
        vault.lock()
    if result["conflicts"]:
        raise click.ClickException(
            f"Pushed {result['pushed']} objects, {len(result['conflicts'])} rejected; "
            "run 'sezam server rejoin' again to retry them."
        )
    click.echo(f"Account back on the server: {result['pushed']} objects pushed.")


def generate_keypair_info(vault_path: Path, password: str) -> str:
    """Helper to show keypair fingerprint."""
    vault = Vault(vault_path)
    vault.unlock(password)
    fp = vault.keypair.fingerprint
    vault.lock()
    return fp


@main.command()
@click.option(
    "--ttl",
    type=click.IntRange(1, MAX_SESSION_TTL_MINUTES),
    default=DEFAULT_SESSION_TTL_MINUTES,
    show_default=True,
    help="Session lifetime in minutes.",
)
def unlock(ttl: int):
    """Unlock the vault (start a time-limited session).

    The master password is never stored; only the derived key is cached in
    the OS keyring until the session expires or 'sezam lock' is run.
    """
    vault = _open_vault()
    _check_rate_limit()
    password = _get_password()

    try:
        vault.unlock(password)
    except ValueError:
        _record_failed_attempt()
        click.echo("Wrong master password.", err=True)
        time.sleep(2)
        sys.exit(1)

    _clear_failed_attempts()
    try:
        _save_session(vault.current_kek, ttl)
    finally:
        vault.lock()
    click.echo(f"Vault unlocked. Session expires in {ttl} min.")


@main.command()
def lock():
    """Lock the vault (end session) and every running mcp-serve."""
    from .mcp import control

    # Session first, so no MCP server can unlock again from it.
    _clear_session()
    replies = control.send_all("lock")
    locked = sum(1 for _, reply in replies if reply and reply.get("status") == "ok")
    click.echo("Vault locked.")
    if locked:
        click.echo(f"Locked {locked} running MCP server(s).")
    if locked < len(replies):
        click.echo(
            f"{len(replies) - locked} MCP server(s) did not answer; they lock within seconds "
            "because the session is gone.",
            err=True,
        )


@main.command()
@click.argument("query")
def search(query: str):
    """Search entries by name, field keys, tags."""
    vault = _open_vault()
    _unlock_vault(vault)

    results = vault.search(query)
    if not results:
        click.echo("No results found.")
    else:
        for r in results:
            click.echo(f"  {r['path']}/{r['name']}")

    vault.lock()


@main.command("get")
@click.argument("path")
@click.option("--field", "-f", help="Specific field to get")
@click.option("--clip", is_flag=True, help="Copy to clipboard (auto-clear 15s)")
def get_entry(path: str, field: Optional[str], clip: bool):
    """Get an entry or specific field value."""
    vault = _open_vault()
    _unlock_vault(vault)

    entry = vault.find_entry_by_path(path)
    if entry is None:
        click.echo(f"Entry not found: {path}", err=True)
        vault.lock()
        sys.exit(1)

    if field:
        value = None
        for f in entry["fields"]:
            if f["key"].lower() == field.lower():
                value = f["value"]
                break
        if value is None:
            click.echo(f"Field not found: {field}", err=True)
            vault.lock()
            sys.exit(1)

        if clip:
            _copy_to_clipboard(value)
            click.echo(f"Copied {field} to clipboard (auto-clear 15s).")
        else:
            click.echo(value)
    else:
        # Show all fields
        click.echo(f"Entry: {entry['name']}")
        if entry["tags"]:
            click.echo(f"Tags: {', '.join(entry['tags'])}")
        click.echo("Fields:")
        for f in entry["fields"]:
            val = "****" if f["sensitive"] else f["value"]
            click.echo(f"  {f['key']}: {val}")

    vault.lock()


@main.command("set")
@click.argument("path")
@click.option("--field", "-f", help="Field key to set")
@click.option("--value", "-v", help="Field value (prompted if not given)")
@click.option("--sensitive", "-s", is_flag=True, help="Mark field as sensitive")
def set_entry(path: str, field: Optional[str], value: Optional[str], sensitive: bool):
    """Create or update an entry."""
    vault = _open_vault()
    _unlock_vault(vault)

    parts = [p for p in path.strip("/").split("/") if p]
    if not parts:
        click.echo("Invalid path.", err=True)
        vault.lock()
        sys.exit(1)

    entry_name = parts[-1]
    folder_parts = parts[:-1]

    # Resolve or create folder path
    current_node = vault.db.get_meta("root_node_id")
    for folder_name in folder_parts:
        children = vault.list_nodes(current_node)
        found = None
        for child in children:
            if child["name"].lower() == folder_name.lower():
                found = child["id"]
                break
        if found is None:
            found = vault.create_node(folder_name, current_node)
        current_node = found

    # Check if entry exists
    existing = vault.find_entry_by_path(path)

    if existing and field:
        # Update specific field
        if value is None:
            if sensitive:
                value = _get_password(f"Value for {field}: ")
            else:
                value = click.prompt(f"Value for {field}")

        fields = existing["fields"]
        updated = False
        for f in fields:
            if f["key"].lower() == field.lower():
                f["value"] = value
                f["sensitive"] = sensitive or f.get("sensitive", False)
                updated = True
                break
        if not updated:
            fields.append({"key": field, "value": value, "sensitive": sensitive, "sort_order": len(fields)})

        vault.update_entry(existing["id"], fields=fields)
        click.echo(f"Updated {field} in {path}")
    elif existing:
        click.echo(f"Entry exists: {path}. Use --field to update a field.", err=True)
    else:
        # Create new entry
        fields = []
        if field and value is not None:
            fields.append({"key": field, "value": value, "sensitive": sensitive, "sort_order": 0})
        elif field:
            if sensitive:
                value = _get_password(f"Value for {field}: ")
            else:
                value = click.prompt(f"Value for {field}")
            fields.append({"key": field, "value": value, "sensitive": sensitive, "sort_order": 0})
        else:
            # Interactive field entry
            click.echo(f"Creating entry: {entry_name}")
            i = 0
            while True:
                key = click.prompt("Field key (empty to finish)", default="", show_default=False)
                if not key:
                    break
                is_sens = click.confirm("Sensitive?", default=False)
                if is_sens:
                    val = _get_password(f"Value for {key}: ")
                else:
                    val = click.prompt(f"Value for {key}")
                fields.append({"key": key, "value": val, "sensitive": is_sens, "sort_order": i})
                i += 1

        if not fields:
            click.echo("No fields provided.", err=True)
            vault.lock()
            sys.exit(1)

        vault.create_entry(current_node, entry_name, fields)
        click.echo(f"Created entry: {path}")

    vault.lock()


@main.command("list")
@click.argument("path", default="")
def list_tree(path: str):
    """List vault tree or contents of a folder."""
    vault = _open_vault()
    _unlock_vault(vault)

    if path:
        node_id, _ = vault.resolve_path(path)
        if node_id is None:
            click.echo(f"Path not found: {path}", err=True)
            vault.lock()
            sys.exit(1)
    else:
        node_id = None

    lines = vault.get_tree(node_id)
    if lines:
        for line in lines:
            click.echo(line)
    else:
        click.echo("(empty)")
    if node_id is None:
        from .vault.pending_states import closed_shared_before_team_log

        # Review 4acfdde R11 (low): their names are sealed under keys that open
        # only through the team log, so the list said just "(empty)".
        closed = closed_shared_before_team_log(vault)
        if closed:
            click.echo(
                f"\n{len(closed)} folder(s) shared with you before the organisation had a team "
                "log are not listed: they open only through the log. An admin runs "
                "'sezam team-log init'; then 'sezam team-log confirm-founder FINGERPRINT' "
                "and 'sezam pull' ('sezam status' says the same)."
            )

    vault.lock()


@main.command("create-personal")
@click.argument("name")
def create_personal(name: str):
    """Create a personal folder (only you can decrypt)."""
    vault = _open_vault()
    _unlock_vault(vault)

    node_id = vault.create_personal_folder(name)
    click.echo(f"Personal folder created: {name} (id={node_id})")

    vault.lock()


@main.command()
@click.option("--length", "-l", default=20, help="Password length")
@click.option("--symbols", "-s", is_flag=True, default=True, help="Include symbols")
@click.option("--no-symbols", is_flag=True, help="Exclude symbols")
@click.option("--passphrase", "-p", is_flag=True, help="Generate passphrase instead")
@click.option("--words", "-w", default=8, help="Number of words for passphrase (~8 bits each)")
@click.option("--clip", is_flag=True, help="Copy to clipboard")
def generate(length: int, symbols: bool, no_symbols: bool, passphrase: bool, words: int, clip: bool):
    """Generate a random password or passphrase."""
    if passphrase:
        pwd = generate_passphrase(word_count=words)
    else:
        pwd = generate_password(length=length, symbols=not no_symbols)

    if clip:
        _copy_to_clipboard(pwd)
        click.echo("Password copied to clipboard (auto-clear 15s).")
    else:
        click.echo(pwd)

    strength = estimate_strength(pwd)
    click.echo(f"Strength: {strength['label']} ({strength['entropy_bits']} bits)", err=True)


@main.command("change-password")
def change_password():
    """Change master password (re-derives KEK, re-wraps all DEKs)."""
    vault = _open_vault()
    _check_rate_limit()
    old_password = _get_password("Current master password: ")

    try:
        vault.unlock(old_password)
    except ValueError:
        _record_failed_attempt()
        click.echo("Wrong master password.", err=True)
        time.sleep(2)
        sys.exit(1)

    _clear_failed_attempts()

    new_password = _get_new_password(vault)

    strength = estimate_strength(new_password)
    click.echo(f"New password strength: {strength['label']} ({strength['entropy_bits']} bits)")

    client = None
    server_url = vault.db.get_meta("server_url")
    if server_url:
        from .vault.sync_client import SyncClient

        client = SyncClient(
            vault.db, server_url, vault.keypair, vault.db.get_meta("user_id")
        )
        # A pending identity rotation logs in with the old key from the journal.
        client.set_dek_manager(vault.dek_mgr)
        try:
            client.prepare_key_change()
        except RuntimeError as exc:
            vault.lock()
            raise click.ClickException(
                f"Server sync failed; password was not changed: {exc}"
            ) from exc

    auth_proof = None
    server_error = None
    from .vault.snapshots import SnapshotError

    try:
        try:
            auth_proof = vault.change_password(old_password, new_password)
        except (SnapshotError, ValueError) as exc:
            raise click.ClickException(f"{exc}; password was not changed") from exc
        if client is not None:
            # One push carries the DEK rewrap, the epoch and the new key
            # material; the server applies them together or not at all.
            client.set_dek_manager(vault.dek_mgr)
            try:
                client.push()
            except RuntimeError as exc:
                server_error = exc
    finally:
        if auth_proof is not None:
            auth_proof[:] = b"\x00" * len(auth_proof)
        _clear_session()
        vault.lock()
    click.echo("Master password changed. Please unlock again.")
    if server_error is not None:
        click.echo(
            f"Warning: the server was not updated yet ({server_error}). "
            "The change is kept locally and is sent by the next 'sezam push'; "
            "until then other devices still use the old password.",
            err=True,
        )
    elif client is not None and client.server_org_recovery_stale():
        click.echo(
            "Warning: the organization recovery shares no longer work in the web vault "
            "after this password change. "
            "Set org recovery up again ('sezam org-recovery-setup --replace' or in the "
            "web vault) and hand out the new shares.",
            err=True,
        )


@main.command("rotate-identity")
def rotate_identity():
    """Replace your signing/encryption keys (e.g. after they leaked).

    The new keys, the rotation certificate, the DEK rewrap and the new key
    material reach the server in one push. Other members see a key-change
    warning and should confirm the new fingerprint with you.
    """
    vault = _open_vault()
    server_url = vault.db.get_meta("server_url")
    if not server_url:
        raise click.ClickException("Identity keys are used only with a server; none is set")
    _check_rate_limit()
    password = _get_password("Master password: ")
    try:
        vault.unlock(password)
    except ValueError:
        _record_failed_attempt()
        click.echo("Wrong master password.", err=True)
        time.sleep(2)
        sys.exit(1)
    _clear_failed_attempts()

    from .vault.snapshots import SnapshotError
    from .vault.sync_client import SyncClient

    def _client() -> SyncClient:
        client = SyncClient(vault.db, server_url, vault.keypair, vault.db.get_meta("user_id"))
        client.set_dek_manager(vault.dek_mgr)
        return client

    try:
        _client().prepare_key_change()
    except RuntimeError as exc:
        vault.lock()
        raise click.ClickException(
            f"Server sync failed; keys were not rotated: {exc}"
        ) from exc

    auth_proof = None
    server_error = None
    try:
        try:
            auth_proof = vault.change_password(password, password, rotate_identity=True)
        except (SnapshotError, ValueError, RuntimeError) as exc:
            raise click.ClickException(f"{exc}; keys were not rotated") from exc
        fingerprint = vault.keypair.fingerprint
        try:
            _client().push()
        except RuntimeError as exc:
            server_error = exc
    finally:
        if auth_proof is not None:
            auth_proof[:] = b"\x00" * len(auth_proof)
        _clear_session()
        vault.lock()
    click.echo(f"Identity keys rotated. New fingerprint: {fingerprint}")
    if server_error is not None:
        click.echo(
            f"Warning: the server was not updated yet ({server_error}). "
            "The rotation is kept locally and is sent by the next 'sezam push'.",
            err=True,
        )
    else:
        click.echo(
            "Members you shared folders with must confirm the new fingerprint; "
            "folders shared with you must be shared again by their owner."
        )


# ── Key export/import (.sezam-key) ──


@main.command("export-key")
@click.argument("dest", type=click.Path(), default=".sezam-key")
def export_key(dest: str):
    """Export encrypted keypair to a .sezam-key backup file.

    The file is encrypted with your current KEK, so it can only be
    imported with the same master password. Store it safely — it
    provides an alternative recovery path for your vault keys.
    """
    vault = _open_vault()
    _unlock_vault_fresh(vault)

    from .crypto.kdf import Argon2Params
    from .crypto.keys import export_sezam_key

    dest_path = Path(dest).resolve()
    export_sezam_key(
        vault.keypair,
        vault.current_kek,
        dest_path,
        bytes.fromhex(vault.db.get_meta("argon2_salt")),
        Argon2Params.from_dict(vault.db.get_meta_json("argon2_params")),
    )
    vault.lock()
    click.echo(f"Key exported to {dest_path}")
    click.echo("Keep this file safe. It is encrypted with your master password.")


@main.command("import-key")
@click.argument("source", type=click.Path(exists=True))
@click.option("--path", type=click.Path(), help="Vault path (default: ~/.sezam)")
def import_key(source: str, path: Optional[str]):
    """Import keypair from a .sezam-key backup file.

    Creates a new vault using the imported keypair. You will be prompted
    for the master password that was used when the key was exported.
    """
    vault_path = Path(path) if path else _get_vault_path()

    if (vault_path / "sezam.db").exists():
        click.echo(f"Vault already exists at {vault_path}. Cannot import into existing vault.", err=True)
        sys.exit(1)

    click.echo("Import .sezam-key backup file.")
    click.echo("Enter the master password that was used when the key was exported.")
    password = _get_password("Master password: ")

    if not password:
        click.echo("Password cannot be empty.", err=True)
        sys.exit(1)

    from .crypto.kdf import Argon2Params, derive_kek, generate_salt
    from .crypto.keys import import_sezam_key

    params = Argon2Params()

    click.echo("Now set a password for the new vault (can be the same or different).")
    new_password = _get_new_password()

    try:
        keypair = import_sezam_key(source, password)
    except Exception as exc:
        click.echo(f"Failed to decrypt .sezam-key file: {exc}", err=True)
        sys.exit(1)

    # Create vault with the imported keypair
    vault_path.mkdir(parents=True, exist_ok=True)
    vault = Vault(vault_path)
    vault._db.open()
    vault._db.create_schema()

    # Set up with new password
    new_salt = generate_salt()
    new_kek = derive_kek(new_password, new_salt, params)

    vault._db.set_meta_json("argon2_params", params.to_dict())
    vault._db.set_meta("argon2_salt", new_salt.hex())

    from .crypto.aead import encrypt_keypair_wrap
    from .models import new_ulid, ulid_to_bytes

    user_id = new_ulid()
    kek_dek_id = new_ulid()
    vault._db.set_meta("kek_dek_id", kek_dek_id)

    encrypted_kp = encrypt_keypair_wrap(
        keypair_data=keypair.serialize_private(),
        kek=new_kek,
        kek_dek_id=ulid_to_bytes(kek_dek_id),
        user_object_id=ulid_to_bytes(user_id),
    )

    vault._db.set_meta("encrypted_keypair", encrypted_kp.hex())
    vault._db.set_meta("user_id", user_id)
    vault._db.set_meta("signing_pk", keypair.signing_pk.hex())
    vault._db.set_meta("encryption_pk", keypair.encryption_pk.hex())
    vault._db.set_meta("key_epoch", "0")

    from .vault.dek import DEKManager

    vault._dek_mgr = DEKManager(vault._db, new_kek)
    vault._keypair = keypair
    vault._user_id = user_id
    vault._unlocked = True

    # Create root DEK and audit DEK
    root_dek_id, root_dek = vault._dek_mgr.create_dek("root")
    vault._dek_mgr.create_dek("audit")

    # Create root node
    from .crypto.aead import BlobKind, encrypt
    from .models import NodeMeta

    root_node_id = new_ulid()
    root_meta = NodeMeta(name="Root")
    encrypted_meta = encrypt(
        plaintext=root_meta.to_json(),
        dek=root_dek,
        dek_id=ulid_to_bytes(root_dek_id),
        object_id=ulid_to_bytes(root_node_id),
        version=1,
        blob_kind=BlobKind.NODE_META,
    )

    from .vault import outbox

    outbox.queue_write(vault._db, root_node_id)
    vault._db.execute(
        "INSERT INTO nodes (id, parent_id, encrypted_meta, dek_id, version, is_deleted) "
        "VALUES (?, NULL, ?, ?, 1, 0)",
        (root_node_id, encrypted_meta, root_dek_id),
    )
    vault._db.set_meta("root_node_id", root_node_id)
    from .vault.sync_writers import WRITES_AUDITED_META

    vault._db.set_meta(WRITES_AUDITED_META, "1")
    from .vault.ai_access import seal_new_vault

    seal_new_vault(vault._db, new_kek)
    vault._db.conn.commit()

    vault.lock()

    click.echo(f"Vault created at {vault_path} with imported keypair.")
    click.echo(f"Fingerprint: {keypair.fingerprint}")


# ── Org recovery (Shamir) ──


@main.command("org-recovery-setup")
@click.option("--threshold", "-t", default=3, help="Minimum shares to reconstruct (default 3)")
@click.option("--shares", "-n", default=5, help="Total shares to generate (default 5)")
@click.option(
    "--replace", is_flag=True,
    help="Replace an existing setup without asking (its shares stop working).",
)
@click.option(
    "--replace-other-admin", is_flag=True,
    help="Replace the org recovery another admin set up on the server (their shares stop working).",
)
def org_recovery_setup(threshold: int, shares: int, replace: bool, replace_other_admin: bool):
    """Set up organizational recovery using Shamir's Secret Sharing.

    Generates a recovery key, wraps the vault KEK with it, and splits
    the recovery key into N shares. Distribute these shares to trusted
    key holders. When K shares come together, they can reset the master
    password.

    IMPORTANT: Write down each share and distribute to separate key holders.
    These shares are shown ONCE and cannot be recovered.
    """
    vault = _open_vault()
    password = _unlock_vault_fresh(vault)
    replace = replace or replace_other_admin

    # Lockout review N4: a new setup voids every share handed out before.
    if vault.org_recovery_configured() and not replace:
        click.echo(
            "WARNING: Org recovery is already set up. A new setup makes EVERY "
            "existing share invalid; key holders must get the new shares.",
            err=True,
        )
        if not sys.stdin.isatty() or not click.confirm(
            "Replace the existing org recovery?", default=False
        ):
            click.echo("Org recovery left unchanged (use --replace to replace it).", err=True)
            vault.lock()
            sys.exit(1)
        replace = True

    from .vault.org_recovery_server import (
        OrgRecoveryNotReplaced,
        OrgRecoveryOnServer,
        setup_and_register,
    )

    click.echo(f"Setting up organizational recovery ({threshold}-of-{shares})...")
    try:
        # Review 526419e V5: registered before the shares are shown; a
        # replacement the server refuses keeps the old setup and its shares.
        try:
            setup = setup_and_register(
                vault, password, threshold, shares,
                replace=replace, replace_other_admin=replace_other_admin,
            )
        except OrgRecoveryOnServer as exc:
            # Review 526419e S2/S3: the recovery on the server (web, another
            # device, another admin) is not replaced without saying so.
            click.echo(f"WARNING: {exc}", err=True)
            prompt = (
                "Replace the other admin's org recovery?" if exc.other_admin
                else "Replace the org recovery on the server?"
            )
            if not sys.stdin.isatty() or not click.confirm(prompt, default=False):
                click.echo("Org recovery left unchanged.", err=True)
                vault.lock()
                sys.exit(1)
            setup = setup_and_register(
                vault, password, threshold, shares,
                replace=True, replace_other_admin=bool(exc.other_admin),
            )
    except OrgRecoveryNotReplaced as exc:
        click.echo(
            f"Org recovery NOT replaced: the server did not take the new recovery key "
            f"({exc}). The existing setup and its shares stay valid.",
            err=True,
        )
        vault.lock()
        sys.exit(1)
    shamir_shares = setup.shares

    click.echo()
    click.echo(f"Recovery shares generated ({threshold}-of-{shares} required):")
    click.echo("=" * 60)
    click.echo("WRITE DOWN EACH SHARE AND DISTRIBUTE TO KEY HOLDERS.")
    click.echo("These shares are shown ONCE and cannot be recovered!")
    click.echo("=" * 60)
    click.echo()

    for idx, share_bytes in shamir_shares:
        # Encode as hex for easy transcription
        share_hex = share_bytes.hex()
        click.echo(f"  Share {idx}: {share_hex}")

    click.echo()
    click.echo(f"Distribute these {shares} shares to {shares} different key holders.")
    click.echo(f"Any {threshold} of them can reconstruct the recovery key.")

    # Review e4cd15a #1: the server learns the recovery key, so after
    # 'sezam org-recovery' it takes the new password on the recovery's proof;
    # without it a lone admin (nobody to grant a key reset) was locked out.
    if setup.registered:
        click.echo("The server knows this recovery: after 'sezam org-recovery' it "
                   "accepts the new password without the old one.")
    elif setup.registered is None:
        click.echo("This vault is not connected yet: 'sezam connect URL' registers "
                   "this recovery on the server.")
    else:
        click.echo(
            f"Warning: the server did not take this org recovery yet ({setup.error}). "
            "'sezam push' offers the registration again; until the server has it, a "
            "reset with these shares needs "
            f"{_setup_reset_way_out(vault)}.",
            err=True,
        )
    vault.lock()


def _setup_reset_way_out(vault: Vault) -> str:
    """Review 8595ec1 #4: a team log's admin has no other admin; the log names the key."""
    from . import teamlog
    from .vault.team_log_local import local_team_state

    state = local_team_state(vault.db)
    if state is not None and teamlog.is_admin(state, vault.db.get_meta("user_id")):
        return "the team log to name it (the next 'sezam push' sends that)"
    return "another admin's 'sezam allow-key-reset'"


_ORG_RECOVERY_REWRAP_WARNING = (
    "Warning: the server still holds the org recovery blob of the old password, so "
    "the shares do not work there (web) yet. The next 'sezam push' sends the new one; "
    "'sezam status' shows it while it waits."
)


@main.command("org-recovery")
@click.option("--share", "-s", "share_inputs", multiple=True, hidden=True)
def org_recovery(share_inputs: tuple):
    """Recover vault access using Shamir shares and set a new password.

    Paste each share ('index:hex_value') at the prompt, which does not echo
    it; an empty line finishes. Shares are never taken as arguments: there
    they would stay in the shell history and show in the process list.
    """
    from .vault.snapshots import SnapshotError

    if share_inputs:
        # Review d615826: the emergency kit used to say 'org-recovery -s ...'.
        click.echo(
            "Shares are not taken on the command line (they would stay in the shell "
            "history and show in the process list). Run 'sezam org-recovery' and paste "
            "each share at the prompt. Remove the command you just ran from the shell "
            "history.",
            err=True,
        )
        sys.exit(2)

    vault_path = _get_vault_path()
    if not (vault_path / "sezam.db").exists():
        click.echo("Vault not found. Run 'sezam init' first.", err=True)
        sys.exit(1)

    parsed_shares: list[tuple[int, bytes]] = []
    click.echo("Paste the Shamir shares (index:hex_value, not shown), empty line to finish:")
    while True:
        line = click.prompt(
            f"Share {len(parsed_shares) + 1}", default="", show_default=False, hide_input=True
        )
        if not line.strip():
            break
        try:
            idx_str, hex_val = line.split(":", 1)
            idx = int(idx_str.strip())
            share_bytes = bytes.fromhex(hex_val.strip())
            parsed_shares.append((idx, share_bytes))
        except (ValueError, TypeError):
            click.echo("Invalid format. Use 'index:hex_value'.", err=True)

    if len(parsed_shares) < 2:
        click.echo("At least 2 shares are required.", err=True)
        sys.exit(1)

    # Get new password
    new_password = _get_new_password()

    vault = Vault(vault_path)

    try:
        vault.org_recovery(parsed_shares, new_password)
    except (ValueError, SnapshotError) as e:
        click.echo(f"Recovery failed: {e}", err=True)
        sys.exit(1)

    click.echo("Recovery successful. Master password has been reset.")
    # The server must learn the new key material and key epoch, otherwise the
    # account password on the server (and every other device) stays the old one.
    server_url = vault.db.get_meta("server_url")
    if server_url and vault.db.get_meta("user_id"):
        from .vault.sync_client import SyncClient

        client = SyncClient(vault.db, server_url, vault.keypair, vault.db.get_meta("user_id"))
        client.set_dek_manager(vault.dek_mgr)
        try:
            result = client.push()
            click.echo("The new password was sent to the server.")
            if result.get("org_recovery_rewrap_pending"):
                click.echo(_ORG_RECOVERY_REWRAP_WARNING, err=True)
        except RuntimeError as e:
            hint = "The next 'sezam push' sends the new password."
            from .vault.sync_common import KEY_CHANGE_NEEDS_PROOF, server_error

            if server_error(e, 403, KEY_CHANGE_NEEDS_PROOF):
                # Without the old password the server needs an admin's grant
                # (review 8595ec1: a team log's lone admin has none).
                from .vault.pending_states import key_reset_way_out

                hint = (
                    "The server needs the old password, the registered recovery key or an "
                    f"admin's approval: {key_reset_way_out(vault.db, vault.db.get_meta('user_id'))}."
                )
            click.echo(f"Server sync failed: {e}\n{hint}", err=True)
    vault.lock()
    click.echo("You can now unlock the vault with your new password.")


# ── Grant a member access to a folder ──


@main.command("fingerprint")
def fingerprint_cmd():
    """Show this account's key fingerprint (an admin compares it before sharing)."""
    vault = _open_vault()
    _unlock_vault_fresh(vault)
    try:
        click.echo(vault.keypair.fingerprint)
    finally:
        vault.lock()


def _same_fingerprint(given: str, actual: str) -> bool:
    return "".join(c for c in given.lower() if c in "0123456789abcdef") == actual.lower()


@main.command("grant-access")
@click.argument("user_id")
@click.argument("folder")
@click.option("--write", "write_access", is_flag=True, help="Allow the member to edit the folder")
@click.option(
    "--fingerprint", "expected_fingerprint", default=None,
    help="The member's key fingerprint as their device shows it ('sezam fingerprint'); "
    "without it you are asked to confirm the first time",
)
def grant_access(
    user_id: str, folder: str, write_access: bool, expected_fingerprint: Optional[str]
):
    """Share FOLDER (a top-level folder name or a folder ID) with an approved member."""
    vault = _open_vault()
    _unlock_vault_fresh(vault)
    server = vault.db.get_meta("server_url")
    if not server or not vault.db.get_meta("user_id"):
        vault.lock()
        raise click.ClickException("This vault is not connected to a server")
    matches = [n["id"] for n in vault.list_nodes() if folder in (n["name"], n["id"])]
    if not matches and vault.db.fetchone(
        "SELECT 1 FROM nodes WHERE id = ? AND is_deleted = 0", (folder,)
    ):
        matches = [folder]
    if len(matches) != 1:
        vault.lock()
        raise click.ClickException(
            f"Folder '{folder}' not found" if not matches
            else f"Several folders are named '{folder}'; use the folder ID"
        )

    from .vault.revocation import grant_member
    from .vault.sync_client import SyncClient

    client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
    client.set_dek_manager(vault.dek_mgr)
    level = "write" if write_access else "read"

    def confirm(actual: str) -> bool:
        # First share with this member: the key is only what the server says.
        if expected_fingerprint is not None:
            return _same_fingerprint(expected_fingerprint, actual)
        click.echo(f"Key fingerprint of member {user_id}:\n  {actual}")
        return click.confirm(
            "Does it match the fingerprint the member's device shows?", default=False
        )

    try:
        grant_member(vault, client, user_id, matches[0], level, confirm_fingerprint=confirm)
    except Exception as exc:
        raise click.ClickException(f"Granting access failed: {exc}") from exc
    finally:
        vault.lock()
    click.echo(f"User {user_id} now has {level} access to '{folder}'.")


# ── Revoke user with auto re-key ──


@main.command("revoke-user")
@click.argument("user_id")
@click.option("--server", "-s", envvar="SEZAM_SERVER", help="Server URL")
def revoke_user(user_id: str, server: Optional[str]):
    """Revoke a user's access and re-key all affected folders.

    Removes the user's access envelopes and generates new DEKs for
    all folders they had access to, re-encrypting entries with new keys.
    This ensures the revoked user cannot decrypt any data even if they
    retained copies of old ciphertexts.
    """
    vault = _open_vault()
    _unlock_vault_fresh(vault)

    if not server:
        server = vault.db.get_meta("server_url")
    if not server:
        server = os.environ.get("SEZAM_SERVER", "")

    client = None
    if server:
        from .vault.sync_client import SyncClient
        client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
        # A refused re-key is rebased on the pulled objects (needs the DEKs).
        client.set_dek_manager(vault.dek_mgr)
        try:
            client.authenticate()
        except RuntimeError as exc:
            vault.lock()
            raise click.ClickException(f"Server authentication failed: {exc}") from exc

    from .vault.revocation import RekeyPending, revoke_member

    try:
        rekey_count = revoke_member(vault, client, user_id)
    except RekeyPending as exc:
        vault.lock()
        raise click.ClickException(f"{exc} Run 'sezam push' to retry.") from exc
    except Exception as exc:
        vault.lock()
        raise click.ClickException(f"Revocation failed: {exc}") from exc
    if client:
        click.echo(f"Server notified: user {user_id} revoked.")

    vault.lock()

    if rekey_count > 0:
        click.echo(f"Re-keyed {rekey_count} folder(s) after revoking user {user_id}.")
    else:
        click.echo(f"User {user_id} had no access envelopes. No re-keying needed.")


@main.command("allow-key-reset")
@click.argument("user_id")
def allow_key_reset(user_id: str):
    """Admin: let a user without the old password (org recovery) send the
    new password to the server once, within an hour."""
    vault = _open_vault()
    _unlock_vault_fresh(vault)
    server = vault.db.get_meta("server_url")
    if not server:
        vault.lock()
        raise click.ClickException("No server is set")
    from .vault.sync_client import SyncClient

    client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
    try:
        client.allow_key_reset(user_id)
    except RuntimeError as exc:
        raise click.ClickException(f"Key reset was not allowed: {exc}") from exc
    finally:
        vault.lock()
    click.echo(
        f"User {user_id} may send a new password within an hour ('sezam push' on their device)."
    )


@main.command("unlock-recovery")
@click.argument("user_id")
def unlock_recovery(user_id: str):
    """Admin: clear a user's password lockout and print a one-time unlock code.

    The code (valid 24 h, until used) lets the user's correct password through
    from any network even when strangers lock the name again; give it to the
    user over a trusted channel for 'sezam connect URL --unlock-code CODE'.
    A lone admin can issue one for themselves from a device still signed in.
    """
    vault = _open_vault()
    _unlock_vault_fresh(vault)
    server = vault.db.get_meta("server_url")
    if not server:
        vault.lock()
        raise click.ClickException("No server is set")
    from .vault.sync_client import SyncClient

    client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
    try:
        resp = client.unlock_recovery(user_id)
    except RuntimeError as exc:
        raise click.ClickException(f"The account was not unlocked: {exc}") from exc
    finally:
        vault.lock()
    click.echo(f"User {user_id} unlocked. One-time unlock code: {resp['unlock_code']}")
    click.echo("Valid 24 hours: sezam connect <server-url> --unlock-code <code>")


# ── Export command (with --format) ──


@main.command()
@click.argument("dest", type=click.Path())
@click.option(
    "--format", "fmt",
    type=click.Choice(["backup", "csv", "bitwarden"]),
    default="backup",
    help="Export format: backup (encrypted db copy), csv (plaintext), bitwarden (JSON)",
)
@click.option(
    "--confirm-plaintext",
    is_flag=True,
    help="Explicitly approve writing plaintext secrets (required without a TTY).",
)
def export(dest: str, fmt: str, confirm_plaintext: bool):
    """Export vault data in various formats."""
    if fmt in {"csv", "bitwarden"}:
        click.echo(f"WARNING: This will export ALL entries as PLAINTEXT {fmt.upper()}.", err=True)
        click.echo("Anyone with access to this file can read your passwords.", err=True)
        if not confirm_plaintext:
            if not sys.stdin.isatty():
                raise click.ClickException(
                    "Plaintext export requires the explicit --confirm-plaintext flag without a TTY."
                )
            if not click.confirm("Continue?"):
                click.echo("Export cancelled.")
                return

    if fmt == "backup":
        # Existing behavior: copy sezam.db (no unlock needed)
        vault = _open_vault()
        vault._db.open()
        vault.db.backup(dest)
        vault._db.close()
        click.echo(f"Encrypted backup saved to {dest}")

    elif fmt == "csv":
        vault = _open_vault()
        _unlock_vault_fresh(vault)
        skipped = _export_csv(vault, dest)
        vault.lock()
        _report_export(f"Plaintext CSV exported to {dest}", dest, skipped)

    elif fmt == "bitwarden":
        vault = _open_vault()
        _unlock_vault_fresh(vault)
        skipped = _export_bitwarden(vault, dest)
        vault.lock()
        _report_export(f"Bitwarden JSON exported to {dest}", dest, skipped)


def export_incomplete_message(dest: str, skipped: dict) -> Optional[str]:
    """Review 526419e N2: what an export left out, or None if nothing."""
    if not skipped["folders"] and not skipped["entries"]:
        return None
    return (
        f"{dest} is INCOMPLETE: {skipped['folders']} folder(s) (with everything in them) "
        f"and {skipped['entries']} entr(y/ies) could not be decrypted on this device "
        "and are not in it. Do not rely on it as a full export; 'sezam pull' may "
        "bring the missing keys, then export again."
    )


def _report_export(done: str, dest: str, skipped: dict) -> None:
    """An export that left data out must not report success (review 526419e N2)."""
    incomplete = export_incomplete_message(dest, skipped)
    if incomplete:
        raise click.ClickException(incomplete)
    click.echo(done)


# ── Vault snapshots (TODO_AI_BROKER section 10) ──


@main.group("snapshot")
def snapshot_group():
    """Automatic encrypted vault snapshots, taken before risky operations."""


@snapshot_group.command("list")
def snapshot_list():
    """List snapshots, oldest first."""
    from .vault.snapshots import list_snapshots, snapshot_dir, snapshots_of_other_passwords, vault_salt

    vault_path = _get_vault_path()
    snaps = list_snapshots(vault_path)
    if not snaps:
        click.echo(f"No snapshots in {snapshot_dir(vault_path)}.")
        return
    salt = vault_salt(vault_path)
    other = {s.name for s in snapshots_of_other_passwords(vault_path, salt)} if salt else set()
    click.echo(f"{'NAME':<48} {'CREATED':<24} {'REASON':<16} SIZE")
    for s in snaps:
        mark = "  (earlier password)" if s.name in other else ""
        click.echo(f"{s.name:<48} {s.created:<24} {s.reason:<16} {s.size}{mark}")
    click.echo(
        "A snapshot opens with the master password that was valid when it was taken."
    )
    if other:
        click.echo(_OLD_PASSWORD_SNAPSHOTS.format(count=len(other)))


# Review 4acfdde R11 (low): a password changed before the release that drops
# such snapshots (d615826) left them, and only the next change dropped them.
# Never automatically: a restored older snapshot makes the newer ones "other".
_OLD_PASSWORD_SNAPSHOTS = (
    "{count} snapshot(s) open with an earlier master password, and their keys "
    "still decrypt today's data. 'sezam snapshot drop-old-passwords' deletes them."
)


@snapshot_group.command("drop-old-passwords")
@click.option("--yes", is_flag=True, help="Do not ask for confirmation (required without a TTY).")
def snapshot_drop_old_passwords(yes: bool):
    """Delete the snapshots that open with an earlier master password."""
    from .vault.snapshots import drop_snapshots_of_other_passwords, snapshots_of_other_passwords, vault_salt

    vault_path = _get_vault_path()
    salt = vault_salt(vault_path)
    if not salt:
        raise click.ClickException(f"No vault in {vault_path}.")
    doomed = snapshots_of_other_passwords(vault_path, salt)
    if not doomed:
        click.echo("No snapshot opens with an earlier master password.")
        return
    for info in doomed:
        click.echo(f"  {info.name}")
    if not yes:
        if not sys.stdin.isatty():
            raise click.ClickException("Pass --yes to delete them without a TTY.")
        click.confirm(f"Delete these {len(doomed)} snapshot(s)?", abort=True)
    removed = drop_snapshots_of_other_passwords(vault_path, salt)
    click.echo(f"Deleted {removed} snapshot(s).")


@snapshot_group.command("restore")
@click.argument("name")
@click.option("--yes", is_flag=True, help="Do not ask for confirmation (required without a TTY).")
def snapshot_restore(name: str, yes: bool):
    """Replace the vault with snapshot NAME (from 'sezam snapshot list').

    Asks for the master password that opens the snapshot. The current vault
    is snapshotted first ('pre-restore'), so the restore can be undone.
    Local changes made after the snapshot are lost unless they are on the
    server; server-connected vaults pull them back on the next sync.
    """
    from .vault.snapshots import SnapshotError, stage_snapshot

    vault_path = _get_vault_path()
    try:
        staging = stage_snapshot(vault_path, name)
    except SnapshotError as exc:
        raise click.ClickException(str(exc)) from exc
    _restore_staged(vault_path, staging, name, "snapshot", yes)


@main.command("restore")
@click.argument("backup", type=click.Path(exists=True, dir_okay=False))
@click.option("--yes", is_flag=True, help="Do not ask for confirmation (required without a TTY).")
def restore_backup(backup: str, yes: bool):
    """Replace the vault with BACKUP, a file from 'sezam export --format backup'.

    Works like 'sezam snapshot restore': asks for the master password that
    opens the backup, and keeps the current vault as a 'pre-restore'
    snapshot. A backup from a newer Sezam is refused.
    """
    from .vault.snapshots import SnapshotError, stage_file

    vault_path = _get_vault_path()
    vault_path.mkdir(parents=True, exist_ok=True)
    try:
        staging = stage_file(vault_path, backup, f"Backup {backup}")
    except SnapshotError as exc:
        raise click.ClickException(str(exc)) from exc
    _restore_staged(vault_path, staging, backup, "backup", yes)


def _restore_staged(vault_path: Path, staging: Path, name: str, kind: str, yes: bool) -> None:
    """Install a staged snapshot or backup once its password is proven."""
    from .mcp import control
    from .vault.snapshots import SnapshotError, discard_staged, install_staged

    try:
        live = vault_path / "sezam.db"
        if live.exists() and not yes:
            if not sys.stdin.isatty():
                raise click.ClickException(
                    "Restoring replaces the current vault; pass --yes without a TTY."
                )
            if not click.confirm(f"Replace the current vault with {name}?"):
                click.echo("Restore cancelled.")
                return

        _check_rate_limit()
        password = _get_password(f"Master password of the {kind}: ")
        staged = Vault(staging)
        staged._db.open()
        try:
            opens = staged.verify_password(password)
        finally:
            staged._db.close()
        if not opens:
            _record_failed_attempt()
            time.sleep(2)
            raise click.ClickException("Wrong master password for this snapshot; nothing restored.")
        _clear_failed_attempts()

        # Nothing may keep using the old database: end the CLI session and
        # lock every running MCP server before the file is replaced.
        _clear_session()
        control.send_all("lock")
        try:
            pre_restore = install_staged(vault_path, staging)
        except (SnapshotError, OSError) as exc:
            raise click.ClickException(f"Restore failed, vault unchanged: {exc}") from exc
    finally:
        discard_staged(staging)

    click.echo(f"Vault restored from {name}.")
    if pre_restore is not None:
        click.echo(f"The previous state is kept as snapshot {pre_restore.name}.")
    click.echo(f"Unlock again with the {kind}'s master password.")


def _collect_all_entries(
    vault: Vault,
    node_id: Optional[str] = None,
    folder_path: str = "",
    folder_parts: tuple[str, ...] = (),
    folder_tier: Optional[int] = None,
    skipped: Optional[dict] = None,
) -> list[dict]:
    """Recursively collect all entries with their folder paths.

    ``_folder_parts`` keeps the folder names apart (a name may hold '/'), and
    ``_effective_tier`` is the tier the entry has in this vault: a folder of
    tier 2 hides everything under it, else the entry's own tier or the
    nearest folder's (review 526419e N1: the CSV holds no folder tiers).
    Folders and entries this vault cannot decrypt are counted into
    ``skipped`` ({"folders", "entries"}) (review 526419e N2).
    """
    if node_id is None:
        node_id = vault.db.get_meta("root_node_id")
    if skipped is None:
        skipped = {"folders": 0, "entries": 0}

    results = []

    # Collect entries in this node
    try:
        entries = vault.list_entries(node_id)
    except Exception:  # noqa: BLE001 - no key for this folder: all its entries are left out
        entries = []
    live = vault.db.fetchone(
        "SELECT COUNT(*) FROM entries WHERE node_id = ? AND is_deleted = 0", (node_id,)
    )[0]
    skipped["entries"] += live - len(entries)
    for entry_meta in entries:
        try:
            entry = vault.read_entry(entry_meta["id"])
        except Exception:  # noqa: BLE001 - counted and reported, not silently dropped
            skipped["entries"] += 1
            continue
        entry["_folder_path"] = folder_path
        entry["_folder_parts"] = folder_parts
        if folder_tier == 2 or entry.get("tier") is None:
            entry["_effective_tier"] = folder_tier
        else:
            entry["_effective_tier"] = entry["tier"]
        results.append(entry)

    # Recurse into child nodes
    children = vault.list_nodes(node_id)
    live = vault.db.fetchone(
        "SELECT COUNT(*) FROM nodes WHERE parent_id = ? AND is_deleted = 0", (node_id,)
    )[0]
    skipped["folders"] += live - len(children)
    for child in children:
        child_path = f"{folder_path}/{child['name']}" if folder_path else child["name"]
        child_tier = folder_tier
        if folder_tier != 2 and child.get("tier") is not None:
            child_tier = child["tier"]
        results.extend(_collect_all_entries(
            vault, child["id"], child_path, folder_parts + (child["name"],), child_tier,
            skipped,
        ))

    return results


def _export_csv(vault: Vault, dest: str) -> dict:
    """Export all decrypted entries to CSV.

    Columns: folder,name,field_key,field_value,sensitive,tier,entry,field_type.
    ``entry`` numbers the entries, so two of the same name in one folder
    import back as two (lockout review M3). Review 526419e N1: an entry
    without fields is one row with an empty field_key, ``field_type`` keeps
    TOTP fields, the tier is the effective one (folder tiers are not in the
    file), and '/' or '\\' in a folder name is escaped with '\\'.
    """
    from .importers.csv_import import join_folder_path

    skipped = {"folders": 0, "entries": 0}
    all_entries = _collect_all_entries(vault, skipped=skipped)

    with private_output(dest, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "folder", "name", "field_key", "field_value", "sensitive", "tier", "entry",
            "field_type",
        ])
        for number, entry in enumerate(all_entries, start=1):
            folder = join_folder_path(entry.get("_folder_parts", ()))
            name = entry["name"]
            tier = entry.get("_effective_tier")
            tier = "" if tier is None else tier
            for field in entry["fields"] or [{"key": "", "value": ""}]:
                writer.writerow([
                    csv_escape(folder),
                    csv_escape(name),
                    csv_escape(field["key"]),
                    csv_escape(field["value"]),
                    str(field.get("sensitive", False)).lower(),
                    tier,
                    number,
                    csv_escape(field.get("field_type") or ""),
                ])
    return skipped


_BITWARDEN_SLOTS = {
    "username": ("username",),
    "password": ("password",),
    "totp": ("totp", "totp_secret"),
    "notes": ("notes",),
}


def _bitwarden_slots(fields: list[dict]) -> dict[int, str]:
    """Field index -> Bitwarden login slot, one field per slot.

    Review 526419e S5: keys differing only in case (password/Password) each
    overwrote the slot, the last one won and the rest were lost. The exactly
    named field takes the slot, else the first case-insensitive match; the
    others are exported as custom fields.
    """
    taken: dict[int, str] = {}
    for slot, names in _BITWARDEN_SLOTS.items():
        exact = [i for i, f in enumerate(fields) if f["key"] in names]
        loose = [i for i, f in enumerate(fields) if f["key"].lower() in names]
        chosen = (exact or loose or [None])[0]
        if chosen is not None:
            taken[chosen] = slot
    return taken


def _export_bitwarden(vault: Vault, dest: str) -> dict:
    """Export all decrypted entries to Bitwarden JSON format.

    Format: {encrypted: false, folders: [...], items: [...]}
    Returns what could not be decrypted (see _collect_all_entries).
    Review d150605 N9: '/' nests folders as in Bitwarden, so a '/' or '\\'
    inside a folder name is escaped with '\\' as in the CSV export (a folder
    'Work/Prod' came back as 'Prod' inside 'Work').
    """
    from .importers.csv_import import join_folder_path

    skipped = {"folders": 0, "entries": 0}
    all_entries = _collect_all_entries(vault, skipped=skipped)
    for entry in all_entries:
        entry["_folder_path"] = join_folder_path(entry.get("_folder_parts", ()))

    # Collect unique folders
    folder_names: dict[str, str] = {}  # folder_path -> id
    folder_list = []
    folder_counter = 0
    for entry in all_entries:
        fp = entry.get("_folder_path", "")
        if fp and fp not in folder_names:
            folder_id = str(folder_counter)
            folder_names[fp] = folder_id
            folder_list.append({"id": folder_id, "name": fp})
            folder_counter += 1

    # Build items
    items = []
    for entry in all_entries:
        fp = entry.get("_folder_path", "")
        folder_id = folder_names.get(fp)

        # Extract login fields
        login: dict = {"uris": [], "username": None, "password": None, "totp": None}
        notes = None
        custom_fields = []
        slots = _bitwarden_slots(entry["fields"])

        for index, field in enumerate(entry["fields"]):
            slot = slots.get(index)
            if slot == "notes":
                notes = field["value"]
            elif slot is not None:
                login[slot] = field["value"]
            elif field["key"].lower() == "url":
                login["uris"].append({"match": None, "uri": field["value"]})
            else:
                f_type = 1 if field.get("sensitive", False) else 0  # 0=text, 1=hidden
                custom_fields.append({
                    "name": field["key"],
                    "value": field["value"],
                    "type": f_type,
                })

        item: dict = {
            "id": entry.get("id", ""),
            "organizationId": None,
            "folderId": folder_id,
            "type": 1,  # login
            "name": entry["name"],
            "notes": notes,
            "favorite": False,
            "login": login,
            "collectionIds": None,
        }
        if custom_fields:
            item["fields"] = custom_fields

        items.append(item)

    bw_export = {
        "encrypted": False,
        "folders": folder_list,
        "items": items,
    }

    with private_output(dest, "w", encoding="utf-8") as f:
        json.dump(bw_export, f, indent=2, ensure_ascii=False)
    return skipped


# ── Import command (extended with 1password and plaintext) ──


@main.command("import")
@click.argument("source", type=click.Path(exists=True))
@click.option(
    "--format", "fmt",
    type=click.Choice(["csv", "keepass", "bitwarden", "1password", "plaintext"]),
    required=True,
)
def import_data(source: str, fmt: str):
    """Import entries from CSV, KeePass, Bitwarden, 1Password, or plaintext."""
    vault = _open_vault()
    _unlock_vault(vault)

    from .vault.snapshots import SnapshotError, take_snapshot

    try:
        take_snapshot(vault.db, "import")
    except SnapshotError as exc:
        vault.lock()
        raise click.ClickException(str(exc)) from exc

    if fmt == "csv":
        from .importers.csv_import import import_csv
        count = import_csv(vault, source)
    elif fmt == "keepass":
        from .importers.keepass import import_keepass
        count = import_keepass(vault, source)
    elif fmt == "bitwarden":
        from .importers.bitwarden import import_bitwarden
        count = import_bitwarden(vault, source)
    elif fmt == "1password":
        count = _import_1password(vault, source)
    elif fmt == "plaintext":
        count = _import_plaintext(vault, source)
    else:
        click.echo(f"Unknown format: {fmt}", err=True)
        vault.lock()
        sys.exit(1)

    vault.lock()
    click.echo(f"Imported {count} entries.")


def _import_1password(
    vault: Vault,
    source: str,
    tier: Optional[int] = None,
    conflict_mode: str = "duplicate",
) -> int:
    """Import entries from a 1Password .1pux file.

    .1pux files are ZIP archives containing export.data (JSON).
    """
    import zipfile

    try:
        with zipfile.ZipFile(source, "r") as zf:
            # 1pux files contain export.data as the main JSON payload
            if "export.data" not in zf.namelist():
                click.echo("Invalid .1pux file: missing export.data", err=True)
                return 0
            raw = zf.read("export.data")
            data = json.loads(raw)
    except zipfile.BadZipFile:
        click.echo("Not a valid ZIP/.1pux file.", err=True)
        return 0

    count = 0
    claimed: set[str] = set()
    for account in data.get("accounts", []):
        for op_vault in account.get("vaults", []):
            vault_name = op_vault.get("attrs", {}).get("name", "")
            for item in op_vault.get("items", []):
                item_data = item.get("item", {})
                if not item_data:
                    continue

                # Skip trashed items
                if item.get("trashed", False):
                    continue

                overview = item_data.get("overview", {})
                details = item_data.get("details", {})

                name = overview.get("title", "Untitled")
                tags = overview.get("tags", [])

                fields = []
                sort_order = 0

                # Process login fields from details.loginFields
                for lf in details.get("loginFields", []):
                    designation = lf.get("designation", "")
                    field_value = lf.get("value", "")
                    if not field_value:
                        continue

                    if designation == "username":
                        fields.append({
                            "key": "username",
                            "value": field_value,
                            "sensitive": False,
                            "sort_order": sort_order,
                        })
                        sort_order += 1
                    elif designation == "password":
                        fields.append({
                            "key": "password",
                            "value": field_value,
                            "sensitive": True,
                            "sort_order": sort_order,
                        })
                        sort_order += 1

                # Process sections and section fields
                for section in details.get("sections", []):
                    for sf in section.get("fields", []):
                        field_key = sf.get("title") or sf.get("id", f"field_{sort_order}")
                        field_val = sf.get("value", {})

                        # 1Password stores values as typed objects
                        if isinstance(field_val, dict):
                            # Common types: string, concealed, url, email, date, etc.
                            actual_value = (
                                field_val.get("string")
                                or field_val.get("concealed")
                                or field_val.get("url")
                                or field_val.get("email")
                                or field_val.get("totp")
                                or str(field_val.get("date", ""))
                                or ""
                            )
                        else:
                            actual_value = str(field_val) if field_val else ""

                        if not actual_value:
                            continue

                        is_sensitive = "concealed" in sf.get("value", {}) if isinstance(sf.get("value"), dict) else False

                        fields.append({
                            "key": field_key,
                            "value": actual_value,
                            "sensitive": is_sensitive,
                            "sort_order": sort_order,
                        })
                        sort_order += 1

                # URLs from overview
                for url_obj in overview.get("urls", []):
                    url = url_obj.get("url", "")
                    if url:
                        fields.append({
                            "key": "url",
                            "value": url,
                            "sensitive": False,
                            "sort_order": sort_order,
                        })
                        sort_order += 1
                        break  # Only first URL

                # Notes from details.notesPlain
                notes = details.get("notesPlain", "")
                if notes:
                    fields.append({
                        "key": "notes",
                        "value": notes,
                        "sensitive": False,
                        "sort_order": sort_order,
                    })
                    sort_order += 1

                if not fields:
                    continue

                # Use vault name as folder
                from .importers import import_entry

                folder_path = vault_name
                node_id = _ensure_folder_path(vault, folder_path)
                if import_entry(
                    vault,
                    node_id,
                    name,
                    fields,
                    tier,
                    conflict_mode,
                    tags if tags else None,
                    claimed=claimed,
                ):
                    count += 1

    return count


def _import_plaintext(vault: Vault, source: str) -> int:
    """Import entries from a plaintext file.

    Format: blocks separated by blank lines, each block is an entry.
    First line = entry name, subsequent lines = key: value pairs.

    Example:
        My Email
        username: user@example.com
        password: secret123

        SSH Server
        host: 192.168.1.1
        user: root
        password: p4ssw0rd
    """
    with open(source, encoding="utf-8") as f:
        content = f.read()

    blocks = content.strip().split("\n\n")
    root_node_id = vault.db.get_meta("root_node_id")
    count = 0

    for block in blocks:
        lines = [line.strip() for line in block.strip().splitlines() if line.strip()]
        if not lines:
            continue

        # First line is the entry name
        name = lines[0].rstrip(":")
        fields = []
        sort_order = 0

        for line in lines[1:]:
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if not key:
                continue

            # Heuristic: mark password/secret/key fields as sensitive
            is_sensitive = any(
                s in key.lower()
                for s in ("password", "secret", "key", "token", "pin", "private")
            )

            fields.append({
                "key": key,
                "value": value,
                "sensitive": is_sensitive,
                "sort_order": sort_order,
            })
            sort_order += 1

        if not fields:
            continue

        vault.create_entry(root_node_id, name, fields)
        count += 1

    return count


def _ensure_folder_path(vault: Vault, folder_path: str) -> str:
    """Create folder hierarchy if needed, return leaf node ID."""
    if not folder_path:
        return vault.db.get_meta("root_node_id")

    parts = [p for p in folder_path.split("/") if p]
    current_node = vault.db.get_meta("root_node_id")

    for part in parts:
        children = vault.list_nodes(current_node)
        found = None
        for child in children:
            if child["name"].lower() == part.lower():
                found = child["id"]
                break
        if found is None:
            found = vault.create_node(part, current_node)
        current_node = found

    return current_node


# ── Push / Pull ──


def _adopt_rotation_prompt(client, vault: Vault) -> None:
    """Take over a password change made on another device, then sync again."""
    click.echo(
        "The account password or identity key was changed on another device; "
        "this vault still uses the old one.",
        err=True,
    )
    _check_rate_limit()
    password = _get_password("Current account password: ")
    try:
        epoch = client.adopt_rotated_key_material(vault, password)
    except RuntimeError:
        _record_failed_attempt()
        raise
    _clear_failed_attempts()
    # The session holds the old KEK, which no longer opens this vault.
    _clear_session()
    click.echo(
        f"Adopted the new account password (key epoch {epoch}); "
        "this vault now unlocks with it."
    )


@main.command("abandon-pending-change")
@click.option("--yes", is_flag=True, help="Do not ask for confirmation")
def abandon_pending_change(yes: bool):
    """Drop a password/key change the server refuses; take over the server's password.

    Use it when 'sezam push' keeps failing on this device's own password
    change (e.g. 'Wrong current account password'). You need the account
    password the server has now (the one your other devices still use); this
    vault then unlocks with it. Entries and changes stay. The new password
    and an identity key rotation are dropped with the change.
    """
    from .vault import pending_states
    from .vault.sync_client import SyncClient

    vault = _open_vault()
    _unlock_vault_fresh(vault)
    server = vault.db.get_meta("server_url")
    try:
        if not server or not vault.db.get_meta("user_id"):
            raise click.ClickException("This vault is not connected to a server")
        client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
        client.set_dek_manager(vault.dek_mgr)
        found = pending_states.blocker(vault.db, pending_states.ABANDON_KEY_CHANGE)
        if found:
            raise click.ClickException(found.message)
        if not yes:
            # Review 526419e N6: it said nothing of what goes with the change.
            journal = pending_states.key_change_journal(vault.db)
            batch = pending_states.rekey_batch(vault.db)
            warning = (
                "This drops the new password set on this device: the vault will unlock "
                "only with the password the server has now."
            )
            if "identity" in journal or batch.get("identity_rotation"):
                warning += (
                    " It also drops the identity key rotation: the old identity key stays "
                    "valid on the server. If it leaked, run 'sezam rotate-identity' again "
                    "right after."
                )
            click.echo(f"Warning: {warning}", err=True)
            click.confirm("Drop the unsent change?", abort=True)
        _check_rate_limit()
        password = _get_password("Account password the server has now: ")
        try:
            epoch = client.abandon_pending_change(vault, password)
        except RuntimeError as exc:
            _record_failed_attempt()
            raise click.ClickException(f"{exc}; nothing was changed") from exc
        _clear_failed_attempts()
        _clear_session()
    finally:
        vault.lock()
    click.echo(
        f"Dropped the unsent change; this vault now uses the server's account "
        f"password (key epoch {epoch}). Run 'sezam push' to send your other changes."
    )


@main.command("finish-pending-change")
def finish_pending_change():
    """Send a password change an older Sezam version left unsent; keep the new password.

    That version kept no proof of the password the server has, and the
    server now refuses a change without it. You need the account password
    the server has now (the one your other devices still use).
    """
    from .vault import pending_states
    from .vault.sync_client import SyncClient

    vault = _open_vault()
    _unlock_vault_fresh(vault)
    server = vault.db.get_meta("server_url")
    try:
        if not server or not vault.db.get_meta("user_id"):
            raise click.ClickException("This vault is not connected to a server")
        if not pending_states.change_lacks_server_proof(vault.db):
            raise click.ClickException("No unsent password change here lacks the server's password")
        client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
        client.set_dek_manager(vault.dek_mgr)
        _check_rate_limit()
        password = _get_password("Account password the server has now: ")
        try:
            client.finish_pending_change(vault, password)
        except RuntimeError as exc:
            _record_failed_attempt()
            raise click.ClickException(f"{exc}; nothing was changed") from exc
        _clear_failed_attempts()
        try:
            client.push()
        except RuntimeError as exc:
            raise click.ClickException(
                f"The proof is kept, but the push failed: {exc}. Run 'sezam push' again."
            ) from exc
    finally:
        vault.lock()
    click.echo("The new password was sent to the server.")


@main.command("abandon-rekey")
@click.option("--yes", is_flag=True, help="Do not ask for confirmation")
@click.option(
    "--queued", is_flag=True,
    help="Drop the queue of removed members waiting for a re-key instead.",
)
def abandon_rekey(yes: bool, queued: bool):
    """Drop this device's pending member re-key that the server keeps refusing.

    The folders go back to the key the server has for them now, objects the
    server holds newer copies of take those copies (your own edits come back
    as conflicts), and a member who can still open a folder is queued for a
    fresh re-key with the next 'sezam push'. With --queued the queue itself
    is dropped: those members keep the keys of folders they could open.
    """
    from .vault.rekey_abandon import abandon_pending_rekey
    from .vault import oplock, pending_states
    from .vault.sync_client import SyncClient

    vault = _open_vault()
    _unlock_vault_fresh(vault)
    if queued:
        try:
            found = pending_states.blocker(vault.db, pending_states.ABANDON_QUEUED)
            if found:
                raise click.ClickException(found.message)
            queue = pending_states.revocation_queue(vault.db)
            if not yes:
                click.confirm(
                    f"Drop the re-key of {', '.join(queue)}? They keep the keys of "
                    "folders they could open until those are re-keyed.",
                    abort=True,
                )
            with oplock.exclusive(vault.db.path):  # INV-6; only the members confirmed
                pending_states.set_revocation_queue(vault.db, [
                    u for u in pending_states.revocation_queue(vault.db) if u not in queue
                ])
        finally:
            vault.lock()
        click.echo("Dropped the queued re-keys.")
        return
    try:
        found = pending_states.blocker(vault.db, pending_states.ABANDON_REKEY)
        if found:
            raise click.ClickException(found.message)
        pending = pending_states.rekey_batch(vault.db)
        if not yes:
            click.confirm(
                f"Drop the unsent re-key for member {pending.get('revoked_user_id')}?",
                abort=True,
            )
        server = vault.db.get_meta("server_url") or ""
        client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
        client.set_dek_manager(vault.dek_mgr)
        if server:
            try:
                client.pull()  # newer server copies win over the dropped batch
            except (RuntimeError, OSError) as exc:
                click.echo(f"Warning: could not pull first ({exc}).", err=True)
        result = abandon_pending_rekey(client)
    finally:
        vault.lock()
    click.echo("Dropped the unsent re-key.")
    if result["conflicts"]:
        click.echo(
            f"{result['conflicts']} local edit(s) came back as conflicts: "
            "'sezam conflicts' lists them."
        )
    if result["requeued"]:
        click.echo(
            "The member can still open folders on this device's keys: the next "
            "'sezam push' re-keys them again from the current state."
        )


@main.command("status")
def status():
    """List everything this vault keeps waiting for the server, with the way out."""
    from .vault.pending_states import pending_states
    from .vault.snapshots import snapshots_of_other_passwords

    vault = _open_vault()
    _unlock_vault(vault)
    try:
        server = vault.db.get_meta("server_url")
        click.echo(f"Server: {server}" if server else "Server: not connected")
        states = pending_states(vault)
        old_snapshots = snapshots_of_other_passwords(vault.db.path.parent, vault.db.get_meta("argon2_salt"))
    finally:
        vault.lock()
    if old_snapshots:
        click.echo(_OLD_PASSWORD_SNAPSHOTS.format(count=len(old_snapshots)))
    if not states:
        click.echo("Nothing is waiting.")
        return
    for state in states:
        click.echo(f"- {state.summary}")
        click.echo(f"    resolve: {state.resolve}")
        if state.drop:
            click.echo(f"    drop:    {state.drop}")


@main.command()
@click.option("--server", "-s", envvar="SEZAM_SERVER", help="Server URL")
def push(server: Optional[str]):
    """Push local changes to server."""
    vault = _open_vault()
    _unlock_vault(vault)

    if not server:
        server = vault.db.get_meta("server_url")
    if not server:
        click.echo("No server configured. Use --server or 'sezam init' with server URL.", err=True)
        vault.lock()
        sys.exit(1)

    from .vault.revocation import blocked_message, finish_queued_into
    from .vault.sync_client import KeyEpochStale, SyncClient
    client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
    client.set_dek_manager(vault.dek_mgr)
    try:
        # Members revoked while another re-key waited (review 688edcb #8b):
        # a queued member's pending batch is sent and counted first, the
        # rest are re-keyed once the push landed the batch they waited for.
        rekeyed: dict[str, int] = {}
        blocked: dict[str, list[str]] = {}
        too_large: dict[str, str] = {}

        def finish_queued() -> None:
            # Review e4cd15a #3: a re-key waits for open conflicts in its
            # folders; the rest of the push (and of the queue, 526419e S4) goes on.
            finish_queued_into(vault, client, rekeyed, blocked, too_large)

        try:
            finish_queued()
            result = client.push()
        except KeyEpochStale:
            _adopt_rotation_prompt(client, vault)
            result = client.push()
        accepted = len(result.get("accepted", []))
        conflicts = len(result.get("conflicts", []))
        click.echo(f"Push: {accepted} accepted, {conflicts} conflicts.")
        if result.get("rollback_warning"):
            # Review 7c10379 Y7: nothing was sent and the push said only that.
            _echo_pull_warnings({"rollback_warning": result["rollback_warning"]})
        if result.get("org_recovery_rewrap_pending"):
            click.echo(_ORG_RECOVERY_REWRAP_WARNING, err=True)
        if result.get("org_recovery_superseded"):
            from .vault.org_recovery_server import SUPERSEDED_NOTE

            click.echo(f"Warning: {SUPERSEDED_NOTE}", err=True)
        from .vault.personal_root import PERSONAL_ROOTS_WAITING_META

        if vault.db.get_meta_json(PERSONAL_ROOTS_WAITING_META):
            # Review 4acfdde R11 (low): a server older than this app.
            click.echo(
                "Warning: your personal folder(s) stay on this device: the server is older than "
                "this app and takes no personal folder of a member yet ('sezam status').",
                err=True,
            )
        finish_queued()
        for user_id, object_ids in blocked.items():
            click.echo(f"Warning: {blocked_message(user_id, object_ids)}", err=True)
        if blocked:
            click.echo(
                "Settle them with 'sezam conflicts resolve ID --keep local|server'.", err=True
            )
        if result.get("rekey_too_large") and not too_large:
            click.echo(f"Warning: {result['rekey_too_large']}", err=True)
        for user_id, reason in too_large.items():
            click.echo(f"Warning: the re-key of revoked user {user_id} waits: {reason}", err=True)
        for user_id, count in rekeyed.items():
            click.echo(f"Re-keyed {count} folder(s) after revoking user {user_id}.")
        from .vault.revocation import finish_handover_rekeys

        for user_id, count in finish_handover_rekeys(vault, client).items():
            click.echo(f"Re-keyed {count} folder(s) the former admin {user_id} held.")
        if conflicts:
            for c in result["conflicts"]:
                click.echo(f"  Conflict: {c['id']} — {c.get('error', '')}", err=True)
            click.echo(
                "Run 'sezam pull', then 'sezam conflicts' to choose which copies to keep.",
                err=True,
            )
        _check_org_recovery_registration(vault)
    except RuntimeError as e:
        click.echo(f"Push failed: {e}", err=True)
        from .vault.sync_common import server_error

        if client.has_pending_key_change() and server_error(e, 403):
            from .vault.pending_states import (
                PRE_PROOF_CHANGE,
                change_lacks_server_proof,
                key_reset_way_out,
            )

            if change_lacks_server_proof(vault.db):
                # Review 4acfdde R11: it never said the change was an older
                # version's, nor how to keep its new password.
                click.echo(
                    f"{PRE_PROOF_CHANGE} 'sezam finish-pending-change' adds it and keeps the "
                    "new password; 'sezam abandon-pending-change' drops the new password.",
                    err=True,
                )
                vault.lock()
                return
            click.echo(
                "The server refuses this device's password change. Way out: "
                f"{key_reset_way_out(vault.db, vault.db.get_meta('user_id'))}; "
                "or drop the change with 'sezam abandon-pending-change' "
                "(needs the password the server has now).",
                err=True,
            )
    vault.lock()


def _check_org_recovery_registration(vault: Vault) -> None:
    """Review 526419e V5: a lone admin learned that the server lacks the
    recovery key only after forgetting the password. Checked after a push,
    while the password can still be asked for."""
    from .vault.org_recovery_server import (
        STALE_NOTE,
        SUPERSEDED_NOTE,
        UNREGISTERED_HINT,
        register_while_password_known,
        registration_issue,
    )

    if vault.key_change_unpushed():
        return
    try:
        issue = registration_issue(vault)
    except RuntimeError:
        return
    if issue == "unregistered":
        click.echo(f"Warning: {UNREGISTERED_HINT}", err=True)
    elif issue == "superseded":
        click.echo(f"Warning: {SUPERSEDED_NOTE}", err=True)
    elif issue == "stale":
        click.echo(f"Warning: {STALE_NOTE}", err=True)
    elif issue == "pending":
        if not sys.stdin.isatty():
            click.echo(
                "Warning: this vault's org recovery is not registered on the server yet; "
                "run 'sezam push' in a terminal to register it with your password.",
                err=True,
            )
            return
        password = _get_password(
            "Master password (registers this vault's org recovery on the server): "
        )
        click.echo(register_while_password_known(vault, password) or "")


def _conflict_client(vault: Vault):
    from .vault.sync_client import SyncClient

    client = SyncClient(
        vault.db, vault.db.get_meta("server_url") or "", vault.keypair,
        vault.db.get_meta("user_id"),
    )
    client.set_dek_manager(vault.dek_mgr)
    return client


def _local_name(vault: Vault, object_type: str, object_id: str) -> str:
    try:
        if object_type == "node":
            return vault.read_node(object_id)["name"]
        return vault.read_entry(object_id)["name"]
    except (KeyError, ValueError, RuntimeError):
        return "(deleted or unreadable here)"


@main.group("conflicts", invoke_without_command=True)
@click.pass_context
def conflicts_group(ctx):
    """List items changed both here and on another device."""
    if ctx.invoked_subcommand is not None:
        return
    vault = _open_vault()
    _unlock_vault(vault)
    try:
        rows = _conflict_client(vault).get_pull_conflicts()
        if not rows:
            click.echo("No sync conflicts.")
            return
        for row in rows:
            state = "deleted on the server" if row["server_is_deleted"] else (
                f"server v{row['server_version']}"
            )
            click.echo(
                f"{row['id']}  {row['object_type']}  "
                f"{_local_name(vault, row['object_type'], row['id'])}  "
                f"(local v{row['local_version']}, {state})"
            )
        click.echo(
            "Resolve with: sezam conflicts resolve ID --keep local|server, then 'sezam push'."
        )
    finally:
        vault.lock()


@conflicts_group.command("resolve")
@click.argument("object_id")
@click.option("--keep", type=click.Choice(["local", "server"]), required=True)
def conflicts_resolve(object_id: str, keep: str):
    """Keep this device's copy (pushed next) or take the server's copy."""
    vault = _open_vault()
    _unlock_vault(vault)
    try:
        _conflict_client(vault).resolve_conflict(object_id, keep)
    except (KeyError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        vault.lock()
    if keep == "local":
        click.echo("Kept the local copy; run 'sezam push' to send it.")
    else:
        click.echo("Took the server copy.")


@main.group("trash", invoke_without_command=True)
@click.pass_context
def trash_group(ctx):
    """List deleted folders and entries that can be restored."""
    if ctx.invoked_subcommand is not None:
        return
    from .vault.trash import list_trash

    vault = _open_vault()
    _unlock_vault(vault)
    try:
        items = list_trash(vault)
        if not items:
            click.echo("Trash is empty.")
            return
        for item in items:
            where = f"/{item['path']}" if item["path"] else "/"
            extra = f"  ({item['entries']} entries)" if item["type"] == "folder" else ""
            click.echo(f"{item['id']}  {item['type']}  {where}  {item['name']}{extra}")
        click.echo("Restore with: sezam trash restore ID, then 'sezam push'.")
    finally:
        vault.lock()


@trash_group.command("restore")
@click.argument("object_id")
def trash_restore(object_id: str):
    """Restore a deleted entry, or a folder with everything deleted in it."""
    from .vault.trash import TrashError, restore_entry, restore_node

    vault = _open_vault()
    _unlock_vault(vault)
    try:
        is_folder = vault.db.fetchone(
            "SELECT 1 FROM nodes WHERE id = ? AND is_deleted = 1", (object_id,)
        ) is not None
        if is_folder:
            count = restore_node(vault, object_id)
            click.echo(f"Folder restored with {count} entries; run 'sezam push' to sync it.")
        else:
            restore_entry(vault, object_id)
            click.echo("Entry restored; run 'sezam push' to sync it.")
    except (KeyError, TrashError) as exc:
        raise click.ClickException(str(exc).strip("'\"")) from exc
    finally:
        vault.lock()


@main.command("history")
@click.argument("path")
@click.option("--show", "show_id", help="Show the fields of one earlier version")
@click.option("--restore", "restore_id", help="Put the fields of one earlier version back")
def history_cmd(path: str, show_id: Optional[str], restore_id: Optional[str]):
    """List earlier versions of an entry; show or restore one of them."""
    from .vault.trash import TrashError, list_history, read_history, restore_history

    vault = _open_vault()
    _unlock_vault(vault)
    try:
        entry = vault.find_entry_by_path(path)
        if entry is None:
            raise click.ClickException(f"Entry not found: {path}")
        if restore_id:
            restore_history(vault, entry["id"], restore_id)
            click.echo(
                "Earlier version restored (the replaced one is in history); "
                "run 'sezam push' to sync it."
            )
        elif show_id:
            for field in read_history(vault, entry["id"], show_id):
                value = "****" if field.get("sensitive") else field["value"]
                click.echo(f"  {field['key']}: {value}")
        else:
            versions = list_history(vault, entry["id"])
            if not versions:
                click.echo("No earlier versions.")
                return
            for version in versions:
                stamp = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(version["changed_at"] / 1000)
                )
                click.echo(f"{version['id']}  {stamp}")
            click.echo("Show with --show ID, restore with --restore ID.")
    except (KeyError, TrashError) as exc:
        raise click.ClickException(str(exc).strip("'\"")) from exc
    finally:
        vault.lock()


@main.command()
@click.option("--server", "-s", envvar="SEZAM_SERVER", help="Server URL")
@click.option(
    "--full-resync",
    is_flag=True,
    help="Explicitly replace local sync state after tombstone garbage collection.",
)
@click.option(
    "--export-dirty",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Save an encrypted copy of the vault before the full resync "
    "('sezam restore PATH' loads it back; it opens with the current password).",
)
@click.option("--yes", is_flag=True, help="Confirm the destructive full resync.")
def pull(
    server: Optional[str],
    full_resync: bool,
    export_dirty: Optional[Path],
    yes: bool,
):
    """Pull changes from server."""
    vault = _open_vault()
    _unlock_vault(vault)

    if not server:
        server = vault.db.get_meta("server_url")
    if not server:
        click.echo("No server configured. Use --server or 'sezam init' with server URL.", err=True)
        vault.lock()
        sys.exit(1)

    from .vault.sync_client import KeyEpochStale, SyncClient, TofuKeyChangeError
    client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
    client.set_dek_manager(vault.dek_mgr)
    try:
        if export_dirty is not None and not full_resync:
            raise click.UsageError("--export-dirty requires --full-resync")
        if full_resync:
            blocker = client.full_resync_blocker()
            if blocker:
                raise RuntimeError(blocker)
            dirty_count = client.dirty_object_count()
            click.echo(
                "WARNING: Full resync replaces the local vault snapshot with the "
                "server's."
            )
            if dirty_count:
                click.echo(
                    f"{dirty_count} unsynchronized object(s) on this device are kept "
                    "and sent with the next push."
                )
                if export_dirty is None:
                    click.echo(
                        "Use --export-dirty PATH to save an encrypted copy of the vault first."
                    )
            confirmed = yes or click.confirm("Continue with full resync?", default=False)
            if not confirmed:
                click.echo("Full resync cancelled.")
                vault.lock()
                return

        adopted = False
        while True:
            try:
                if full_resync:
                    result = client.full_resync(
                        confirmed=True,
                        dirty_export_path=export_dirty,
                    )
                else:
                    result = client.pull()
                break
            except KeyEpochStale:
                if adopted:
                    raise
                _adopt_rotation_prompt(client, vault)
                adopted = True
            except TofuKeyChangeError as change:
                click.echo(
                    "TOFU WARNING: public keys changed for user "
                    f"{change.user_id}.\nOld fingerprint: {change.old_fingerprint}"
                    f"\nNew fingerprint: {change.new_fingerprint}",
                    err=True,
                )
                if not click.confirm(
                    "Have you independently verified and accepted the new fingerprint?",
                    default=False,
                ):
                    raise RuntimeError("Public key change was not confirmed")
                client.confirm_tofu_key_change(change, change.new_fingerprint)
        _echo_pull_warnings(result)
        click.echo(f"Pull: {result['pulled']} objects, commit_seq={result['max_commit_seq']}.")
        if result.get("kept_local"):
            click.echo(
                f"Kept {result['kept_local']} local folder(s)/entr(ies) the server "
                "does not have yet."
            )
            # Review d150605 #6: offer to send them right away.
            if yes or click.confirm("Push them to the server now?", default=True):
                try:
                    pushed = client.push()
                    click.echo(
                        f"Push: {len(pushed.get('accepted', []))} accepted, "
                        f"{len(pushed.get('conflicts', []))} conflict(s)."
                    )
                except RuntimeError as exc:
                    click.echo(f"Push failed: {exc}. Run 'sezam push' again.", err=True)
            else:
                click.echo("Run 'sezam push' to send them.")
    except (RuntimeError, click.UsageError) as e:
        click.echo(f"Pull failed: {e}", err=True)
    vault.lock()


# ── Share commands ──


@main.command()
@click.argument("path")
@click.option("--expires", default="24h", help="Expiry: 1h, 24h, 7d")
@click.option("--views", default=1, help="Max views (default 1)")
@click.option("--pin", is_flag=True, help="Require PIN")
@click.option(
    "--notify/--no-notify", "notify_on_view", default=True,
    help="Notify the owner after each successful view (default enabled)",
)
def share(path: str, expires: str, views: int, pin: bool, notify_on_view: bool):
    """Create a share link for an entry (encrypted, uploaded to server)."""
    vault = _open_vault()
    _unlock_vault(vault)

    entry = vault.find_entry_by_path(path)
    if entry is None:
        click.echo(f"Entry not found: {path}", err=True)
        vault.lock()
        sys.exit(1)

    # Get server URL
    server = vault.db.get_meta("server_url")
    if not server:
        server = os.environ.get("SEZAM_SERVER", "")
    if not server:
        click.echo("No server configured. Set SEZAM_SERVER or configure via 'sezam init'.", err=True)
        vault.lock()
        sys.exit(1)

    # Generate a random 32-byte share key for XChaCha20-Poly1305 AEAD encryption
    share_key = os.urandom(32)

    # Generate raw 32-byte share_id and derive URL-safe base64 encoding
    raw_share_id = os.urandom(32)
    share_id = base64.urlsafe_b64encode(raw_share_id).decode("ascii").rstrip("=")

    # Serialize entry to JSON for encryption
    entry_json = json.dumps(entry, separators=(",", ":"), default=str).encode("utf-8")

    # Encrypt with XChaCha20-Poly1305 using nacl directly (standalone, no vault DEK envelope)
    # AAD per spec 6.1: alg(1B) || schema_version(1B) || blob_kind=3(1B) || raw_share_id(32B) || u32be(1)
    import nacl.bindings

    aad = struct.pack("BBB", 1, 1, 3) + raw_share_id + struct.pack(">I", 1)  # 39 bytes
    nonce = os.urandom(24)  # XChaCha20-Poly1305 uses 24-byte nonce
    ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        entry_json,
        aad,
        nonce,
        share_key,
    )

    # Combine nonce + ciphertext for the share blob
    share_blob = nonce + ciphertext
    share_blob_b64 = base64.b64encode(share_blob).decode("ascii")

    # Parse expiry
    expiry_ms = _parse_expiry(expires)

    # Optionally generate PIN
    pin_hash = None
    pin_value = None
    if pin:
        import argon2
        pin_value = str(os.urandom(3).hex()[:6]).upper()  # 6-char hex PIN
        pin_hash = argon2.PasswordHasher().hash(pin_value)

    # Upload to server via POST /api/share
    import urllib.request
    import urllib.error

    payload = {
        "id": share_id,
        "encrypted_blob": share_blob_b64,
        "expires_at": expiry_ms,
        "max_views": views,
        "notify_on_view": notify_on_view,
    }
    if pin_hash:
        payload["pin_hash"] = pin_hash

    # Authenticate first
    from .vault.sync_client import SyncClient
    client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
    try:
        token = client.authenticate()
    except RuntimeError as e:
        click.echo(f"Authentication failed: {e}", err=True)
        vault.lock()
        sys.exit(1)

    server_url = server.rstrip("/")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{server_url}/api/share",
        data=req_data,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        click.echo(f"Server error {e.code}: {error_body}", err=True)
        vault.lock()
        sys.exit(1)
    except Exception as e:
        click.echo(f"Failed to upload share: {e}", err=True)
        vault.lock()
        sys.exit(1)

    # share_id was already generated locally from raw_share_id

    # Build share URL with key in fragment (never sent to server)
    key_b64 = base64.urlsafe_b64encode(share_key).decode("ascii").rstrip("=")
    share_url = f"{server_url}/s/{share_id}#{key_b64}"

    click.echo(f"Share link created (expires: {expires}, max views: {views})")
    click.echo(f"URL: {share_url}")
    if pin_value:
        click.echo(f"PIN: {pin_value}")

    vault.lock()


@main.command("share-list")
@click.option("--server", "-s", envvar="SEZAM_SERVER", help="Server URL")
def share_list(server: Optional[str]):
    """List active share links (requires admin)."""
    vault = _open_vault()
    _unlock_vault(vault)

    if not server:
        server = vault.db.get_meta("server_url")
    if not server:
        server = os.environ.get("SEZAM_SERVER", "")
    if not server:
        click.echo("No server configured.", err=True)
        vault.lock()
        sys.exit(1)

    from .vault.sync_client import SyncClient
    client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
    try:
        token = client.authenticate()
    except RuntimeError as e:
        click.echo(f"Authentication failed: {e}", err=True)
        vault.lock()
        sys.exit(1)

    import urllib.request
    import urllib.error

    server_url = server.rstrip("/")
    headers = {
        "Authorization": f"Bearer {token}",
    }
    req = urllib.request.Request(
        f"{server_url}/api/shares",
        headers=headers,
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        click.echo(f"Server error {e.code}: {error_body}", err=True)
        vault.lock()
        sys.exit(1)
    except Exception as e:
        click.echo(f"Failed to list shares: {e}", err=True)
        vault.lock()
        sys.exit(1)

    shares = resp_data if isinstance(resp_data, list) else resp_data.get("shares", [])

    if not shares:
        click.echo("No active shares.")
    else:
        # Print table header
        click.echo(f"{'ID':<40} {'Created':<20} {'Expires':<20} {'Views':<12} {'Max Views':<10}")
        click.echo("-" * 102)
        for s in shares:
            share_id = s.get("id", s.get("share_id", "?"))
            created = _format_timestamp(s.get("created_at", 0))
            expires = _format_timestamp(s.get("expires_at", 0))
            view_count = s.get("view_count", s.get("views", 0))
            max_views = s.get("max_views", "?")
            click.echo(f"{share_id:<40} {created:<20} {expires:<20} {view_count:<12} {max_views:<10}")

    vault.lock()


@main.command("provision-device")
@click.option("--server", "-s", envvar="SEZAM_SERVER", help="Server URL")
def provision_device(server: Optional[str]):
    """Print a one-time link (QR payload) that sets up the mobile app."""
    vault = _open_vault()
    _unlock_vault(vault)
    server = server or vault.db.get_meta("server_url")
    if not server:
        click.echo("No server configured.", err=True)
        vault.lock()
        sys.exit(1)

    from urllib.parse import urlencode
    from .vault.sync_client import SyncClient

    client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
    try:
        client.authenticate()
        issued = client.create_provisioning_token()
    except RuntimeError as e:
        click.echo(f"Provisioning failed: {e}", err=True)
        sys.exit(1)
    finally:
        vault.lock()

    link = "sezam://provision?" + urlencode({
        "token": issued["token"],
        "server": server.rstrip("/"),
        "username": issued["username"],
    })
    if issued.get("genesis_hash"):
        link += "#g=" + issued["genesis_hash"]
    click.echo("Scan this in the Sezam app (Settings > Provision via QR).")
    click.echo(f"Single use, valid until {_format_timestamp(issued['expires_at'])}:")
    click.echo(link)


@main.command("share-revoke")
@click.argument("share_id")
@click.option("--server", "-s", envvar="SEZAM_SERVER", help="Server URL")
def share_revoke(share_id: str, server: Optional[str]):
    """Revoke (delete) a share link by ID."""
    vault = _open_vault()
    _unlock_vault(vault)

    if not server:
        server = vault.db.get_meta("server_url")
    if not server:
        server = os.environ.get("SEZAM_SERVER", "")
    if not server:
        click.echo("No server configured.", err=True)
        vault.lock()
        sys.exit(1)

    from .vault.sync_client import SyncClient
    client = SyncClient(vault.db, server, vault.keypair, vault.db.get_meta("user_id"))
    try:
        token = client.authenticate()
    except RuntimeError as e:
        click.echo(f"Authentication failed: {e}", err=True)
        vault.lock()
        sys.exit(1)

    import urllib.request
    import urllib.error

    server_url = server.rstrip("/")
    headers = {
        "Authorization": f"Bearer {token}",
    }
    req = urllib.request.Request(
        f"{server_url}/api/share/{share_id}",
        headers=headers,
        method="DELETE",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()  # consume response
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        click.echo(f"Server error {e.code}: {error_body}", err=True)
        vault.lock()
        sys.exit(1)
    except Exception as e:
        click.echo(f"Failed to revoke share: {e}", err=True)
        vault.lock()
        sys.exit(1)

    click.echo(f"Share {share_id} revoked.")
    vault.lock()


# ── MCP Server ──


@main.command("mcp-policy")
@click.argument("path")
@click.option("--tier", type=click.IntRange(0, 2), default=None)
@click.option(
    "--allow-action",
    type=click.Choice(
        [
            "totp_code", "ssh_execute", "ssh_session", "ssh_upload", "ssh_download",
            "ssh_agent", "ssh_agent_forwarding", "ssh_agent_unbound", "ftp", "http",
        ]
    ),
    multiple=True,
    help=(
        "Explicitly allow an MCP action; repeat for multiple actions. "
        "ssh_agent_forwarding / ssh_agent_unbound additionally let 'sezam ssh-agent' "
        "sign through a forwarded agent / without session-bind (host not verified)."
    ),
)
@click.option("--clear-actions", is_flag=True, help="Deny all MCP actions.")
@click.option(
    "--allow-read-secret/--deny-read-secret",
    default=None,
    help="Explicitly allow or deny raw secret reads.",
)
@click.option(
    "--local-root",
    default=None,
    help="Only local directory ssh_upload/ssh_download may use for this entry.",
)
@click.option(
    "--clear-local-root", is_flag=True, help="Use the default transfer directory again."
)
@click.option(
    "--remote-root",
    default=None,
    help="Absolute remote directory every SFTP/FTP path of this entry must lie under.",
)
@click.option(
    "--clear-remote-root", is_flag=True, help="Do not confine remote paths any more."
)
@click.option(
    "--max-session-minutes",
    type=click.IntRange(1, 24 * 60),
    default=None,
    help="Close interactive SSH sessions after this many minutes (default 60).",
)
def mcp_policy(
    path: str,
    tier: Optional[int],
    allow_action: tuple[str, ...],
    clear_actions: bool,
    allow_read_secret: Optional[bool],
    local_root: Optional[str],
    clear_local_root: bool,
    remote_root: Optional[str],
    clear_remote_root: bool,
    max_session_minutes: Optional[int],
):
    """Configure encrypted AI/MCP policy for a vault entry."""
    from .mcp.ssh import SSHBrokerError, validate_local_root, validate_remote_root

    if clear_actions and allow_action:
        raise click.UsageError("--clear-actions cannot be combined with --allow-action")
    if clear_local_root and local_root is not None:
        raise click.UsageError("--clear-local-root cannot be combined with --local-root")
    if clear_remote_root and remote_root is not None:
        raise click.UsageError("--clear-remote-root cannot be combined with --remote-root")
    if remote_root is not None:
        try:
            remote_root = validate_remote_root(remote_root)
        except SSHBrokerError as exc:
            raise click.UsageError(str(exc)) from None
    if (
        tier is None
        and not allow_action
        and not clear_actions
        and allow_read_secret is None
        and local_root is None
        and not clear_local_root
        and remote_root is None
        and not clear_remote_root
        and max_session_minutes is None
    ):
        raise click.UsageError("Specify at least one policy option")
    if local_root is not None:
        try:
            root = validate_local_root(local_root, (_get_vault_path(),))
        except SSHBrokerError as exc:
            raise click.UsageError(str(exc)) from None
        if not root.is_dir():
            raise click.UsageError(f"--local-root is not an existing directory: {root}")
        local_root = str(root)

    vault = _open_vault()
    _unlock_vault_fresh(vault)
    try:
        entry = vault.find_entry_by_path(path)
        if entry is None:
            raise click.ClickException(f"Entry not found: {path}")
        actions = [] if clear_actions else list(dict.fromkeys(allow_action)) or None
        vault.update_entry(
            entry["id"],
            tier=tier,
            ai_read_secret=allow_read_secret,
            allowed_actions=actions,
            local_root=local_root,
            clear_local_root=clear_local_root,
            remote_root=remote_root,
            clear_remote_root=clear_remote_root,
            max_session_minutes=max_session_minutes,
        )
        click.echo(f"Updated MCP policy for {path}")
    finally:
        vault.lock()


_GROUP_HELP = (
    "Broker running as its own OS user (isolation L2): this group may also "
    "connect to the agent/MCP socket and pull the brake (ai_off, status) on "
    "brake-<pid>, never lock or unlock. Set SEZAM_RUN_DIR to a shared run "
    "directory on both sides; see 'sezam broker install-service'."
)


def _harden_broker_process() -> None:
    """Linux: no core dump, no same-user ptrace or /proc/<pid>/mem; refuse to
    start rather than hold vault keys in a process that stays dumpable."""
    from .mcp.hardening import HardeningError, harden_process

    try:
        harden_process()
    except HardeningError as exc:
        raise click.ClickException(f"Refusing to start: {exc}")


@main.command("mcp-serve")
@click.option("--transport", type=click.Choice(["stdio", "socket"]), default="stdio", help="Transport: stdio (default) or socket")
@click.option("--socket-path", default=None, help="Socket/pipe path (default: platform-specific)")
@click.option("--token/--no-token", default=False, help="Generate and require per-session token")
@click.option(
    "--approval-ui/--deny-tier1",
    default=True,
    help="Show a local confirmation dialog for Tier 1 actions, or deny them immediately.",
)
@click.option(
    "--idle-lock-minutes",
    type=click.IntRange(1, 24 * 60),
    default=30,
    show_default=True,
    help="Lock the vault after this many minutes without an MCP tool call.",
)
@click.option("--group", default=None, help=_GROUP_HELP)
def mcp_serve(
    transport: str,
    socket_path: Optional[str],
    token: bool,
    approval_ui: bool,
    idle_lock_minutes: int,
    group: Optional[str],
):
    """Run MCP server for AI agent access to the vault.

    Exposes vault and credential-free SSH tools via MCP over stdio
    or a Unix socket / Windows named pipe.
    """
    _harden_broker_process()
    vault = _open_vault()
    from .vault import ai_access

    if not ai_access.read_state(vault).enabled:
        raise click.ClickException(
            "AI access is turned off. Run 'sezam ai on' (master password) first."
        )
    # stdin is the JSON-RPC channel, so the password is never read from it.
    # The server follows the CLI session: without one it runs locked and
    # every tool call answers vault_locked until 'sezam unlock'.
    from .mcp.server import SezamMCPServer

    session_token = None
    if token:
        session_token = SezamMCPServer.generate_session_token()
        click.echo(f"Session token: {session_token}", err=True)

    server = SezamMCPServer(vault, session_token=session_token)
    if approval_ui:
        from .mcp.approval import install_desktop_approval_handler

        install_desktop_approval_handler(server.approval_manager)
    else:
        server.approval_manager.set_on_request(
            lambda request: server.approval_manager.deny(request.request_id)
        )

    from .mcp import control

    watch = _watch_session_and_lock(
        vault,
        server.broker.close,
        idle_seconds=server.idle_seconds,
        idle_limit=idle_lock_minutes * 60,
        on_unlock=server.mark_active,
        on_tick=server.broker.enforce_kill_switch,
    )
    # 'sezam ai off' and 'sezam lock' reach this process through its control
    # endpoint. Without one the brake would wait for the next tool call, so
    # the server does not run at all.
    control_server = control.ControlEndpoints(
        control.broker_handlers(server.broker, watch.lock_now), group
    )
    try:
        control_server.start()
    except OSError as exc:
        watch.set()
        vault.lock()
        raise click.ClickException(f"Cannot open the control channel: {exc}")
    # A brake pulled on the phone arrives through the sync server.
    from .mcp.remote_policy import RemotePolicyPoller

    poller = RemotePolicyPoller(vault, server.broker)
    server.broker.remote_policy = poller
    poller.start()
    if not vault.is_unlocked:
        click.echo(
            "Vault is locked: MCP tool calls return vault_locked until 'sezam unlock'.",
            err=True,
        )
    try:
        if transport == "stdio":
            click.echo("MCP server running on stdio (JSON-RPC). Send JSON-RPC messages on stdin.", err=True)
            server.run_stdio()
        elif transport == "socket":
            if socket_path is None:
                socket_path = SezamMCPServer.default_socket_path()
            click.echo(f"MCP server running on {socket_path}", err=True)
            server.run_socket(socket_path, group)
    finally:
        poller.stop()
        control_server.stop()
        watch.set()
        server.stop()
        vault.lock()


@main.command("ssh-agent")
@click.option(
    "--approval-ui/--deny-tier1",
    default=True,
    help="Show a local confirmation dialog before a Tier 1 signature, or refuse it.",
)
@click.option(
    "--idle-lock-minutes",
    type=click.IntRange(1, 24 * 60),
    default=30,
    show_default=True,
    help="Lock the vault after this many minutes without a signature request.",
)
@click.option(
    "--grant-minutes",
    type=click.IntRange(0, 8 * 60),
    default=10,
    show_default=True,
    help="After a Tier 1 approval, offer to allow the same entry, host and user "
    "for this many minutes (0 = never offer).",
)
@click.option(
    "--print-config",
    is_flag=True,
    help="Print ssh_config blocks for the entries the agent serves and exit.",
)
@click.option("--group", default=None, help=_GROUP_HELP)
def ssh_agent(
    approval_ui: bool,
    idle_lock_minutes: int,
    grant_minutes: int,
    print_config: bool,
    group: Optional[str],
):
    """Run an SSH agent whose private keys never leave the vault.

    Lists only keys of entries whose MCP policy allows 'ssh_agent' and signs
    only SSH logins as the entry's username. Point clients at it with
    'IdentityAgent' or SSH_AUTH_SOCK. Follows the CLI session like
    mcp-serve; 'sezam ai off' and 'sezam lock' stop it signing.

    Limitation: once logged in, the AI has a shell and could add its own key
    to ~/.ssh/authorized_keys, bypassing Sezam from then on. Use a dedicated
    account and 'AuthorizedKeysFile none' with Sezam SSH certificates where
    that matters.
    """
    import threading

    from .mcp import control
    from .mcp.approval import ApprovalManager
    from .mcp.broker import MCPBroker
    from .mcp.ssh_agent import (
        AUTHORIZED_KEYS_LIMITATION,
        SSHAgentServer,
        SSHAgentService,
        client_config,
    )
    from .vault import ai_access

    _harden_broker_process()
    vault = _open_vault()
    if print_config:
        kek = _load_session()
        if kek is not None:
            try:
                vault.unlock_with_kek(kek)
            except ValueError:
                pass
            finally:
                kek[:] = b"\x00" * len(kek)
        if not vault.is_unlocked:
            _unlock_vault(vault)
        try:
            click.echo(client_config(MCPBroker(vault, ApprovalManager())), nl=False)
        finally:
            vault.lock()
        return
    if not ai_access.read_state(vault).enabled:
        raise click.ClickException(
            "AI access is turned off. Run 'sezam ai on' (master password) first."
        )
    approvals = ApprovalManager()
    if approval_ui:
        from .mcp.approval import install_desktop_approval_handler

        install_desktop_approval_handler(approvals)
    else:
        approvals.set_on_request(lambda request: approvals.deny(request.request_id))
    broker = MCPBroker(vault, approvals)

    last_activity = [time.monotonic()]

    def mark_active() -> None:
        last_activity[0] = time.monotonic()

    service = SSHAgentService(broker, on_activity=mark_active, grant_minutes=grant_minutes)

    def on_lock() -> None:
        service.clear_grants()
        broker.close()

    watch = _watch_session_and_lock(
        vault,
        on_lock,
        idle_seconds=lambda: time.monotonic() - last_activity[0],
        idle_limit=idle_lock_minutes * 60,
        on_unlock=mark_active,
        on_tick=broker.enforce_kill_switch,
    )
    control_server = control.ControlEndpoints(control.broker_handlers(broker, watch.lock_now), group)
    agent_server = SSHAgentServer(service, group=group)
    try:
        control_server.start()
        try:
            agent_server.start()
        except OSError:
            control_server.stop()
            raise
    except OSError as exc:
        watch.set()
        vault.lock()
        raise click.ClickException(f"Cannot start the SSH agent: {exc}")
    from .mcp.remote_policy import RemotePolicyPoller

    poller = RemotePolicyPoller(vault, broker)
    broker.remote_policy = poller
    poller.start()
    click.echo(f"Sezam SSH agent running on {agent_server.path}", err=True)
    click.echo(f"  IdentityAgent {agent_server.path}", err=True)
    click.echo(f"Note: {AUTHORIZED_KEYS_LIMITATION}", err=True)
    if not vault.is_unlocked:
        click.echo("Vault is locked: no keys are offered until 'sezam unlock'.", err=True)
    stopped = threading.Event()
    try:
        while not stopped.wait(1.0):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        poller.stop()
        agent_server.stop()
        control_server.stop()
        watch.set()
        broker.close()
        vault.lock()


@main.command("ai-host-setup")
@click.option("--entry", "path", required=True, help="Path of the AI SSH CA entry, e.g. Servers/Web-AI.")
@click.option("--web-root", default=None, help="Directory the AI account may change (group-writable).")
@click.option(
    "--sudo-command",
    default=None,
    help="Allow exactly this one command as root via sudo, e.g. '/bin/systemctl reload nginx'.",
)
def ai_host_setup(path: str, web_root: Optional[str], sudo_command: Optional[str]):
    """Print (never run) the commands that prepare a server for an AI account
    that logs in only with short-lived certificates from a Sezam SSH CA
    entry: dedicated user without sudo, no cron/at/linger, the CA public key
    and principal, and an sshd Match block with 'AuthorizedKeysFile none'.
    'sezam ai off' then makes the CA stop signing; issued certificates
    expire within their TTL."""
    from .mcp.host_setup import HostSetupError, host_setup_script

    vault = _open_vault()
    _unlock_vault(vault)
    try:
        entry = vault.find_entry_by_path(path)
        if entry is None:
            raise click.ClickException(f"Entry not found: {path}")
        try:
            script = host_setup_script(entry, path, web_root=web_root, sudo_command=sudo_command)
        except HostSetupError as exc:
            raise click.ClickException(str(exc)) from None
    finally:
        vault.lock()
    click.echo(script, nl=False)


@main.group("broker")
def broker_group():
    """Run the AI broker as its own OS user (isolation level L2)."""


@broker_group.command("install-service")
@click.option(
    "--platform",
    "target",
    type=click.Choice(["linux", "windows"]),
    default=lambda: "windows" if sys.platform == "win32" else "linux",
    help="Print for this platform (default: the current one).",
)
@click.option("--user", default="sezam-broker", show_default=True, help="OS user of the broker.")
@click.option("--group", default="sezam-ai", show_default=True, help="Group of the agents.")
@click.option(
    "--agent-user",
    default=lambda: getpass.getuser(),
    help="User the AI agent runs as (default: you).",
)
@click.option("--python", "python", default=sys.executable, help="Python with Sezam installed.")
def broker_install_service(target: str, user: str, group: str, agent_user: str, python: str):
    """Print (never run) the commands and service definitions for an L2
    broker: 'sezam ssh-agent' and 'sezam mcp-serve' as their own OS user,
    the vault readable only by it, the agent's user in a group that may use
    the sockets and pull the brake but not lock, unlock or turn AI on."""
    from .mcp import service

    printer = service.windows if target == "windows" else service.systemd
    try:
        text = printer(python, user, group, agent_user)
    except ValueError as exc:
        raise click.ClickException(str(exc))
    click.echo(text, nl=False)


@main.group("ai")
def ai_group():
    """AI access kill switch: off (no password), on (master password), status."""


@ai_group.command("off")
@click.option(
    "--terminate-remote", is_flag=True,
    help="Also kill the sessions the AI opened through 'sezam ssh-agent' "
         "(every other session of that server account; asks for the master "
         "password after the brake if no CLI session is open).",
)
def ai_off(terminate_remote: bool):
    """Turn AI access off at once. Needs no password."""
    from .mcp import control

    if not _has_local_vault():
        # A member of an L2 broker's group: only the brokers can persist it.
        replies = control.send_all("ai_off")
        stopped = sum(
            1 for _, r in replies if r and r.get("status") == "ok" and r.get("persisted")
        )
        if not stopped:
            raise click.ClickException(
                f"No vault here and no running broker confirmed the brake "
                f"({len(replies)} found in {control.run_dir()})."
            )
        click.echo(f"AI access is OFF: {stopped} running broker(s) stopped and saved it.")
        if len(replies) > stopped:
            click.echo(f"{len(replies) - stopped} broker(s) did not confirm.", err=True)
        return
    vault = _open_vault()
    # With a live CLI session an audit record written here goes in now;
    # otherwise it is queued for the next unlock. The brake never prompts.
    kek = _load_session()
    if kek is not None:
        try:
            vault.unlock_with_kek(kek)
        except ValueError:
            pass
        finally:
            kek[:] = b"\x00" * len(kek)
    try:
        result = control.pull_brake(vault, "cli")
        if terminate_remote and not vault.is_unlocked:
            _unlock_vault(vault)  # only after the brake: it never waits on a prompt
        remote = _ai_off_remote_logins(vault, terminate_remote) if vault.is_unlocked else None
    finally:
        vault.lock()
    message = f"AI access is OFF (epoch {result.state.epoch})."
    if result.stopped:
        message += f" {result.stopped} running MCP server(s) stopped."
    click.echo(message)
    if result.unanswered:
        click.echo(
            f"{result.unanswered} MCP server(s) did not answer; they close their "
            "sessions within seconds.",
            err=True,
        )
    if result.unanchored:
        click.echo(
            f"The 'off' is not anchored on the sync server ({result.unanchored}). Until it is, "
            "a program running as your OS user could write back an earlier 'on'. With a CLI "
            "session open (sezam unlock) or a running 'sezam mcp-serve' it is anchored; "
            "run 'sezam ai off' again then.",
            err=True,
        )
    if remote is None:
        click.echo(
            "SSH logins the AI made through 'sezam ssh-agent' are not ended by this; "
            "with a CLI session open (sezam unlock) 'sezam ai off' lists them and "
            "'--terminate-remote' ends them.",
            err=True,
        )
    elif remote:
        click.echo("SSH logins through 'sezam ssh-agent' since AI access was turned on:", err=True)
        for target, outcome in remote:
            click.echo(f"  {target}: {outcome}", err=True)


def _ai_off_remote_logins(vault: Vault, terminate: bool) -> list[tuple[str, str]]:
    """Review d615826: a shell the AI opened through the agent outlives the brake."""
    from .mcp import agent_sessions

    out = []
    for login in agent_sessions.agent_logins(vault):
        if terminate:
            outcome = agent_sessions.terminate(vault, login)
        elif login.certificate:
            outcome = "may still be open (certificate: the host's reaper ends it when it expires)"
        else:
            outcome = "may still be open ('sezam ai off --terminate-remote' kills it)"
        out.append((login.target, outcome))
    return out


@ai_group.command("on")
def ai_on():
    """Turn AI access on again. Always asks for the master password."""
    from .vault import ai_access

    vault = _open_vault()
    _unlock_vault_fresh(vault, "Master password (required to turn AI access on): ")
    try:
        state = ai_access.enable(vault, "cli")
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        vault.lock()
    click.echo(f"AI access is ON (epoch {state.epoch}).")


@ai_group.command("status")
def ai_status():
    """Show whether AI access is on, the running MCP servers with their SSH
    sessions, and every entry an AI agent can reach and what it may do."""
    from .mcp import control
    from .mcp.approval import ApprovalManager, visible_text
    from .mcp.broker import MCPBroker
    from .vault import ai_access

    local = _has_local_vault()
    if local:
        vault = _open_vault()
        state = ai_access.read_state(vault)
        click.echo(f"AI access: {'ON' if state.enabled else 'OFF'} (epoch {state.epoch})")
    else:
        click.echo(f"No vault for this user: brokers in reach in {control.run_dir()} only.")

    servers = [reply for _, reply in control.send_all("status") if reply and reply.get("status") == "ok"]
    sessions = [s for reply in servers for s in reply.get("sessions") or [] if isinstance(s, dict)]

    rows = None
    if local:
        kek = _load_session()
        if kek is not None:
            try:
                vault.unlock_with_kek(kek)
            except ValueError:
                pass
            finally:
                kek[:] = b"\x00" * len(kek)
        if not vault.is_unlocked and sys.stdin.isatty():
            _unlock_vault(vault)
        try:
            if vault.is_unlocked:
                rows = MCPBroker(vault, ApprovalManager()).access_overview()
        finally:
            vault.lock()
    paths = {row["id"]: row["path"] for row in rows or []}

    click.echo(f"Running MCP servers: {len(servers)}")
    for reply in servers:
        click.echo(
            f"  pid {reply.get('pid')}: AI {reply.get('ai_access')}, vault "
            f"{'unlocked' if reply.get('vault_unlocked') else 'locked'}, "
            f"{reply.get('ssh_sessions', 0)} SSH session(s), "
            f"remote brake: {visible_text(str(reply.get('remote_policy', '?')))}"
        )
        for s in reply.get("sessions") or []:
            if not isinstance(s, dict):
                continue
            where = paths.get(s.get("entry_id"), f"entry {s.get('entry_id')}")
            click.echo(
                f"    {visible_text(str(where))}  agent {visible_text(str(s.get('agent')))}  "
                f"open {_minutes(s.get('open_seconds'))}, idle {_minutes(s.get('idle_seconds'))}"
            )
    if not sessions:
        click.echo("SSH sessions: none")

    if not local:
        return
    if rows is None:
        click.echo("Entries: run 'sezam unlock' first to list what AI agents can reach.")
        return
    click.echo(f"Entries an AI agent can reach: {len(rows)}")
    if not rows:
        return
    table = [(
        "PATH", "TIER", "ACTIONS", "READ_SECRET", "LOCAL_ROOT", "REMOTE_ROOT", "MAX_SESSION_MIN"
    )]
    for row in rows:
        table.append((
            visible_text(row["path"]),
            f"{row['tier']} ({'auto' if row['tier'] == 0 else 'approval'})",
            ",".join(row["actions"]) or "-",
            "yes" if row["read_secret"] else "no",
            visible_text(row["local_root"]) if row["local_root"] else "(default)",
            visible_text(row["remote_root"]) if row["remote_root"] else "(any)",
            str(row["max_session_minutes"]),
        ))
    widths = [max(len(r[i]) for r in table) for i in range(len(table[0]))]
    for r in table:
        click.echo("  " + "  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())


@ai_group.command("log")
@click.option("--since", "since", default="24h", show_default=True,
              help="How far back: e.g. 30m, 1h, 7d.")
@click.option("--entry", "entry_path", default=None, help="Only records of this entry path.")
def ai_log(since, entry_path):
    """What AI agents did: time, agent, entry, action, command or paths,
    result, bytes, owner approvals and refusals, SSH agent signatures and
    the kill switch. Needs the unlocked vault (the details are encrypted)."""
    from .mcp import audit_view

    try:
        seconds = audit_view.parse_since(since)
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--since")
    vault = _open_vault()
    kek = _load_session()
    if kek is not None:
        try:
            vault.unlock_with_kek(kek)
        except ValueError:
            pass
        finally:
            kek[:] = b"\x00" * len(kek)
    if not vault.is_unlocked:
        if not sys.stdin.isatty():
            raise click.ClickException("The vault is locked: run 'sezam unlock' first.")
        _unlock_vault(vault)
    try:
        paths = audit_view.entry_paths(vault)
        records = list(audit_view.ai_records(vault, int((time.time() - seconds) * 1000)))
    finally:
        vault.lock()
    if entry_path is not None:
        wanted = entry_path.strip("/").lower()
        ids = {i for i, p in paths.items() if p.lower() == wanted}
        if not ids:
            raise click.ClickException(f"No entry at {entry_path!r}.")
        records = [r for r in records if (r.detail or {}).get("entry_id") in ids]
    if not records:
        click.echo(f"No AI activity in the last {since}.")
        return
    for line in audit_view.format_log(records, paths):
        click.echo(line)


def _minutes(seconds) -> str:
    if not isinstance(seconds, int) or seconds < 0:
        return "?"
    return f"{seconds // 60} min" if seconds >= 60 else f"{seconds} s"


def _watch_session_and_lock(
    vault: Vault,
    on_lock,
    interval: float = 2.0,
    idle_seconds=None,
    idle_limit: Optional[float] = None,
    on_unlock=None,
    on_tick=None,
):
    """Make a running MCP server follow the CLI session.

    A valid session unlocks the vault (checked once immediately, then every
    ``interval``); when the session ends ('sezam lock' or expiry) or, with
    ``idle_seconds``/``idle_limit``, after that long without a tool call, the
    vault is locked and ``on_lock`` closes the SSH sessions. After an idle
    lock, or ``lock_now()`` (the control channel's ``lock``), only a new
    session (a fresh 'sezam unlock') unlocks it again. ``on_tick`` runs
    first on every tick (the kill switch backstop).

    Returns a handle: ``set()`` stops watching, ``lock_now()`` locks.
    """
    import threading

    stop = threading.Event()
    mutex = threading.RLock()
    state: dict = {"session": None, "spent": None}

    def lock(reason: str) -> None:
        # Cut the agent's live SSH sessions first: once the vault reads as
        # locked, nothing opened under the old unlock may still be running.
        on_lock()
        vault.lock()
        state["session"] = None
        click.echo(f"{reason}: MCP server locked.", err=True)

    def tick() -> None:
        with mutex:
            if on_tick is not None:
                on_tick()
            _tick()

    def lock_now() -> None:
        with mutex:
            loaded = _load_session_record()
            if loaded is not None:
                kek, session_id = loaded
                kek[:] = b"\x00" * len(kek)
                state["spent"] = session_id
            if vault.is_unlocked:
                lock("Lock requested")
            else:
                on_lock()

    def _tick() -> None:
        loaded = _load_session_record()
        if vault.is_unlocked:
            if loaded is None:
                lock("Session ended")
            elif idle_limit is not None and idle_seconds() > idle_limit:
                state["spent"] = loaded[1]
                lock("Idle timeout")
            else:
                state["session"] = loaded[1]  # a renewed session is adopted
        if loaded is None:
            return
        kek, session_id = loaded
        try:
            if vault.is_unlocked or session_id == state["spent"]:
                return
            try:
                vault.unlock_with_kek(kek)
            except ValueError:
                _clear_session()
                click.echo("The session is stale: run 'sezam unlock' again.", err=True)
                return
            state["session"] = session_id
            if on_unlock is not None:
                on_unlock()
            click.echo("Session active: MCP server unlocked.", err=True)
        finally:
            kek[:] = b"\x00" * len(kek)

    def watch() -> None:
        while not stop.wait(interval):
            try:
                tick()
            except Exception:
                logger.exception("MCP session watcher failed; locking")
                with mutex:
                    if vault.is_unlocked:
                        lock("Watcher error")

    tick()
    threading.Thread(target=watch, name="sezam-session-watch", daemon=True).start()
    return _SessionWatch(stop.set, lock_now)


class _SessionWatch:
    def __init__(self, stop, lock_now):
        self.set = stop
        self.lock_now = lock_now


# ── Helper functions ──


def _parse_expiry(expires: str) -> int:
    """Parse expiry string to Unix ms timestamp."""
    now_ms = int(time.time() * 1000)
    if expires.endswith("h"):
        return now_ms + int(expires[:-1]) * 3600 * 1000
    elif expires.endswith("d"):
        return now_ms + int(expires[:-1]) * 86400 * 1000
    elif expires.endswith("m"):
        return now_ms + int(expires[:-1]) * 60 * 1000
    return now_ms + 86400 * 1000  # default 24h


def _format_timestamp(ts_ms: int) -> str:
    """Format a Unix ms timestamp for display."""
    if not ts_ms:
        return "?"
    try:
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(ts_ms)


def _copy_to_clipboard(text: str) -> None:
    """Copy text to clipboard with auto-clear after 15s."""
    try:
        import subprocess
        if sys.platform == "win32":
            subprocess.run(
                ["clip"],
                input=text.encode("utf-16le"),
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        elif sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
        else:
            subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(), check=True)

        # Schedule clipboard clear after 15s (best effort)
        _schedule_clipboard_clear()
    except Exception:
        click.echo("Could not copy to clipboard.", err=True)


def _schedule_clipboard_clear() -> None:
    """Schedule clipboard clear after 15s (background process)."""
    import subprocess
    if sys.platform == "win32":
        subprocess.Popen(
            ["cmd", "/c", "timeout /t 15 /nobreak >nul && echo.|clip"],
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
        )
    elif sys.platform == "darwin":
        subprocess.Popen(["bash", "-c", "sleep 15 && echo -n '' | pbcopy"])
    else:
        subprocess.Popen(["bash", "-c", "sleep 15 && echo -n '' | xclip -selection clipboard"])


from . import cli_team_log  # noqa: E402,F401  (registers 'sezam team-log')

if __name__ == "__main__":
    main()
