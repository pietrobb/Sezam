"""``sezam team-log``: the organisation's signed team log (docs/DESIGN_TEAM_LOG.md §7, §9)."""

from __future__ import annotations

from typing import Optional

import click

from . import teamlog
from .teamlog import TeamLogError
from . import cli
from .cli import main


def _connected(vault):
    if not vault.db.get_meta("server_url") or not vault.db.get_meta("user_id"):
        raise click.ClickException("This vault is not connected to a server")
    client = cli._conflict_client(vault)
    client.authenticate()
    return client


def _founder(client) -> tuple[str, list[str]]:
    """Fingerprints linked to the founder by verified, two-key rotations."""
    from .crypto.keys import compute_fingerprint
    from .vault.team_log_local import founder_key_lineage

    founder_id, keys = founder_key_lineage(client._db)
    fingerprints = sorted(
        compute_fingerprint(bytes.fromhex(spk), bytes.fromhex(epk)) for spk, epk in keys
    )
    return founder_id, fingerprints


@main.group("team-log")
def team_log_group():
    """The organisation's signed team log: members, folder access, folder keys."""


@team_log_group.command("status")
def team_log_status():
    """Show the team log this device follows and whether it is trusted here."""
    vault = cli._open_vault()
    cli._unlock_vault_fresh(vault)
    try:
        client = _connected(vault)
        client._refresh_team_log()
        state = client.team_state()
        if state is None:
            click.echo("This organisation has no team log yet (an admin starts it: 'sezam team-log init').")
            return
        founder_id, fingerprints = _founder(client)
        click.echo(f"Head: record {state.head_seq}, genesis {state.genesis_hash}")
        click.echo(f"Founded by {founder_id}, linked key fingerprints:\n  " + "\n  ".join(fingerprints))
        if client.team_log_trusted(state):
            click.echo("Trusted on this device.")
        else:
            click.echo(
                "NOT trusted on this device: compare the fingerprint with the founder's "
                "('sezam fingerprint' on their device), then 'sezam team-log confirm-founder FINGERPRINT'."
            )
        for user_id, member in sorted(state.members.items()):
            if member.active:
                recovery = "  org recovery named" if teamlog.recovery_key(state, user_id) else ""
                click.echo(f"  member {user_id}  {member.role}{recovery}")
        admins = [u for u in state.members if teamlog.is_admin(state, u)]
        if len(admins) == 1 and teamlog.recovery_key(state, admins[0]) is None:
            # Review 8595ec1 #3: losing the lone admin froze the organisation unnoticed.
            click.echo(
                f"WARNING: the only admin ({admins[0]}) has no org recovery named in the log; "
                "losing their devices and password freezes members, access and keys. "
                "The admin runs 'sezam org-recovery-setup' (then 'sezam push') or "
                "'sezam team-log hand-over USER_ID'."
            )
        for folder in sorted(state.folders):
            access = ", ".join(f"{u}:{lvl}" for u, lvl in sorted(state.access.get(folder, {}).items()))
            click.echo(f"  folder {folder}  key generation {len(state.folders[folder]) - 1}  {access}")
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        vault.lock()


@team_log_group.command("confirm-founder")
@click.argument("fingerprint")
def team_log_confirm_founder(fingerprint: str):
    """Trust the log once its founder's FINGERPRINT matches the one their device shows."""
    from .vault.sync_common import CONFIRMED_MEMBER_KEYS_META

    vault = cli._open_vault()
    cli._unlock_vault_fresh(vault)
    try:
        client = _connected(vault)
        client._refresh_team_log()
        if client.team_state() is None:
            raise click.ClickException("This organisation has no team log yet.")
        founder_id, fingerprints = _founder(client)
        actual = next((fp for fp in fingerprints if cli._same_fingerprint(fingerprint, fp)), None)
        if actual is None:
            raise click.ClickException(
                "The fingerprint is not linked to the founder's genesis identity. Nothing was confirmed."
            )
        confirmed = dict(vault.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {})
        confirmed[founder_id] = actual
        vault.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, confirmed)
        click.echo("The team log is trusted on this device.")
    finally:
        vault.lock()


@team_log_group.command("confirm-genesis")
@click.argument("anchor")
def team_log_confirm_genesis(anchor: str):
    """Pin ANCHOR: a genesis hash or invitation URL received from a trusted admin, not the server."""
    import re
    from urllib.parse import parse_qs, urlsplit
    from .vault.team_log_local import (
        CONFIRMED_GENESIS_META, FORGOTTEN_GENESIS_META, GENESIS_META, forgotten_genesis, local_team_state,
        readable_forgotten_genesis,
    )

    if "://" in anchor:
        values = parse_qs(urlsplit(anchor).fragment, keep_blank_values=True).get("g", [])
        anchor = values[0] if len(values) == 1 else ""
    if not re.fullmatch(r"[0-9a-f]{64}", anchor):
        raise click.BadParameter("Expected a 64-character lowercase genesis hash or invitation with #g=.")
    vault = cli._open_vault()
    cli._unlock_vault_fresh(vault)
    try:
        with vault.db.transaction(immediate=True):
            if readable_forgotten_genesis(vault.db) is None:
                # INV-7 (capability run 411): the way out of an unreadable list.
                vault.db.execute("DELETE FROM vault_meta WHERE key = ?", (FORGOTTEN_GENESIS_META,))
            state = local_team_state(vault.db)
            pins = [vault.db.get_meta(CONFIRMED_GENESIS_META), vault.db.get_meta(GENESIS_META),
                    state.genesis_hash if state is not None else None]
            if any(pin is not None and pin != anchor for pin in pins):
                raise click.ClickException(
                    "The anchor conflicts with this device's existing pin. Nothing was changed. "
                    "(A team log lost for good: 'sezam team-log forget-pin' first.)"
                )
            vault.db.set_meta(CONFIRMED_GENESIS_META, anchor)
            forgotten = forgotten_genesis(vault.db)
            if anchor in forgotten:
                vault.db.set_meta_json(FORGOTTEN_GENESIS_META, [g for g in forgotten if g != anchor])
        click.echo("Genesis anchor confirmed on this device; the next pull must match it.")
    finally:
        vault.lock()


@team_log_group.command("forget-pin")
@click.argument("genesis", nargs=-1)
def team_log_forget_pin(genesis: tuple[str, ...]):
    """Leave the team log this device pins: GENESIS is its genesis hash (16+ characters),
    every one of them when the account keys name another than this device holds.

    Only for a team log lost for good (the server moved, was reseeded, or kept
    no restore): the device drops its pin and its copy of that log, and follows
    the server's log once its founder is confirmed again. Without GENESIS it
    shows the pinned one.
    """
    from .vault.team_log_forget import forget_team_log_pin, pinned_genesis
    from .vault.team_log_local import RISK_MARKER

    vault = cli._open_vault()
    cli._unlock_vault_fresh(vault)
    try:
        pins = pinned_genesis(vault)
        if not pins:
            click.echo("This device pins no team log.")
            return
        if not genesis:
            click.echo("Pinned genesis: " + ", ".join(sorted(pins)))
            click.echo("To leave it for good: 'sezam team-log forget-pin GENESIS...'.")
            return
        click.echo(
            f"{RISK_MARKER} a hostile server can drop the team's log or serve a new genesis on purpose to make "
            "you forget the pin. Go on only if your admin confirmed out of band that the log is lost for good.\n"
            "This device then no longer insists on that team log: whatever log the server has next is "
            "new to it, and nothing from it is trusted until you confirm its founder's fingerprint."
        )
        if not click.confirm("Forget the pinned team log on this device?", default=False):
            raise click.ClickException("Nothing was changed.")
        try:
            left = forget_team_log_pin(vault, " ".join(genesis), _connected(vault))
        except (ValueError, RuntimeError) as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo("Forgot " + ", ".join(sorted(left)) + ". Next: 'sezam pull', then "
                   "'sezam team-log status' and 'sezam team-log confirm-founder FINGERPRINT'.")
    finally:
        vault.lock()


@team_log_group.command("publish-anchor")
def team_log_publish_anchor():
    """Store the genesis trusted here in your encrypted account keys, for new devices.

    A new browser, phone or desktop of this account then trusts the same log
    without asking the server. Sent together with a NEW master password (one
    epoch-advancing push): with the same password the server could still hand
    a new device the account's older salt and keys without the genesis, and
    they would open. A log not trusted on this device is never published.
    """
    import sys
    import time

    from .vault.snapshots import SnapshotError
    from .vault.sync_client import SyncClient
    from .vault.team_log_local import publishable_anchor

    vault = cli._open_vault()
    server_url = vault.db.get_meta("server_url")
    if not server_url or not vault.db.get_meta("user_id"):
        raise click.ClickException("This vault is not connected to a server")
    cli._check_rate_limit()
    password = cli._get_password("Master password: ")
    try:
        vault.unlock(password)
    except ValueError:
        cli._record_failed_attempt()
        click.echo("Wrong master password.", err=True)
        time.sleep(2)
        sys.exit(1)
    cli._clear_failed_attempts()
    click.echo("The genesis is published together with a new master password.")
    click.echo("Choose one never used for this account before, on any device: an older one may"
               " still open keys the server kept without the genesis.")
    new_password = cli._get_new_password(vault)
    if new_password == password:
        vault.lock()
        raise click.ClickException(
            "The new password must differ: under the same password the server could "
            "still give a new device the older keys without the genesis. Nothing was published."
        )

    def _client() -> SyncClient:
        client = SyncClient(vault.db, server_url, vault.keypair, vault.db.get_meta("user_id"))
        client.set_dek_manager(vault.dek_mgr)
        return client

    auth_proof = None
    server_error = None
    try:
        try:
            _client().prepare_key_change()
        except RuntimeError as exc:
            raise click.ClickException(f"Server sync failed; nothing was published: {exc}") from exc
        anchor = publishable_anchor(vault.db, vault.db.get_meta("user_id"), vault.keypair)
        if anchor is None:
            raise click.ClickException(
                "The team log is not trusted on this device ('sezam team-log status'); nothing was published."
            )
        try:
            auth_proof = vault.change_password(password, new_password)
        except (SnapshotError, ValueError, RuntimeError) as exc:
            raise click.ClickException(f"{exc}; nothing was published") from exc
        try:
            _client().push()
        except RuntimeError as exc:
            server_error = exc
    finally:
        if auth_proof is not None:
            auth_proof[:] = b"\x00" * len(auth_proof)
        cli._clear_session()
        vault.lock()
    click.echo(f"Genesis {anchor} is stored in your encrypted account keys; unlock with the new password.")
    if server_error is not None:
        click.echo(
            f"Warning: the server was not updated yet ({server_error}). "
            "It is kept locally and sent by the next 'sezam push'.",
            err=True,
        )


@team_log_group.command("init")
@click.option(
    "--fingerprint", "fingerprints", multiple=True, metavar="USER_ID=FINGERPRINT",
    help="A member's key fingerprint as their device shows it; others not confirmed yet are asked",
)
def team_log_init(fingerprints: tuple[str, ...]):
    """Admin: start the team log from the organisation as it is now (one append).

    This account is its only admin (one admin per organisation for now). Every
    approved account with a confirmed key becomes a member, every shared
    folder's current key generation 0, and the envelopes this account sealed its
    access. Accounts left unconfirmed get nothing and are listed.
    """
    from .vault.team_migration import found_team_log

    given = {}
    for item in fingerprints:
        user_id, sep, fp = item.partition("=")
        if not sep:
            raise click.BadParameter(f"'{item}' is not USER_ID=FINGERPRINT", param_hint="--fingerprint")
        given[user_id] = fp

    def confirm(user_id: str, actual: str) -> bool:
        if user_id in given:
            return cli._same_fingerprint(given[user_id], actual)
        click.echo(f"Key fingerprint of account {user_id}:\n  {actual}")
        return click.confirm("Does it match the fingerprint the member's device shows?", default=False)

    def confirm_plan(plan) -> bool:
        click.echo("The team log will sign exactly this:")
        click.echo(f"  admin: {vault.db.get_meta('user_id')} (you)")
        for user_id in plan.members:
            click.echo(f"  member: {user_id}")
        for folder in plan.folders:
            try:
                name = vault.read_node(folder)["name"]
            except (KeyError, ValueError):
                name = folder
            levels = plan.access.get(folder, {})
            granted = ", ".join(f"{uid}={lvl}" for uid, lvl in sorted(levels.items())) or "nobody but you"
            click.echo(f"  folder {name} ({folder}): {granted}")
        for user_id in plan.unconfirmed:
            click.echo(f"  not added (key not confirmed): {user_id}")
        if plan.hidden:
            why = {"read": "only read access", "unconfirmed": "key not confirmed",
                   "no access": "no access from you"}
            click.echo(f"WARNING: {len(plan.hidden)} item(s) written before the log would be hidden "
                       "on every device (their author gets no write access there):")
            for h in plan.hidden:
                click.echo(f"  {h.kind} {h.item} by {h.author} in {h.folder}: {why[h.reason]}")
            click.echo("  They show again once the author has write access there "
                       "('sezam grant-access USER_ID FOLDER --write', after founding) or, for an "
                       "unconfirmed key, after confirming it (--fingerprint USER_ID=FINGERPRINT).")
        return click.confirm("Sign these members and rights?", default=False)

    vault = cli._open_vault()
    cli._unlock_vault_fresh(vault)
    try:
        client = _connected(vault)
        result = found_team_log(vault, client, confirm, confirm_plan=confirm_plan)
    except (RuntimeError, ValueError, TeamLogError) as exc:
        raise click.ClickException(f"The team log was not started: {exc}") from exc
    finally:
        vault.lock()
    click.echo(f"Team log started: {len(result.members)} member(s), "
               f"{len(result.folders)} shared folder(s).")
    for user_id in result.unconfirmed:
        click.echo(f"  not added (key not confirmed): {user_id}; add later with 'sezam team-log add-member'")
    for dek_id in result.not_founded:
        click.echo(f"  key {dek_id} is shared but is not a folder's current key: not in the log")
    if result.hidden:
        click.echo(f"  {len(result.hidden)} item(s) hidden until their author gets write access "
                   "('sezam grant-access USER_ID FOLDER --write').")
    click.echo("Members confirm your fingerprint ('sezam fingerprint') with 'sezam team-log confirm-founder'.")


def _describe(change) -> str:
    kind, data = change
    named = data.get("user_id") or data.get("folder") or ""
    return f"{kind} {named}".rstrip()


def _removal_drop_effect(vault, user_id: str) -> str:
    """What dropping a set-aside member.remove leaves (review 4acfdde R11, low).

    The re-key does not wait for the removal: once it ran, the folders it
    re-keyed are closed to the member even if the removal is dropped, while
    the account and the membership stay."""
    from .vault import pending_states

    me = vault.db.get_meta("user_id")
    text = (f"{user_id} stays an active member: the account still signs in and can be "
            "given folders again.")
    if user_id in pending_states.revocation_queue(vault.db) or (
        pending_states.rekey_batch(vault.db).get("revoked_user_id") == user_id
    ):
        return text + " The re-key queued for the removal still goes out with the next push."
    if vault.db.fetchone(
        "SELECT 1 FROM access_envelopes WHERE user_id = ? AND created_by = ?", (user_id, me)
    ):
        return text + " They keep the folders this device shared with them."
    return text + (" The folders re-keyed for the removal stay closed to them (they keep what "
                   "they synced before); share a folder again to give it back.")


@team_log_group.command("queue")
def team_log_queue():
    """List the team changes waiting for a push and those set aside as refused."""
    from .vault.team_log_local import queued_changes, set_aside_changes

    vault = cli._open_vault()
    cli._unlock_vault_fresh(vault)
    try:
        queued = queued_changes(vault.db)
        aside = set_aside_changes(vault.db)
    finally:
        vault.lock()
    click.echo(f"Waiting for the next push: {len(queued)}")
    for change in queued:
        click.echo(f"  {_describe(change)}")
    click.echo(f"Set aside (refused): {len(aside)}")
    for number, item in enumerate(aside, 1):
        click.echo(f"  {number}. {_describe(item['change'])}  ({item['reason']})")
    if aside:
        click.echo("'sezam team-log retry' queues them again; 'sezam team-log discard N' drops one.")


@team_log_group.command("retry")
def team_log_retry():
    """Queue the set-aside team changes again; the next push sends them."""
    from .vault.team_log_local import retry_set_aside

    vault = cli._open_vault()
    cli._unlock_vault_fresh(vault)
    try:
        count = retry_set_aside(vault.db)
    finally:
        vault.lock()
    click.echo(f"{count} team change(s) queued again; 'sezam push' sends them.")


@team_log_group.command("discard")
@click.argument("numbers", type=int, nargs=-1)
@click.option("--all", "discard_all", is_flag=True, help="Drop every set-aside team change")
def team_log_discard(numbers: tuple[int, ...], discard_all: bool):
    """Drop set-aside team changes by NUMBER ('sezam team-log queue' lists them)."""
    from .vault.team_log_local import discard_set_aside, set_aside_changes

    if not numbers and not discard_all:
        raise click.UsageError("Give the NUMBER(s) of the set-aside changes, or --all.")
    vault = cli._open_vault()
    cli._unlock_vault_fresh(vault)
    try:
        aside = set_aside_changes(vault.db)
        chosen = range(1, len(aside) + 1) if discard_all else numbers
        if any(n < 1 or n > len(aside) for n in chosen) or not aside:
            raise click.ClickException(f"There are {len(aside)} set-aside team change(s).")
        for n in chosen:
            item = aside[n - 1]
            click.echo(f"{n}. {_describe(item['change'])}  ({item['reason']})")
            if item["change"][0] == "member.remove":
                click.echo(f"   {_removal_drop_effect(vault, item['change'][1]['user_id'])}")
        click.confirm("Drop these team changes?", default=False, abort=True)
        dropped = discard_set_aside(vault.db, None if discard_all else list(numbers))
    finally:
        vault.lock()
    click.echo(f"{len(dropped)} team change(s) dropped.")


@team_log_group.command("add-member")
@click.argument("user_id")
@click.option("--fingerprint", "expected_fingerprint", default=None,
              help="The account's key fingerprint as their device shows it")
def team_log_add_member(user_id: str, expected_fingerprint: Optional[str]):
    """Admin: add an approved account to the team log (its key fingerprint confirmed)."""
    from .vault.team_migration import add_member

    def confirm(actual: str) -> bool:
        if expected_fingerprint is not None:
            return cli._same_fingerprint(expected_fingerprint, actual)
        click.echo(f"Key fingerprint of account {user_id}:\n  {actual}")
        return click.confirm("Does it match the fingerprint the member's device shows?", default=False)

    vault = cli._open_vault()
    cli._unlock_vault_fresh(vault)
    try:
        client = _connected(vault)
        add_member(vault, client, user_id, confirm)
    except (RuntimeError, ValueError, TeamLogError) as exc:
        raise click.ClickException(f"The member was not added: {exc}") from exc
    finally:
        vault.lock()
    click.echo(f"{user_id} is a member of the team log.")


@team_log_group.command("readmit")
@click.argument("user_id")
@click.option("--fingerprint", "expected_fingerprint", default=None,
              help="The member's NEW key fingerprint as their device shows it")
def team_log_readmit(user_id: str, expected_fingerprint: Optional[str]):
    """Admin: take member USER_ID back under the fresh keys their account rotated to.

    For a member the team log still names with keys nobody holds any more
    (a server restored from before their identity rotation, the device with
    the new key lost): 'sezam allow-key-reset USER_ID' here, then
    'sezam rotate-identity' on their device, then this. Their folders are
    re-keyed and granted again at the level they had.
    """
    from .vault.team_migration import readmit_member

    def confirm(actual: str) -> bool:
        if expected_fingerprint is not None:
            return cli._same_fingerprint(expected_fingerprint, actual)
        click.echo(f"New key fingerprint of account {user_id}:\n  {actual}")
        return click.confirm("Does it match the fingerprint the member's device shows?", default=False)

    vault = cli._open_vault()
    cli._unlock_vault_fresh(vault)
    try:
        client = _connected(vault)
        granted = readmit_member(vault, client, user_id, confirm)
    except (RuntimeError, ValueError, TeamLogError) as exc:
        raise click.ClickException(f"The member was not readmitted: {exc}") from exc
    finally:
        vault.lock()
    click.echo(f"{user_id} is back in the team log under the new keys; {granted} folder(s) granted again.")


@team_log_group.command("hand-over")
@click.argument("user_id")
@click.option("--fingerprint", "expected_fingerprint", default=None,
              help="The member's key fingerprint as their device shows it")
def team_log_hand_over(user_id: str, expected_fingerprint: Optional[str]):
    """Admin: make member USER_ID the organisation's admin; you become a member.

    The log has one admin. Hand the role over before that admin's devices and
    password could be lost, or the organisation can no longer change members,
    access or keys.
    """
    from .vault.team_migration import hand_over_admin

    def confirm(actual: str) -> bool:
        if expected_fingerprint is not None:
            return cli._same_fingerprint(expected_fingerprint, actual)
        click.echo(f"Key fingerprint of account {user_id} in the team log:\n  {actual}")
        return click.confirm("Does it match the fingerprint the member's device shows?", default=False)

    vault = cli._open_vault()
    cli._unlock_vault_fresh(vault)
    try:
        client = _connected(vault)
        hand_over_admin(vault, client, user_id, confirm)
    except (RuntimeError, ValueError, TeamLogError) as exc:
        raise click.ClickException(f"The admin role was not handed over: {exc}") from exc
    finally:
        vault.lock()
    click.echo(f"{user_id} is the team log's admin now; this account is a member.")
    click.echo("The new admin sets up org recovery on their device ('sezam org-recovery-setup').")
