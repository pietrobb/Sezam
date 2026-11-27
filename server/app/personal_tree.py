"""Who owns a personal tree (TL7, review 1141a20 R9-F).

A member's personal root is a top-level node: a member creates no other
top-level node (the push takes one only sealed with the member's own key).
So a top-level node of an account that is not and never was the admin is
that account's personal root, and its whole tree is theirs alone. The org
root belongs to the admin who made it, also after a handover (the log keeps
every record the former admin signed as admin).

``cache`` is the push's authority cache: node rows are shared with
``_has_write_authority`` under the same keys.
"""

from __future__ import annotations

from typing import Optional

from . import authority

_MAX_DEPTH = 64


async def node_row(cur, node_id: str, cache: dict) -> Optional[tuple]:
    """(owner_id, parent_ref) of a live node, or None."""
    key = ("node", node_id)
    if key not in cache:
        await cur.execute(
            "SELECT owner_id, parent_ref FROM vault_objects "
            "WHERE id = %s AND object_type = 'node' AND is_deleted = 0",
            (node_id,),
        )
        row = await cur.fetchone()
        cache[key] = tuple(row) if row else None
    return cache[key]


async def ever_admin(cur, user_id: str, cache: dict) -> bool:
    """Is ``user_id`` the admin, or did they sign anything as one in the team log?"""
    key = ("ever_admin", user_id)
    if key not in cache:
        await cur.execute("SELECT is_admin FROM users WHERE id = %s", (user_id,))
        row = await cur.fetchone()
        # No such account (the foreign key forbids it): no member's root either.
        # INV-1: the admin now is the log's; the users row only without a log.
        admin = row is None or await authority.team_admin(cur, user_id, cached=bool(row[0]))
        if not admin:
            # A member signs only their own member.keys; every other record
            # is an admin's. Review R17-R9s: gathered by the cached replay,
            # not parsed again from this account's records under the push lock.
            from . import team_log
            admin = user_id in await team_log.admin_authors(cur)
        cache[key] = admin
    return cache[key]


async def is_personal_root(cur, owner_id: str, cache: dict) -> bool:
    """Is a top-level node of ``owner_id`` that account's personal root?"""
    return not await ever_admin(cur, owner_id, cache)


async def tree_owner(cur, node_id: Optional[str], cache: dict) -> Optional[str]:
    """The account whose personal tree holds node ``node_id`` (the node included), or None."""
    current = node_id
    for _ in range(_MAX_DEPTH):
        if current is None:
            return None
        row = await node_row(cur, current, cache)
        if row is None:
            return None
        owner_id, parent_ref = row
        if parent_ref is None:
            return owner_id if await is_personal_root(cur, owner_id, cache) else None
        current = parent_ref
    return None
