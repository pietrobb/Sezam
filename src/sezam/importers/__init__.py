"""Import modules for various password manager formats."""


def import_entry(
    vault,
    node_id,
    name,
    fields,
    tier=None,
    conflict_mode="duplicate",
    tags=None,
    claimed=None,
) -> bool:
    """Create or update one entry according to the import conflict policy.

    ``claimed`` (one set per import run) holds the ids this run already
    matched or created. An imported item is matched only against an entry
    with its name that no earlier item of the run took, so two items with
    the same name in one folder never collapse into one entry (lockout
    review M3): the second one is created, or matches a second existing
    entry of that name.
    """
    if conflict_mode not in {"skip", "overwrite", "duplicate"}:
        raise ValueError(f"Unsupported import conflict mode: {conflict_mode}")
    if claimed is None:
        claimed = set()

    existing = None
    if conflict_mode != "duplicate":
        existing = min(
            (
                entry["id"]
                for entry in vault.list_entries(node_id)
                if entry["name"].casefold() == name.casefold() and entry["id"] not in claimed
            ),
            default=None,
        )
    if existing and conflict_mode == "skip":
        claimed.add(existing)
        return False
    if existing and conflict_mode == "overwrite":
        vault.update_entry(existing, name=name, fields=fields, tier=tier, tags=tags)
        claimed.add(existing)
        return True

    claimed.add(vault.create_entry(node_id, name, fields, tier=tier, tags=tags))
    return True
