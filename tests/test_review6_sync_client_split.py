"""Review d615826 R6-H: sync_client.py (5383+ lines) is split into push/pull/resync/rekey modules.

SyncClient keeps its public surface: it is composed of mixins, every method is
defined exactly once, and the names callers import from sync_client still come
from there.
"""

from pathlib import Path

from sezam.vault import sync_client

VAULT = Path(sync_client.__file__).parent
SPLIT = ["sync_client", "sync_common", "sync_push", "sync_rekey", "sync_pull",
         "sync_apply", "sync_resync", "sync_state", "sync_writers", "team_log_local"]
MAX_LINES = 1300


def test_no_sync_module_grows_back_past_the_limit():
    sizes = {
        name: len((VAULT / f"{name}.py").read_text(encoding="utf-8").splitlines())
        for name in SPLIT
    }
    assert all(size <= MAX_LINES for size in sizes.values()), sizes


def test_sync_client_is_composed_of_the_split_modules():
    modules = {cls.__module__ for cls in sync_client.SyncClient.__mro__ if cls is not object}
    assert modules == {f"sezam.vault.{name}" for name in SPLIT if name != "sync_common"}


def test_every_method_is_defined_once():
    owners: dict[str, list[str]] = {}
    for cls in sync_client.SyncClient.__mro__[:-1]:
        for name in vars(cls):
            if not (name.startswith("__") and name.endswith("__")):
                owners.setdefault(name, []).append(cls.__name__)
    twice = {name: classes for name, classes in owners.items() if len(classes) > 1}
    assert not twice


def test_names_callers_import_still_come_from_sync_client():
    for name in ("SyncClient", "KeyEpochStale", "TofuKeyChangeError", "SyncRollbackWarning",
                 "pull_warnings", "key_rotation_message", "compute_state_hash",
                 "unsent_envelope_count",
                 "CONFIRMED_MEMBER_KEYS_META", "SERVER_ROLLBACK_META", "COMMIT_ANCHOR_META",
                 "RESEED_ARCHIVES_META", "_CHECKPOINT_META_KEY", "open_current_auth_proof"):
        assert hasattr(sync_client, name), name
