"""R16-N19 (capability review run 638): a share a server without its log took
alone, that the log then will not take, is re-keyed away.

Saved seed TeamLogMachine@32 (R16-N16): admin device B shared folders with m6
while the server had lost its log; once B held the log again its next push put
the share in it (log_pre_log_grants). Here that step is refused, (a) by the
log's rules on B, (b) by the server. B kept no trace in (b) (its row was
deleted on the premise the grant was never shared) and only logged a warning in
(a); either way m6 kept a live envelope of the folder's current key the log
gives them no access to (INV-6). Now B notes the key and its handover re-key
replaces it in the same sync, and the push reports the share as withdrawn.
"""
import functools

from hypothesis import HealthCheck, settings
import pytest

from sezam import teamlog
from sezam.vault import pending_states, sync_client, trash
from tests import property_seeds
from tests.test_sync_state_machine import TeamLogMachine, loopback_server  # noqa: F401 - fixture


@pytest.mark.parametrize("refused_by", ["log", "server"])
def test_a_sent_pre_log_share_the_log_will_not_take_is_rekeyed(loopback_server, monkeypatch, refused_by):  # noqa: F811
    seed = next(s for s in property_seeds.load("test_sync_state_machine.py") if str(s) == "TeamLogMachine@32")
    cls = sync_client.SyncClient
    real_log, real_queue, real_send = cls.log_pre_log_grants, cls.queue_team_grant, cls._send_push
    real_init, real_after_settle = TeamLogMachine.__init__, TeamLogMachine._check_new_device_matches
    machines: list = []
    inside = {"pre": False}
    converted: set[str] = set()
    refused: list[tuple] = []  # (envelope_id, dek_id, user_id, folder, device db)

    def note_refused(client, envelope_id):
        row = client._db.fetchone("SELECT dek_id, user_id FROM access_envelopes WHERE id = ?", (envelope_id,))
        folder = client._db.fetchone("SELECT node_id FROM deks WHERE id = ?", (row["dek_id"],))["node_id"]
        refused.append((envelope_id, row["dek_id"], row["user_id"], folder, client._db))
        machine = machines[-1]  # the share is withdrawn: the run no longer counts it as granted
        machine.granted[row["user_id"]].discard(folder)
        machine.write_granted[row["user_id"]].discard(folder)

    def log_pre(self):
        inside["pre"] = True
        try:
            return real_log(self)
        finally:
            inside["pre"] = False

    def queue(self, envelope_id, changes):
        if inside["pre"]:
            if refused_by == "log":
                note_refused(self, envelope_id)
                raise teamlog.TeamLogError("refused_here", 0)
            converted.add(envelope_id)
        return real_queue(self, envelope_id, changes)

    def send(self, objects, *args, **kwargs):
        ids = sorted({o.get("id") for o in objects} & converted)
        if refused_by == "server" and kwargs.get("team_changes") and ids:
            for envelope_id in ids:
                converted.discard(envelope_id)
                note_refused(self, envelope_id)
            raise RuntimeError("Server error 400 (refused here)") from teamlog.TeamLogError("refused_here", 0)
        return real_send(self, objects, *args, **kwargs)

    def init(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        machines.append(self)

    def after_settle(self):  # the teardown's final settle is where B's next push runs
        check(self)
        real_after_settle(self)

    def check(machine):
        assert refused, "the run never reached a sent pre-log share"
        server = {o["id"]: o for o in machine.db._storage.get("vault_objects", [])}
        for envelope_id, dek_id, user_id, folder, db in refused:
            node = db.fetchone("SELECT dek_id FROM nodes WHERE id = ? AND is_deleted = 0", (folder,))
            obj = server.get(envelope_id)
            assert node is None or node["dek_id"] != dek_id, (
                f"{folder} is still on {dek_id}, which {user_id} holds through {envelope_id} "
                f"(live on the server: {obj is not None and not obj.get('is_deleted')})")
            assert db.fetchone("SELECT 1 FROM access_envelopes WHERE id = ?", (envelope_id,)) is None
            assert not pending_states.leaked_grant_keys(db, user_id)

    monkeypatch.setattr(cls, "log_pre_log_grants", log_pre)
    monkeypatch.setattr(cls, "queue_team_grant", queue)
    monkeypatch.setattr(cls, "_send_push", send)
    monkeypatch.setattr(TeamLogMachine, "__init__", init)
    monkeypatch.setattr(TeamLogMachine, "_check_new_device_matches", after_settle)
    TeamLogMachine.server = loopback_server
    property_seeds.replay_machine(
        TeamLogMachine, seed,
        settings(stateful_step_count=25, deadline=None, database=None, suppress_health_check=list(HealthCheck)),
    )


def test_a_withdrawn_share_of_a_deleted_folder_is_rekeyed_before_another_device_restores_it(
        loopback_server, monkeypatch):  # noqa: F811
    """Capability review run 652 (seed TeamLogMachine@36): B withdrew m6's share
    because its folder is deleted and only noted the key, to re-key once the
    folder is live on B. The note is B's alone: A restored the folder from its
    trash and pushed it while B did not sync, and m6's live envelope opened the
    folder's current key again (INV-6) until B's next sync. Now B's push that
    withdraws the share re-keys the deleted folder too; A's restore is on the
    new key (or refused on the old one) and m6's envelope is gone."""
    seed = next(s for s in property_seeds.load("test_sync_state_machine.py") if str(s) == "TeamLogMachine@36")
    real_note, real_inv = pending_states.note_leaked_grant, TeamLogMachine.an_envelope_goes_with_its_access
    noted: list[tuple] = []  # (dek_id, user_id, folder, db)
    done: list[str] = []

    def note(db, dek_id, user_id):
        folder = db.fetchone("SELECT node_id FROM deks WHERE id = ?", (dek_id,))["node_id"]
        noted.append((dek_id, user_id, folder, db))
        real_note(db, dek_id, user_id)

    @functools.wraps(real_inv)
    def inv(self):
        real_inv(self)
        if done or not noted:
            return
        dek_id, user_id, folder, db = noted[0]
        if not db.fetchone("SELECT 1 FROM nodes WHERE id = ? AND is_deleted = 1", (folder,)):
            return  # the case here is a deleted folder
        noter = next(name for name, dev in self.devices.items() if dev.vault.db is db)
        other = next((name for name in sorted(self.devices) if name != noter
                      and folder in {i["id"] for i in trash.list_trash(self.devices[name].vault)}), None)
        assert other, "no other device of the admin has the folder in its trash"
        done.append(other)
        self._local(other, f"restore folder {folder}", lambda v: trash.restore_node(v, folder))
        self._push(other, None)  # the device holding the note does not sync
        server = {o["id"]: o for o in self.db._storage.get("vault_objects", [])}
        assert not server[folder].get("is_deleted"), "the restore did not land"
        assert not [o["id"] for o in server.values() if o["object_type"] == "envelope" and not o.get("is_deleted")
                    and o.get("parent_ref") == dek_id and o.get("target_user_id") == user_id]
        node = self.devices[other].vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))
        assert node["dek_id"] != dek_id, f"{folder} came back on {dek_id}, which {user_id} may hold"
        real_inv(self)

    monkeypatch.setattr(pending_states, "note_leaked_grant", note)
    monkeypatch.setattr(TeamLogMachine, "an_envelope_goes_with_its_access", inv)
    monkeypatch.setattr(TeamLogMachine, "_setup_state_per_class", {})  # Hypothesis caches the invariants
    TeamLogMachine.server = loopback_server
    property_seeds.replay_machine(
        TeamLogMachine, seed,
        settings(stateful_step_count=25, deadline=None, database=None, suppress_health_check=list(HealthCheck)),
    )
    assert done, "the run never withdrew a share of a deleted folder"


class _Db:
    """The calls pending_states makes: meta, and whether a key or a node on it exists."""

    def __init__(self):
        self.meta, self.deks, self.nodes = {}, set(), set()

    def get_meta_json(self, key):
        return self.meta.get(key)

    def set_meta_json(self, key, value):
        self.meta[key] = value

    def fetchone(self, sql, args):
        return 1 if args[0] in (self.deks if "FROM deks" in sql else self.nodes) else None


def test_a_leak_note_is_kept_while_its_key_is_known():
    """Capability review runs 642/652: a note is not lost with the next note,
    and it names its key for the re-key while any folder here, a deleted one
    too, is on it."""
    db = _Db()
    db.deks |= {"k1", "k2"}
    pending_states.note_leaked_grant(db, "k1", "m6")
    pending_states.note_leaked_grant(db, "k2", "m7")
    assert pending_states.leaked_grant_keys(db) == {}  # no folder here on either key
    db.nodes.add("k1")  # a folder on k1, live or deleted
    assert pending_states.leaked_grant_keys(db) == {"k1": ["m6"]}
    db.deks.discard("k2")
    pending_states.note_leaked_grant(db, "k1", "m8")
    assert db.meta[pending_states.LEAKED_GRANTS_META] == {"k1": ["m6", "m8"]}
