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
from hypothesis import HealthCheck, settings
import pytest

from sezam import teamlog
from sezam.vault import pending_states, sync_client
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
