"""The team log in the Rust core (docs/CORE_UNIFICATION.md step U1).

The core replays in two runs: it names the signature checks, the client runs
them with its own libsodium (here PyNaCl) and the second run is told how
many passed. Checked against the shared vectors and, on random logs, against
the Python reference src/sezam/teamlog.py, which it replaces.
"""

import json
import random

import pytest
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from sezam import teamlog
from sezam.vault import sync_core

from tests.team_log_vectors import VECTORS_PATH

SCENARIOS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["scenarios"]


def _passed(checks: list[dict]) -> int:
    for index, check in enumerate(checks):
        try:
            VerifyKey(bytes.fromhex(check["pk"])).verify(bytes.fromhex(check["message"]), bytes.fromhex(check["sig"]))
        except (BadSignatureError, ValueError):
            return index
    return len(checks)


def core_replay(records: list, state: dict | None = None) -> dict:
    checks = sync_core.call("team_log_replay", records=records, state=state)["checks"]
    return sync_core.call("team_log_replay", records=records, state=state, verified=_passed(checks))


def core_ask(state: dict, questions: list[tuple[str, list]]) -> list:
    return sync_core.call("team_log_ask", state=state, questions=[{"fn": n, "args": a} for n, a in questions])


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["name"] for s in SCENARIOS])
def test_every_vector_with_libsodium_checking_the_signatures(scenario):
    out = core_replay(scenario["records"])
    if "error" in scenario:
        assert {k: out["refused"][k] for k in ("code", "seq")} == scenario["error"]
        return
    questions = [("state_json", [])] + [(q["fn"], q["args"]) for q in scenario["questions"]]
    answers = core_ask(out["state"], questions)
    assert answers[0] == scenario["state"]
    assert answers[1:] == [q["answer"] for q in scenario["questions"]]


# ── random logs against the Python reference ─────────────────────────────

ULID = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ulid(prefix: str, n: int) -> str:
    return prefix + str(n).rjust(26 - len(prefix), "0")


class _Log:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.keys = {}  # user -> (signing key, encryption pk hex)
        self.users = [_ulid("01JM", i) for i in range(1, 5)]
        self.folders = [_ulid("01JF", i) for i in range(1, 3)]
        self.deks = [_ulid("01JD", i) for i in range(1, 7)]
        self.records: list[dict] = []
        self.state = teamlog.TeamState()
        self.by_pk: dict[str, SigningKey] = {}

    def key(self, user, fresh: bool = False):
        """The keys ``user`` signs with (``fresh``: sometimes new ones, for a member.add)."""
        if user not in self.keys or fresh and self.rng.random() < 0.6:
            self.keys[user] = (SigningKey.generate(), SigningKey.generate().verify_key.encode().hex())
        return self.keys[user]

    def pk(self, user):
        return self.key(user)[0].verify_key.encode().hex()

    def signer(self, user):
        """The key the log names for ``user`` when this test holds it, else its own."""
        member = self.state.members.get(user)
        held = self.keys.get(user)
        if member is not None and held and held[0].verify_key.encode().hex() != member.signing_pk:
            return self.by_pk.get(member.signing_pk, held[0])
        return self.key(user)[0]

    def data(self, kind):
        r = self.rng
        user = r.choice(self.users)
        if kind == "member.add":
            sk, enc = self.key(user, fresh=True)
            self.by_pk[sk.verify_key.encode().hex()] = sk
            return {"user_id": user, "signing_pk": sk.verify_key.encode().hex(), "encryption_pk": enc,
                    "role": r.choice(["admin", "member", "member"])}
        if kind == "member.role":
            return {"user_id": user, "role": r.choice(["admin", "member"])}
        if kind == "member.remove":
            return {"user_id": user}
        if kind == "folder.key":
            folder = r.choice(self.folders)
            gens = self.state.folders.get(folder, [])
            gen = len(gens) if r.random() < 0.85 else r.randrange(3)
            prev = gens[-1][0] if gens and r.random() < 0.9 else (None if r.random() < 0.5 else r.choice(self.deks))
            return {"folder": folder, "gen": gen, "dek_id": r.choice(self.deks), "prev_dek_id": prev}
        if kind == "access.set":
            return {"folder": r.choice(self.folders), "user_id": user, "level": r.choice(["read", "write", None])}
        if kind == "org.recovery":
            return {"recovery_pk": r.choice([None, SigningKey.generate().verify_key.encode().hex()])}
        if kind == "org.recovery.wrap":
            total = r.randrange(0, 5)
            return {"wrapped_kek": "ab" * 72, "key_epoch": r.randrange(3), "threshold": r.randrange(0, 4),
                    "total_shares": total}
        raise AssertionError(kind)

    def next_record(self):
        r = self.rng
        admins = [u for u in self.users if teamlog.is_admin(self.state, u)] if self.state.head_seq >= 0 else []
        if self.state.head_seq < 0:
            founder = self.users[0]
            body = teamlog.next_body(self.state, "genesis", founder, {
                "org": _ulid("01JG", 1), "user_id": founder, "signing_pk": self.pk(founder),
                "encryption_pk": self.key(founder)[1]})
            signer = self.key(founder)[0]
            self.by_pk[self.pk(founder)] = signer
        elif r.random() < 0.12:
            # a member rotates its own keys (or tries to)
            user = r.choice(self.users)
            old = self.signer(user)
            new_sk, new_enc = SigningKey.generate(), SigningKey.generate().verify_key.encode().hex()
            self.by_pk[new_sk.verify_key.encode().hex()] = new_sk
            if r.random() < 0.2:
                new_enc = self.pk(user)  # a key it holds already
            data = {"user_id": user, "signing_pk": new_sk.verify_key.encode().hex(), "encryption_pk": new_enc}
            proof_key = new_sk if r.random() < 0.9 else old
            data["new_key_sig"] = proof_key.sign(teamlog.new_key_message(
                self.state.head_hash, user, data["signing_pk"], new_enc)).signature.hex()
            body = teamlog.next_body(self.state, "member.keys", user if r.random() < 0.9 else r.choice(self.users), data)
            signer = old
            if r.random() < 0.9:
                self.keys[user] = (new_sk, new_enc)
        else:
            kind = r.choice(["member.add", "member.add", "member.role", "member.remove", "folder.key",
                             "folder.key", "access.set", "access.set", "access.set", "org.recovery",
                             "org.recovery.wrap"])
            author = r.choice(admins) if admins and r.random() < 0.85 else r.choice(self.users)
            body = teamlog.next_body(self.state, kind, author, self.data(kind))
            signer = self.signer(author)
        if r.random() < 0.05:
            body["v"] = 1
        if r.random() < 0.03:
            body["seq"] += 1
        record = teamlog.sign_record(body, signer)
        if r.random() < 0.03:
            record["sig"] = ("0" if record["sig"][0] != "0" else "1") + record["sig"][1:]
        if r.random() < 0.02:
            record["body"] = record["body"].replace('"v":2', '"v": 2')
        return record


def _questions(log: _Log) -> list[tuple[str, list]]:
    q = [("state_json", []), ("admin_policy_refusal", [])]
    for u in log.users:
        q += [("is_admin", [u]), ("recovery_key", [u]), ("recovery_wrap", [u]),
              ("signing_key_retired", [u, log.pk(u)])]
        for d in log.deks:
            q.append(("may_hold_key", [u, d]))
            q.append(("tombstone_refusal", [u, d]))
        for f in log.folders + [None]:
            for d in log.deks[:3] + [None]:
                for own in (False, True):
                    q.append(("item_refusal", [u, f or log.folders[0], f, d, own, False]))
                    q.append(("item_refusal", [u, "01JE0000000000000000000001", f, d, own, True]))
            for g in log.folders + [None]:
                q.append(("move_refusal", [u, f, g, False]))
                q.append(("move_refusal", [u, f, g, True]))
        for signer in log.users:
            for d in log.deks:
                enc = log.state.members[u].encryption_pk if u in log.state.members else "00" * 32
                for level in ("read", "write", None):
                    q.append(("envelope_valid", [signer, u, d, level, enc]))
                q.append(("superseded_envelope_valid", [signer, u, d, enc]))
    for f in log.folders:
        q += [("is_team_folder", [f]), ("current_key", [f]), ("is_stale", [f]), ("may_seal", [f]),
              ("key_recipients", [f])]
        for u in log.users:
            q.append(("may_write", [f, u]))
        for d in log.deks:
            q.append(("key_generation", [f, d]))
    return q


def _python_answer(state: teamlog.TeamState, name: str, args: list):
    if name == "state_json":
        return state.to_json()
    answer = getattr(teamlog, name)(state, *args)
    if name == "key_recipients":
        return [list(t) for t in answer]
    if name == "key_generation":
        return list(answer)
    return answer


@pytest.mark.parametrize("seed", range(40))
def test_random_logs_replay_and_answer_as_the_python_reference(seed):
    log = _Log(random.Random(seed))
    for _ in range(30):
        record = log.next_record()
        try:
            expected = teamlog.replay([record], log.state)
        except teamlog.TeamLogError as exc:
            expected = exc
        core_state = sync_core.call("team_log_replay", records=[], state=None, verified=0)["state"]
        out = core_replay(log.records + [record])
        if isinstance(expected, teamlog.TeamLogError):
            assert "refused" in out, (seed, record)
            assert (out["refused"]["code"], out["refused"]["seq"]) == (expected.code, expected.seq), (seed, record)
            continue
        log.records.append(record)
        log.state = expected
        core_state = out["state"]
        questions = _questions(log)
        answers = core_ask(core_state, questions)
        for (name, args), answer in zip(questions, answers):
            assert answer == _python_answer(log.state, name, args), (seed, len(log.records), name, args)


def test_the_core_replays_onto_a_state_it_gave_back():
    scenario = next(s for s in SCENARIOS if "error" not in s and len(s["records"]) > 3)
    whole = core_replay(scenario["records"])["state"]
    first = core_replay(scenario["records"][:2])["state"]
    assert core_replay(scenario["records"][2:], first)["state"] == whole


def test_a_projected_change_matches_the_python_reference():
    scenario = next(s for s in SCENARIOS if s["name"] == "basic")
    state = core_replay(scenario["records"])["state"]
    py_state = teamlog.replay(scenario["records"])
    author = next(uid for uid in py_state.members if teamlog.is_admin(py_state, uid))
    for kind, data in [
        ("access.set", {"folder": next(iter(py_state.folders)), "user_id": author, "level": "read"}),
        ("member.remove", {"user_id": author}),
        ("genesis", {}),
    ]:
        out = sync_core.call("team_log_project", state=state, kind=kind, author=author, data=data)
        try:
            projected = teamlog.apply_change(py_state, kind, author, data).to_json()
        except teamlog.TeamLogError as exc:
            assert (out["refused"]["code"], out["refused"]["seq"]) == (exc.code, exc.seq)
            continue
        assert core_ask(out["state"], [("state_json", [])])[0] == projected
