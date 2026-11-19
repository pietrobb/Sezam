"""Seeded random team logs for the Python/JS/Dart differential test (R9-A2, goal #367).

Each scenario is in the shared vector format (tests/vectors/team_log.json): the
Python reference decides its state and answers, or the error of its last record.
The generator mostly writes records an honest client could write, then bends one
thing at a time: another author or signer, a retired or another member's key, a
wrong new-key proof, a skipped generation, a removed or demoted admin.
"""
from __future__ import annotations

import hashlib
import random

from nacl.public import PrivateKey
from nacl.signing import SigningKey

from sezam import teamlog as tl
from tests.team_log_vectors import ORG, _id

UIDS = [_id("01JM", n) for n in range(1, 6)]
FOLDERS = [_id("01JF", n) for n in range(1, 4)]
DEKS = [_id("01JD", n) for n in range(1, 13)]
LEVELS = ["write", "read", None]


class Key:
    def __init__(self, n: int):
        seed = hashlib.sha256(b"sezam-team-log-differential:" + str(n).encode()).digest()
        self.sk = SigningKey(seed)
        self.spk = self.sk.verify_key.encode().hex()
        self.epk = PrivateKey(hashlib.sha256(seed + b"x25519").digest()).public_key.encode().hex()


KEYS = [Key(n) for n in range(10)]
BY_SPK = {k.spk: k for k in KEYS}


def _questions(state: tl.TeamState, rng: random.Random) -> list[dict]:
    out = []

    def q(fn, *args):
        out.append({"fn": fn, "args": list(args), "answer": _answer(state, fn, args)})

    for folder in FOLDERS:
        for fn in ("current_key", "is_team_folder", "is_stale", "may_seal", "key_recipients"):
            q(fn, folder)
        for uid in UIDS:
            q("may_write", folder, uid)
        for dek in rng.sample(DEKS, 3):
            q("key_generation", folder, dek)
    for uid in UIDS:
        q("is_admin", uid)
        for dek in rng.sample(DEKS, 3):
            q("may_hold_key", uid, dek)
            q("tombstone_refusal", uid, dek)
        for _ in range(3):
            q("envelope_valid", rng.choice(UIDS), uid, rng.choice(DEKS), rng.choice(LEVELS),
              rng.choice(KEYS).epk)
        q("item_refusal", uid, _id("01JE", 1), rng.choice(FOLDERS + [None]), rng.choice(DEKS + [None]),
          rng.random() < 0.3, rng.random() < 0.7)
        q("move_refusal", uid, rng.choice(FOLDERS + [None]), rng.choice(FOLDERS + [None]))
    return out


def _answer(state, fn, args):
    value = getattr(tl, fn)(state, *args)
    if isinstance(value, tuple):
        value = list(value)
    if fn == "key_recipients":
        value = [list(r) for r in value]
    return value


class _Gen:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.records: list[dict] = []
        self.state = tl.TeamState()
        self.failed = False
        self.noise = rng.choice([0.03, 0.15, 0.5, 1.0])

    def honest(self, p: float) -> bool:
        return self.rng.random() >= (1 - p) * self.noise

    def pick(self, good: list, every: list):
        return self.rng.choice(good) if good and self.honest(0.9) else self.rng.choice(every)

    def unused_keys(self) -> list[Key]:
        return [k for k in KEYS if k.spk not in self.state.seen_keys and k.epk not in self.state.seen_keys]

    def _signer_of(self, uid: str) -> Key:
        member = self.state.members.get(uid)
        if member is not None and member.signing_pk in BY_SPK and self.honest(0.93):
            return BY_SPK[member.signing_pk]
        return self.rng.choice(KEYS)

    def _author(self) -> str:
        admins = [u for u, m in self.state.members.items() if m.active and m.role == "admin"]
        if admins and self.honest(0.9):
            return self.rng.choice(admins)
        return self.rng.choice(UIDS)

    def _push(self, kind: str, author: str, data: dict, signer: Key) -> None:
        body = tl.next_body(self.state, kind, author, data)
        roll = self.rng.random()
        if roll < 0.02 * self.noise:
            body["seq"] = max(0, body["seq"] + self.rng.choice([-1, 1, 2]))
        elif roll < 0.04 * self.noise and body.get("prev"):
            body["prev"] = "ab" * 32
        record = tl.sign_record(body, signer.sk)
        self.records.append(record)
        try:
            self.state = tl.apply_record(self.state, record)
        except tl.TeamLogError:
            self.failed = True

    def genesis(self) -> None:
        uid, key = self.rng.choice(UIDS[:2]), self.rng.choice(KEYS[:3])
        self._push("genesis", uid, {"org": ORG, "user_id": uid, "signing_pk": key.spk,
                                    "encryption_pk": key.epk}, key if self.honest(0.97) else KEYS[-1])

    def step(self) -> None:
        rng, author = self.rng, self._author()
        signer = self._signer_of(author)
        kind = rng.choices(
            ["member.add", "member.remove", "member.role", "member.keys", "folder.key", "access.set", "genesis"],
            weights=[18, 8, 6, 14, 18, 30, 0.3],
        )[0]
        if kind == "access.set" and not any(self.state.folders.values()) and self.honest(0.95):
            kind = "folder.key"
        members = [u for u, m in self.state.members.items() if m.active]
        if kind in ("member.remove", "member.role") and self.honest(0.85):
            admins = [u for u in members if self.state.members[u].role == "admin"]
            members = [u for u in members if len(admins) > 1 or u not in admins]
        others = [u for u in UIDS if u not in self.state.members or not self.state.members[u].active]
        pool = {"member.add": others, "member.remove": members, "member.role": members,
                "access.set": members}.get(kind, [])
        if kind in ("member.remove", "member.role", "access.set") and not pool and others and self.honest(0.9):
            kind, pool = "member.add", others
        uid = rng.choice(pool) if pool and self.honest(0.9) else rng.choice(UIDS)
        if kind == "genesis":
            key = rng.choice(KEYS)
            return self._push("genesis", author, {"org": ORG, "user_id": author, "signing_pk": key.spk,
                                                  "encryption_pk": key.epk}, signer)
        if kind == "member.add":
            key = self.pick(self.unused_keys(), KEYS)
            spk, epk = key.spk, key.epk
            if not self.honest(0.9):
                epk = rng.choice(KEYS).epk  # mixed pair: another key's encryption key
            role = rng.choice(["member", "member", "admin"])
            return self._push(kind, author, {"user_id": uid, "signing_pk": spk, "encryption_pk": epk,
                                             "role": role}, signer)
        if kind == "member.remove":
            return self._push(kind, author, {"user_id": uid}, signer)
        if kind == "member.role":
            current = self.state.members[uid].role if uid in self.state.members else None
            role = self.pick([r for r in ("member", "admin") if r != current], ["member", "admin"])
            return self._push(kind, author, {"user_id": uid, "role": role}, signer)
        if kind == "member.keys":
            who = author if self.honest(0.85) else uid
            new = self.pick(self.unused_keys(), KEYS)
            epk = new.epk if self.honest(0.9) else rng.choice(KEYS).epk
            prover = new if self.honest(0.92) else rng.choice(KEYS)
            proof = prover.sk.sign(tl.new_key_message(self.state.head_hash, who, new.spk, epk)).signature.hex()
            return self._push(kind, author, {"user_id": who, "signing_pk": new.spk, "encryption_pk": epk,
                                             "new_key_sig": proof}, signer)
        known = [f for f in FOLDERS if self.state.folders.get(f)]
        folder = rng.choice(known) if kind == "access.set" and known and self.honest(0.9) else rng.choice(FOLDERS)
        if kind == "folder.key":
            keys = self.state.folders.get(folder, [])
            gen = len(keys) if self.honest(0.85) else rng.randint(0, 3)
            prev = keys[-1][0] if keys and self.honest(0.9) else rng.choice(DEKS + [None])
            if not keys and self.honest(0.9):
                prev = None
            return self._push(kind, author, {"folder": folder, "gen": gen, "dek_id": self.pick([d for d in DEKS if d not in self.state.dek_index], DEKS),
                                             "prev_dek_id": prev}, signer)
        current = self.state.access.get(folder, {}).get(uid)
        level = self.pick([lv for lv in LEVELS if lv != current], LEVELS)
        return self._push("access.set", author, {"folder": folder, "user_id": uid, "level": level}, signer)


def scenario(seed: int) -> dict:
    rng = random.Random(seed)
    gen = _Gen(rng)
    gen.genesis()
    for _ in range(rng.randint(0, 40)):
        if gen.failed:
            break
        gen.step()
    name = f"differential_{seed}"
    if gen.failed:
        try:
            tl.replay(gen.records)
        except tl.TeamLogError as exc:
            return {"name": name, "records": gen.records, "error": {"seq": exc.seq, "code": exc.code}}
        raise AssertionError(f"{name}: apply_record refused but replay accepted")
    state = tl.replay(gen.records)
    assert state.to_json() == gen.state.to_json(), name
    return {"name": name, "records": gen.records, "state": state.to_json(), "questions": _questions(state, rng)}


def scenarios(count: int, first_seed: int = 0) -> dict:
    return {"scenarios": [scenario(seed) for seed in range(first_seed, first_seed + count)]}
