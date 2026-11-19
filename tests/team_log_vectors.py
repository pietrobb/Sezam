"""Builds tests/vectors/team_log.json — the team log decision vectors.

Run ``python -m tests.team_log_vectors`` once to write the file. Never
regenerate it to make a client pass: web and mobile must reproduce the answers
the Python reference (src/sezam/teamlog.py) gives. tests/test_team_log_vectors.py
checks that this builder still produces the stored file byte for byte.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from nacl.public import PrivateKey
from nacl.signing import SigningKey

from sezam import teamlog as tl

VECTORS_PATH = Path(__file__).parent / "vectors" / "team_log.json"


def _id(prefix: str, n: int | str) -> str:
    n = str(n)
    return prefix + "0" * (26 - len(prefix) - len(n)) + n


ORG = _id("01JG", 1)
F1, F2 = _id("01JF", 1), _id("01JF", 2)
K = {n: _id("01JD", n) for n in range(1, 10)}
ITEM = _id("01JE", 1)  # a folder or item below F1
NO_WRITE = "team log gives no write access here"
UNKNOWN_KEY = "sealed with a key the team log does not know"
OTHER_FOLDER = "sealed with another folder's team key"
NAMES = ("alice", "bob", "carol", "dave", "eve", "bob2")


class Actor:
    def __init__(self, name: str, index: int):
        seed = hashlib.sha256(b"sezam-team-log-vector:" + name.encode()).digest()
        self.name = name
        self.uid = _id("01JM", index)
        self.sk = SigningKey(seed)
        self.spk = self.sk.verify_key.encode().hex()
        self.epk = PrivateKey(hashlib.sha256(seed + b"x25519").digest()).public_key.encode().hex()


ACTORS = {name: Actor(name, i + 1) for i, name in enumerate(NAMES)}
# bob's rotated identity keeps bob's user id
ACTORS["bob2"].uid = ACTORS["bob"].uid
A, B, C, D, E, B2 = (ACTORS[n] for n in NAMES)
# org recovery signing keys (R10-D)
R1, R2 = (SigningKey(hashlib.sha256(b"sezam-org-recovery:" + n).digest()).verify_key.encode().hex()
          for n in (b"1", b"2"))
# org recovery KEK wraps (capability run 316): nonce(24) || XChaCha20-Poly1305(32 + 16)
W1, W2 = ((hashlib.sha256(b"sezam-org-recovery-wrap:" + n).hexdigest() * 3)[:144] for n in (b"1", b"2"))


class Log:
    def __init__(self, rules: int = tl.FORMAT_VERSION):
        self.records: list[dict] = []
        self.state = tl.TeamState()
        self.rules = rules  # the "v" of the records it writes

    def _push(self, record: dict) -> "Log":
        self.records.append(record)
        try:
            self.state = tl.apply_record(self.state, record)
        except tl.TeamLogError:
            self.state = None  # only the last record of a failing scenario may fail
        return self

    def body(self, kind: str, author: Actor, data: dict, **override) -> dict:
        body = tl.next_body(self.state, kind, author.uid, data)
        body["v"] = self.rules
        body.update(override)
        return body

    def add(self, kind: str, author: Actor, data: dict, signer: Actor | None = None, **override) -> "Log":
        return self._push(tl.sign_record(self.body(kind, author, data, **override), (signer or author).sk))

    def raw(self, text: str, signer: Actor) -> "Log":
        sig = signer.sk.sign(tl.SIG_DOMAIN + text.encode("utf-8")).signature.hex()
        return self._push({"body": text, "sig": sig})

    # shorthands
    def genesis(self, who: Actor = A) -> "Log":
        return self.add("genesis", who, {
            "org": ORG, "user_id": who.uid, "signing_pk": who.spk, "encryption_pk": who.epk,
        })

    def member(self, who: Actor, role: str = "member", by: Actor = A) -> "Log":
        return self.add("member.add", by, {
            "user_id": who.uid, "signing_pk": who.spk, "encryption_pk": who.epk, "role": role,
        })

    def key(self, folder: str, gen: int, dek: str, prev: str | None, by: Actor = A) -> "Log":
        return self.add("folder.key", by, {"folder": folder, "gen": gen, "dek_id": dek, "prev_dek_id": prev})

    def access(self, folder: str, who: Actor, level: str | None, by: Actor = A, **kw) -> "Log":
        return self.add("access.set", by, {"folder": folder, "user_id": who.uid, "level": level}, **kw)

    def remove(self, who: Actor, by: Actor = A) -> "Log":
        return self.add("member.remove", by, {"user_id": who.uid})

    def recovery(self, who: Actor, pk: str | None) -> "Log":
        return self.add("org.recovery", who, {"recovery_pk": pk})

    def wrap(self, who: Actor, wrapped: str, epoch: int = 0, threshold: int = 2, total: int = 3) -> "Log":
        return self.add("org.recovery.wrap", who, {
            "wrapped_kek": wrapped, "key_epoch": epoch, "threshold": threshold, "total_shares": total,
        })

    def rotate(self, who: Actor, new: Actor, proof_by: Actor | None = None, author: Actor | None = None) -> "Log":
        prev = self.state.head_hash
        proof = (proof_by or new).sk.sign(
            tl.new_key_message(prev, who.uid, new.spk, new.epk)
        ).signature.hex()
        return self.add("member.keys", author or who, {
            "user_id": who.uid, "signing_pk": new.spk, "encryption_pk": new.epk, "new_key_sig": proof,
        })


def basic(rules: int = tl.FORMAT_VERSION) -> Log:
    return (
        Log(rules).genesis().member(B).member(C)
        .key(F1, 0, K[1], None).access(F1, B, "write").access(F1, C, "read")
    )


def _q(fn: str, *args, answer) -> dict:
    return {"fn": fn, "args": list(args), "answer": answer}


def _good(name: str, log: Log, questions: list[dict]) -> dict:
    assert log.state is not None, name
    return {"name": name, "records": log.records, "state": log.state.to_json(), "questions": questions}


def _bad(name: str, log: Log, code: str) -> dict:
    assert log.state is None, name
    try:
        tl.replay(log.records)
    except tl.TeamLogError as exc:
        assert exc.code == code, (name, exc.code)
        return {"name": name, "records": log.records, "error": {"seq": exc.seq, "code": exc.code}}
    raise AssertionError(name)


def _encoding_cases() -> list[dict]:
    """Bodies that sign fine but are not canonical or break the schema (record 1)."""
    log = Log().genesis()
    body = log.body("member.add", A, {
        "user_id": B.uid, "signing_pk": B.spk, "encryption_pk": B.epk, "role": "member",
    })
    text = tl.canonical(body)
    cases = {
        "space_after_colon": (text.replace('"v":2', '"v": 2'), "bad_encoding"),
        "keys_out_of_order": (
            '{"v":2,' + text[1:].replace(',"v":2', ''), "bad_encoding"),
        "boolean_value": (text.replace('"v":2', '"v":true'), "bad_encoding"),
        "float_value": (text.replace('"v":2', '"v":2.0'), "bad_encoding"),
        "escaped_string": (text.replace('"role":"member"', '"role":"memb\\u0065r"'), "bad_encoding"),
        "duplicate_key": (text[:-1] + ',"v":2}', "bad_encoding"),
        "non_ascii": (text.replace('"role":"member"', '"role":"m\u00e9mber"'), "bad_encoding"),
        "array_value": (text.replace('"v":2', '"v":[2]'), "bad_encoding"),
        "extra_body_field": (tl.canonical({**body, "x": 1}), "bad_schema"),
        "extra_data_field": (tl.canonical({**body, "data": {**body["data"], "x": "y"}}), "bad_schema"),
        "missing_data_field": (
            tl.canonical({**body, "data": {k: v for k, v in body["data"].items() if k != "role"}}),
            "bad_schema"),
        "uppercase_hex": (text.replace(B.spk, B.spk.upper()), "bad_schema"),
        "bad_ulid": (text.replace(B.uid, B.uid[:-1] + "U"), "bad_schema"),
        "unknown_role": (text.replace('"role":"member"', '"role":"owner"'), "bad_schema"),
        "unknown_type": (text.replace('"type":"member.add"', '"type":"member.ban"'), "bad_schema"),
        "version_3": (text.replace('"v":2', '"v":3'), "bad_schema"),
        "version_0": (text.replace('"v":2', '"v":0'), "bad_schema"),
        "trailing_newline": (text + "\n", "bad_encoding"),
        "newline_in_string": (text.replace('"role":"member"', '"role":"member\\n"'), "bad_encoding"),
        "negative_int": (text.replace('"seq":1', '"seq":-1'), "bad_encoding"),
        "huge_int": (text.replace('"seq":1', '"seq":9007199254740993'), "bad_encoding"),
        "seq_as_string": (text.replace('"seq":1', '"seq":"1"'), "bad_schema"),
        "gen_as_string": (tl.canonical(Log().genesis().body("folder.key", A, {
            "folder": F1, "gen": "0", "dek_id": K[1], "prev_dek_id": None})), "bad_schema"),
    }
    out = []
    for name, (bad_text, code) in cases.items():
        case = Log().genesis()
        case.raw(bad_text, A)
        out.append(_bad("encoding_" + name, case, code))
    for name, sig in {
        "sig_with_newline": lambda s: s + "\n",
        "sig_uppercase": str.upper,
        "sig_short": lambda s: s[:-2],
    }.items():
        case = Log().genesis()
        record = tl.sign_record(case.body("member.add", A, {
            "user_id": B.uid, "signing_pk": B.spk, "encryption_pk": B.epk, "role": "member"}), A.sk)
        case._push({"body": record["body"], "sig": sig(record["sig"])})
        out.append(_bad("record_" + name, case, "bad_schema"))
    case = Log().genesis()
    case._push({"body": tl.canonical(case.body("member.remove", A, {"user_id": B.uid})), "sig": "00" * 64,
                "extra": "x"})
    out.append(_bad("record_extra_field", case, "bad_schema"))
    return out


def build_vectors() -> dict:
    s: list[dict] = []
    full = basic()
    s.append(_good("basic", full, [
        _q("may_write", F1, A.uid, answer=True),
        _q("may_write", F1, B.uid, answer=True),
        _q("may_write", F1, C.uid, answer=False),
        _q("may_write", F1, E.uid, answer=False),
        _q("may_write", F2, A.uid, answer=False),
        _q("key_recipients", F1, answer=[[B.uid, B.epk, "write"], [C.uid, C.epk, "read"]]),
        _q("key_recipients", F2, answer=[]),
        _q("current_key", F1, answer=K[1]),
        _q("current_key", F2, answer=None),
        _q("key_generation", F1, K[1], answer=["current", 0]),
        _q("key_generation", F1, K[9], answer=["unknown", None]),
        _q("key_generation", F2, K[1], answer=["unknown", None]),
        _q("is_team_folder", F1, answer=True),
        _q("is_team_folder", F2, answer=False),
        _q("may_seal", F1, answer=True),
        _q("may_seal", F2, answer=False),
        _q("is_admin", A.uid, answer=True),
        _q("is_admin", B.uid, answer=False),
        _q("may_hold_key", B.uid, K[1], answer=True),
        _q("may_hold_key", A.uid, K[1], answer=True),
        _q("may_hold_key", E.uid, K[1], answer=False),
        _q("may_hold_key", B.uid, K[9], answer=False),
        _q("envelope_valid", A.uid, B.uid, K[1], "write", B.epk, answer=True),
        _q("envelope_valid", A.uid, C.uid, K[1], "read", C.epk, answer=True),
        _q("envelope_valid", A.uid, C.uid, K[1], "write", C.epk, answer=False),
        _q("envelope_valid", A.uid, C.uid, K[1], None, C.epk, answer=False),
        _q("envelope_valid", B.uid, C.uid, K[1], "read", C.epk, answer=False),
        _q("envelope_valid", A.uid, C.uid, K[1], "read", E.epk, answer=False),
        _q("envelope_valid", A.uid, E.uid, K[1], "read", E.epk, answer=False),
        # item_refusal(user, object, team folder above, sealing key, own personal key, sealing)
        _q("item_refusal", B.uid, ITEM, F1, K[1], False, True, answer=None),
        _q("item_refusal", A.uid, ITEM, F1, K[1], False, True, answer=None),
        _q("item_refusal", C.uid, ITEM, F1, K[1], False, True, answer=NO_WRITE),
        _q("item_refusal", E.uid, ITEM, F1, K[1], False, True, answer=NO_WRITE),
        _q("item_refusal", B.uid, ITEM, F1, K[9], False, True, answer=UNKNOWN_KEY),
        _q("item_refusal", B.uid, ITEM, F1, None, False, True, answer=UNKNOWN_KEY),
        _q("item_refusal", B.uid, ITEM, F1, K[9], True, True, answer=None),
        _q("item_refusal", C.uid, ITEM, F1, K[9], True, True, answer=NO_WRITE),
        _q("item_refusal", C.uid, ITEM, None, K[9], False, True, answer=None),
        _q("item_refusal", B.uid, ITEM, None, K[1], False, True, answer=OTHER_FOLDER),
        _q("item_refusal", B.uid, ITEM, F2, K[1], False, True, answer=OTHER_FOLDER),
        _q("item_refusal", A.uid, F1, None, K[1], False, True, answer=None),
        _q("tombstone_refusal", B.uid, K[1], answer=None),
        _q("tombstone_refusal", C.uid, K[1], answer=NO_WRITE),
        _q("tombstone_refusal", C.uid, K[9], answer=None),
        _q("tombstone_refusal", C.uid, None, answer=None),
        _q("move_refusal", B.uid, F1, None, answer=None),
        _q("move_refusal", C.uid, F1, None, answer=NO_WRITE),
        _q("move_refusal", C.uid, F1, F2, answer=NO_WRITE),
        _q("move_refusal", D.uid, F1, None, answer=NO_WRITE),
        _q("move_refusal", C.uid, F1, F1, answer=None),
        _q("move_refusal", C.uid, None, F1, answer=None),
        _q("move_refusal", A.uid, F1, F2, answer=None),
        # TL7: one's own personal object may leave for outside every team folder only.
        _q("move_refusal", C.uid, F1, None, True, answer=None),
        _q("move_refusal", D.uid, F1, None, True, answer=None),
        _q("move_refusal", C.uid, F1, F2, True, answer=NO_WRITE),
        _q("move_refusal", C.uid, F1, None, False, answer=NO_WRITE),
    ]))

    removed = basic().remove(B)
    s.append(_good("remove_member_before_rekey", removed, [
        _q("is_stale", F1, answer=True),
        _q("may_seal", F1, answer=False),
        _q("may_write", F1, B.uid, answer=False),
        _q("may_hold_key", B.uid, K[1], answer=False),
        _q("key_recipients", F1, answer=[[C.uid, C.epk, "read"]]),
        _q("envelope_valid", A.uid, B.uid, K[1], "write", B.epk, answer=False),
        _q("envelope_valid", A.uid, C.uid, K[1], "read", C.epk, answer=True),
        _q("item_refusal", A.uid, ITEM, F1, K[1], False, True, answer="folder waits for a re-key"),
        _q("item_refusal", A.uid, ITEM, F1, K[1], False, False, answer=None),
        _q("item_refusal", B.uid, ITEM, F1, K[1], False, False, answer=NO_WRITE),
    ]))
    rekeyed = basic().remove(B).key(F1, 1, K[2], K[1])
    s.append(_good("remove_member_then_rekey", rekeyed, [
        _q("is_stale", F1, answer=False),
        _q("may_seal", F1, answer=True),
        _q("current_key", F1, answer=K[2]),
        _q("key_generation", F1, K[1], answer=["old", 0]),
        _q("key_generation", F1, K[2], answer=["current", 1]),
        _q("may_hold_key", C.uid, K[1], answer=False),
        _q("may_hold_key", C.uid, K[2], answer=True),
        _q("may_hold_key", B.uid, K[2], answer=False),
        _q("envelope_valid", A.uid, C.uid, K[1], "read", C.epk, answer=False),
        _q("envelope_valid", A.uid, C.uid, K[2], "read", C.epk, answer=True),
        _q("item_refusal", A.uid, ITEM, F1, K[1], False, False, answer="sealed with an old key generation"),
        _q("item_refusal", A.uid, ITEM, F1, K[2], False, True, answer=None),
    ]))
    s.append(_good("downgrade_write_to_read", basic().access(F1, B, "read"), [
        _q("is_stale", F1, answer=True),
        _q("may_write", F1, B.uid, answer=False),
        _q("may_hold_key", B.uid, K[1], answer=True),
        _q("key_recipients", F1, answer=[[B.uid, B.epk, "read"], [C.uid, C.epk, "read"]]),
    ]))
    s.append(_good("upgrade_read_to_write", basic().access(F1, C, "write"), [
        _q("is_stale", F1, answer=False),
        _q("may_write", F1, C.uid, answer=True),
    ]))
    s.append(_good("access_none", basic().access(F1, C, None), [
        _q("is_stale", F1, answer=True),
        _q("may_hold_key", C.uid, K[1], answer=False),
        _q("key_recipients", F1, answer=[[B.uid, B.epk, "write"]]),
    ]))
    s.append(_good("readd_removed_member", basic().remove(B).member(B), [
        _q("may_write", F1, B.uid, answer=False),
        _q("may_hold_key", B.uid, K[1], answer=False),
        _q("is_stale", F1, answer=True),
    ]))
    second = basic().member(D, "admin").key(F2, 0, K[3], None, by=D).remove(A, by=D)
    s.append(_good("second_admin_removes_founder", second, [
        _q("is_admin", A.uid, answer=False),
        _q("is_admin", D.uid, answer=True),
        _q("may_write", F1, D.uid, answer=True),
        _q("is_stale", F1, answer=True),
        _q("is_stale", F2, answer=False),
        _q("may_hold_key", D.uid, K[3], answer=True),
    ]))
    s.append(_good("remove_generation_author",
                   basic().member(D, "admin").key(F2, 0, K[3], None, by=D).remove(D), [
        _q("is_stale", F2, answer=True),
        _q("may_seal", F2, answer=False),
        _q("may_hold_key", D.uid, K[3], answer=False),
    ]))
    s.append(_good("role_change", basic().add("member.role", A, {"user_id": B.uid, "role": "admin"}), [
        _q("is_admin", B.uid, answer=True),
        _q("may_write", F1, B.uid, answer=True),
    ]))
    s.append(_good("member_rotates_keys", basic().rotate(B, B2), [
        _q("key_recipients", F1, answer=[[B.uid, B2.epk, "write"], [C.uid, C.epk, "read"]]),
        _q("envelope_valid", A.uid, B.uid, K[1], "write", B.epk, answer=False),
        _q("envelope_valid", A.uid, B.uid, K[1], "write", B2.epk, answer=True),
    ]))
    rotated_then_signs = basic().rotate(B, B2).add("member.role", A, {"user_id": C.uid, "role": "admin"})
    s.append(_good("after_rotation_admin_continues", rotated_then_signs, [
        _q("is_admin", C.uid, answer=True),
    ]))

    s.append(_good("readd_latest_keys_after_rotation", basic().rotate(B, B2).remove(B2).member(B2), [
        _q("may_write", F1, B.uid, answer=False),
        _q("key_recipients", F1, answer=[[C.uid, C.epk, "read"]]),
    ]))
    transfer = basic().add("member.role", A, {"user_id": B.uid, "role": "admin"})
    transfer.add("member.role", A, {"user_id": A.uid, "role": "member"})
    s.append(_good("admin_handover", transfer, [
        _q("is_admin", A.uid, answer=False),
        _q("is_admin", B.uid, answer=True),
    ]))
    # Review 1141a20: after a handover what the old admin sealed with a
    # folder's current key while admin is still theirs (a pulled copy), not
    # a new write; a re-key, a removal or a folder founded later ends it.
    handed = basic().add("member.role", A, {"user_id": B.uid, "role": "admin"})
    handed.add("member.role", A, {"user_id": A.uid, "role": "member"})
    s.append(_good("handover_keeps_the_former_admins_items", handed, [
        _q("item_refusal", A.uid, ITEM, F1, K[1], False, False, answer=None),
        _q("item_refusal", A.uid, ITEM, F1, K[1], False, True, answer=NO_WRITE),
        _q("item_refusal", A.uid, ITEM, F1, K[9], True, False, answer=None),
        _q("item_refusal", C.uid, ITEM, F1, K[1], False, False, answer=NO_WRITE),
        _q("admin_policy_refusal", answer=None),
    ]))
    s.append(_good("handover_then_rekey", copy.deepcopy(handed).key(F1, 1, K[2], K[1], by=B), [
        _q("item_refusal", A.uid, ITEM, F1, K[2], False, False, answer=NO_WRITE),
        _q("item_refusal", B.uid, ITEM, F1, K[2], False, True, answer=None),
    ]))
    s.append(_good("handover_then_remove", copy.deepcopy(handed).remove(A, by=B), [
        _q("item_refusal", A.uid, ITEM, F1, K[1], False, False, answer=NO_WRITE),
    ]))
    s.append(_good("handover_then_new_folder", copy.deepcopy(handed).key(F2, 0, K[3], None, by=B), [
        _q("item_refusal", A.uid, ITEM, F2, K[3], False, False, answer=NO_WRITE),
        _q("item_refusal", A.uid, ITEM, F1, K[1], False, False, answer=None),
    ]))
    # TL7: a head with two active admins (records may pass through one).
    s.append(_good("two_admins_at_the_head", basic().add("member.role", A, {"user_id": B.uid, "role": "admin"}), [
        _q("admin_policy_refusal", answer="more than one admin"),
    ]))
    s.append(_bad("rotation_back_to_retired_keys", basic().rotate(B, B2).rotate(B2, B), "key_reused"))
    s.append(_bad("readd_retired_keys_after_rotation", basic().rotate(B, B2).remove(B2).member(B), "key_reused"))
    # Review 8595ec1 (R10-B): a record is judged by the rules of its "v". A log
    # stored under rules 1 (before retired keys stayed retired) still replays;
    # rules 2 apply from its first record on, and the version never goes down.
    s.append(_good("rules_1_readds_retired_keys", basic(1).rotate(B, B2).remove(B2).member(B), [
        _q("is_admin", A.uid, answer=True),
        _q("key_recipients", F1, answer=[[C.uid, C.epk, "read"]]),
    ]))
    s.append(_good("rules_1_rotates_back", basic(1).rotate(B, B2).rotate(B2, B), [
        _q("key_recipients", F1, answer=[[B.uid, B.epk, "write"], [C.uid, C.epk, "read"]]),
    ]))
    upgraded = basic(1).rotate(B, B2).remove(B2).member(B)
    upgraded.rules = 2
    upgraded.access(F1, B, "read")
    s.append(_good("rules_1_log_continues_under_rules_2", upgraded, [
        _q("may_hold_key", B.uid, K[1], answer=True),
        _q("may_write", F1, B.uid, answer=False),
    ]))
    upgraded = basic(1).rotate(B, B2)
    upgraded.rules = 2
    s.append(_bad("rules_2_after_rules_1_keeps_retired_keys", upgraded.rotate(B2, B), "key_reused"))
    downgraded = basic()
    downgraded.rules = 1
    s.append(_bad("rules_downgrade", downgraded.access(F1, C, "write"), "rules_downgrade"))
    record = Log().genesis().records[0]
    signature = bytes.fromhex(record["sig"])
    order = 2**252 + 27742317777372353535851937790883648493
    high_s = signature[:32] + (int.from_bytes(signature[32:], "little") + order).to_bytes(32, "little")
    s.append(_bad("noncanonical_signature_scalar", Log()._push({**record, "sig": high_s.hex()}), "bad_signature"))
    body = tl.next_body(tl.TeamState(), "genesis", A.uid, {
        "org": ORG, "user_id": A.uid, "signing_pk": "01" + "00" * 31, "encryption_pk": A.epk,
    })
    s.append(_bad("small_order_signer", Log()._push({
        "body": tl.canonical(body), "sig": "01" + "00" * 63,
    }), "bad_signature"))
    # Review 8595ec1 (R10-D): an admin names their org recovery key in the log,
    # so a server restored from before its registration still knows it. It goes
    # with the admin role; only rules 2 know the record.
    s.append(_good("org_recovery_named", basic().recovery(A, R1), [_q("is_admin", A.uid, answer=True)]))
    s.append(_good("org_recovery_replaced_and_cleared", basic().recovery(A, R1).recovery(A, R2).recovery(A, None), [
        _q("is_admin", A.uid, answer=True),
    ]))
    second = basic().add("member.role", A, {"user_id": B.uid, "role": "admin"}).recovery(B, R2).recovery(A, R1)
    s.append(_good("org_recovery_two_admins", second, [_q("is_admin", B.uid, answer=True)]))
    s.append(_good("org_recovery_ends_with_demotion", basic().add(
        "member.role", A, {"user_id": B.uid, "role": "admin"}).recovery(B, R2).add(
        "member.role", A, {"user_id": B.uid, "role": "member"}), [_q("is_admin", B.uid, answer=False)]))
    s.append(_good("org_recovery_ends_with_removal", basic().add(
        "member.role", A, {"user_id": B.uid, "role": "admin"}).recovery(B, R2).remove(B, by=A), [
        _q("is_admin", B.uid, answer=False),
    ]))
    s.append(_bad("org_recovery_by_member", basic().recovery(B, R1), "not_admin"))
    s.append(_bad("org_recovery_unchanged", basic().recovery(A, R1).recovery(A, R1), "unchanged"))
    s.append(_bad("org_recovery_clear_without_key", basic().recovery(A, None), "unchanged"))
    s.append(_bad("org_recovery_member_key", basic().recovery(A, C.spk), "key_reused"))
    s.append(_bad("org_recovery_under_rules_1", basic(1).recovery(A, R1), "bad_schema"))
    # Capability run 316: the KEK wrap of the named key rides in the log, so a
    # restored server serves it; a new key (or none) drops the old wrap.
    s.append(_good("org_recovery_wrap", basic().recovery(A, R1).wrap(A, W1), [_q("is_admin", A.uid, answer=True)]))
    s.append(_good("org_recovery_wrap_rewrapped", basic().recovery(A, R1).wrap(A, W1).wrap(A, W2, epoch=1), [
        _q("is_admin", A.uid, answer=True),
    ]))
    s.append(_good("org_recovery_wrap_dropped_with_new_key", basic().recovery(A, R1).wrap(A, W1).recovery(A, R2), [
        _q("is_admin", A.uid, answer=True),
    ]))
    s.append(_good("org_recovery_wrap_ends_with_demotion", basic().add(
        "member.role", A, {"user_id": B.uid, "role": "admin"}).recovery(B, R2).wrap(B, W2).add(
        "member.role", A, {"user_id": B.uid, "role": "member"}), [_q("is_admin", B.uid, answer=False)]))
    s.append(_bad("org_recovery_wrap_without_key", basic().wrap(A, W1), "no_recovery_key"))
    s.append(_bad("org_recovery_wrap_unchanged", basic().recovery(A, R1).wrap(A, W1).wrap(A, W1), "unchanged"))
    s.append(_bad("org_recovery_wrap_by_member", basic().recovery(A, R1).wrap(B, W1), "not_admin"))
    s.append(_bad("org_recovery_wrap_bad_shares", basic().recovery(A, R1).wrap(A, W1, threshold=4), "bad_shares"))
    s.append(_bad("org_recovery_wrap_zero_threshold", basic().recovery(A, R1).wrap(A, W1, threshold=0), "bad_shares"))
    s.append(_bad("org_recovery_wrap_short", basic().recovery(A, R1).wrap(A, W1[:-2]), "bad_schema"))
    s.append(_bad("org_recovery_wrap_under_rules_1", basic(1).wrap(A, W1), "bad_schema"))

    # Refusals — the whole log is rejected at the given record.
    s.append(_bad("sibling_rekey", basic().key(F1, 1, K[2], K[1]).key(F1, 1, K[3], K[1]), "bad_generation"))
    s.append(_bad("rekey_from_old_key", basic().key(F1, 1, K[2], K[1]).key(F1, 2, K[3], K[1]), "bad_generation"))
    s.append(_bad("rekey_skips_generation", basic().key(F1, 2, K[2], K[1]), "bad_generation"))
    s.append(_bad("first_key_not_generation_0", Log().genesis().key(F1, 1, K[1], None), "bad_generation"))
    s.append(_bad("first_key_with_prev", Log().genesis().key(F1, 0, K[1], K[2]), "bad_generation"))
    s.append(_bad("dek_reused", basic().key(F2, 0, K[1], None), "dek_reused"))
    s.append(_bad("member_grants_access", basic().access(F1, C, "write", by=B), "not_admin"))
    s.append(_bad("member_adds_member", basic().member(E, by=B), "not_admin"))
    s.append(_bad("member_rekeys", basic().key(F1, 1, K[2], K[1], by=B), "not_admin"))
    s.append(_bad("stranger_signs", basic().access(F1, E, "read", by=E), "not_member"))
    s.append(_bad("removed_member_signs", basic().member(D, "admin").remove(D).access(F1, C, "write", by=D),
                  "not_member"))
    s.append(_bad("forged_signature", basic().access(F1, C, "write", signer=E), "bad_signature"))
    s.append(_bad("wrong_prev", basic().access(F1, C, "write", prev="ab" * 32), "bad_prev"))
    s.append(_bad("skipped_seq", basic().access(F1, C, "write", seq=99), "bad_seq"))
    s.append(_bad("repeated_seq", basic().access(F1, C, "write", seq=1), "bad_seq"))
    s.append(_bad("no_genesis", Log().add("member.add", A, {
        "user_id": B.uid, "signing_pk": B.spk, "encryption_pk": B.epk, "role": "member"}), "bad_genesis"))
    s.append(_bad("second_genesis", Log().genesis().genesis(B), "bad_genesis"))
    s.append(_bad("genesis_for_someone_else", Log().add("genesis", A, {
        "org": ORG, "user_id": B.uid, "signing_pk": A.spk, "encryption_pk": A.epk}), "bad_genesis"))
    s.append(_bad("genesis_signed_by_other_key", Log().add("genesis", A, {
        "org": ORG, "user_id": A.uid, "signing_pk": A.spk, "encryption_pk": A.epk}, signer=E), "bad_signature"))
    s.append(_bad("remove_last_admin", basic().remove(A), "last_admin"))
    s.append(_bad("demote_last_admin", basic().add("member.role", A, {"user_id": A.uid, "role": "member"}),
                  "last_admin"))
    s.append(_bad("add_active_member", basic().member(B), "member_exists"))
    s.append(_bad("add_with_someone_elses_key", basic().add("member.add", A, {
        "user_id": E.uid, "signing_pk": B.spk, "encryption_pk": E.epk, "role": "member"}), "key_reused"))
    s.append(_bad("add_with_same_key_twice", basic().add("member.add", A, {
        "user_id": E.uid, "signing_pk": E.spk, "encryption_pk": E.spk, "role": "member"}), "key_reused"))
    s.append(_bad("access_unknown_folder", basic().access(F2, B, "read"), "folder_unknown"))
    s.append(_bad("access_for_stranger", basic().access(F1, E, "read"), "not_active"))
    s.append(_bad("access_for_removed", basic().remove(B).access(F1, B, "read"), "not_active"))
    s.append(_bad("access_unchanged", basic().access(F1, B, "write"), "unchanged"))
    s.append(_bad("access_none_without_access", basic().access(F1, A, None), "unchanged"))
    s.append(_bad("remove_stranger", basic().remove(E), "not_active"))
    s.append(_bad("rotation_without_new_key_proof", basic().rotate(B, B2, proof_by=B), "bad_new_key_signature"))
    s.append(_bad("admin_rotates_member", basic().rotate(B, B2, author=A), "not_self"))
    s.append(_bad("rotation_to_someone_elses_key", basic().rotate(B, C), "key_reused"))
    s.append(_bad("old_key_after_rotation", basic().rotate(B, B2).add("member.keys", B, {
        "user_id": B.uid, "signing_pk": E.spk, "encryption_pk": E.epk, "new_key_sig": "00" * 64}),
        "bad_signature"))
    s.extend(_encoding_cases())

    return {
        "_comment": (
            "Team log decision vectors (docs/DESIGN_TEAM_LOG.md), built by tests/team_log_vectors.py "
            "from the Python reference src/sezam/teamlog.py. Web and mobile must give the same state, "
            "answers and errors; never regenerate this file to make a client pass."
        ),
        "domains": {
            "sig": tl.SIG_DOMAIN.decode("ascii"), "hash": tl.HASH_DOMAIN.decode("ascii"),
            "new_key": tl.NEW_KEY_DOMAIN.decode("ascii"),
        },
        "scenarios": s,
    }


def dump(vectors: dict) -> str:
    return json.dumps(vectors, indent=1, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    VECTORS_PATH.write_text(dump(build_vectors()), encoding="utf-8", newline="\n")
    print(VECTORS_PATH)
