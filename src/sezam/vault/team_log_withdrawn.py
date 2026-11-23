"""Records of this account that this device withdrew (review 18c300f R16-H1).

A server keeps every record a device signs and sends, also one it answered
with a refusal. On 18c300f it could serve such a record later: a hand-over
the admin had seen refused (the admin removed Bob since) made Bob the admin;
an identity rotation the device had dropped named keys nobody holds. The
device now remembers what it sent while the server has not taken it
(SENT_META: hash -> [seq, prev]) and what it withdrew (WITHDRAWN_META):

* the server refused the request (an answer 4xx: nothing of it was applied);
* its log holds another record at that seq, or the record was signed on one
  it withdrew (it moved on without it);
* the change it carried was dropped (an abandoned key change);
* it followed a fork without it (its change is made again or set aside).

Such a record never enters its log (a pull, a fork it follows). A record
signed and sent again is its will again.
"""

from __future__ import annotations

from .. import teamlog

SENT_META = "team_log_sent"  # hash -> [seq, prev, type]
WITHDRAWN_META = "team_log_withdrawn"


def withdrawn(db) -> frozenset[str]:
    return frozenset(db.get_meta_json(WITHDRAWN_META) or [])


def _load(db) -> tuple[dict, set]:
    return dict(db.get_meta_json(SENT_META) or {}), set(db.get_meta_json(WITHDRAWN_META) or [])


def _save(db, sent: dict, gone: set) -> None:
    db.set_meta_json(SENT_META, sent)
    db.set_meta_json(WITHDRAWN_META, sorted(gone))


def _follow_prev(sent: dict, gone: set) -> None:
    """A record signed on a withdrawn one is withdrawn with it."""
    moved = True
    while moved:
        moved = False
        for record_hash, (_seq, prev, _kind) in list(sent.items()):
            if prev in gone:
                del sent[record_hash]
                gone.add(record_hash)
                moved = True


def note_sent(db, records: list[dict], refused: bool) -> None:
    """``records`` went to the server and it did not answer that it took
    them: refused (an answer 4xx) or not known."""
    if not records:
        return
    sent, gone = _load(db)
    for record in records:
        record_hash = teamlog.record_hash(record)
        body = teamlog.parse_body(record["body"])
        if refused:
            sent.pop(record_hash, None)
            gone.add(record_hash)
        else:
            gone.discard(record_hash)
            sent[record_hash] = [body["seq"], body["prev"], body["type"]]
    _follow_prev(sent, gone)
    _save(db, sent, gone)


def note_stored(db, stored: dict[int, str]) -> None:
    """The local log now holds ``stored`` (seq -> hash): a sent record there
    was taken, another one at its seq was left behind."""
    sent, gone = _load(db)
    if not sent:
        return
    for record_hash, (seq, _prev, _kind) in list(sent.items()):
        if seq in stored:
            del sent[record_hash]
            if stored[seq] != record_hash:
                gone.add(record_hash)
    _follow_prev(sent, gone)
    _save(db, sent, gone)


def withdraw(db, hashes: list[str]) -> None:
    """Withdraw ``hashes``: the records of this account a fork the device
    followed went on without (capability finding 505)."""
    if not hashes:
        return
    sent, gone = _load(db)
    for record_hash in hashes:
        sent.pop(record_hash, None)
        gone.add(record_hash)
    _follow_prev(sent, gone)
    _save(db, sent, gone)


def withdraw_sent(db, kind: str) -> None:
    """Withdraw every sent record of ``kind`` (its change was dropped)."""
    sent, gone = _load(db)
    for record_hash, (_seq, _prev, sent_kind) in list(sent.items()):
        if sent_kind == kind:
            del sent[record_hash]
            gone.add(record_hash)
    _follow_prev(sent, gone)
    _save(db, sent, gone)
