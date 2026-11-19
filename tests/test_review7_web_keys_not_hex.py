"""Review 7c10379 (web, medium): decrypted keys stayed in memory as hex strings.

provenDekSuccessors, which every pull and every new item runs, keyed a Map by
the hex string of each DEK the browser held and of each key a re-key archive
sealed. A string cannot be wiped, so the lock's memzero of state.deks left
copies of every folder key on the heap. The archived key is now matched byte
for byte and wiped after the match.
"""

from __future__ import annotations

from tests.test_review6_web_dek_scope import (
    KEYS,
    NEW_DEK,
    RETIRED_DEK,
    TEAM_DEK,
    _archive,
    _dek,
    _js,
    _state,
)
from tests.test_review_web import pytestmark  # noqa: F401

SPY = """
const keyHex = new Set(Object.values(state.deks).map(b => Buffer.from(b).toString('hex')));
const realHex = bytesToHex;
let leaked = 0;
bytesToHex = value => { const out = realHex(value); if (keyHex.has(out)) leaked++; return out; };
const wiped = [];
const realZero = sodium.memzero;
sodium.memzero = value => { wiped.push(Buffer.from(value).toString('hex')); return realZero(value); };
"""


def test_the_key_chain_is_found_without_hex_copies_of_the_keys():
    objects = [_dek(TEAM_DEK, "01T0000000000000000000000A", "folder"),
               _dek(RETIRED_DEK, "01T0000000000000000000000A", "folder"),
               _dek(NEW_DEK, "01T0000000000000000000000A", "folder"),
               _archive(RETIRED_DEK, NEW_DEK)]
    state = _state(objects, [TEAM_DEK, RETIRED_DEK, NEW_DEK])
    out = _js(SPY + "({successors: provenDekSuccessors(), leaked, wiped})", state)
    assert out["successors"] == {RETIRED_DEK: NEW_DEK}
    assert out["leaked"] == 0, out
    # The copy of the old key the archive opened is wiped; the held keys stay.
    assert KEYS[RETIRED_DEK].hex() in out["wiped"], out
