"""Key voucher vectors (review e443cbc, goal #443): the Python reference."""

import json

import pytest

from sezam import key_vouchers as kv
from tests.key_vouchers_vectors import VECTORS_PATH, build

VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def test_the_builder_still_produces_the_stored_vectors():
    assert build() == VECTORS


@pytest.mark.parametrize("item", VECTORS["messages"], ids=lambda m: m["message_hex"][:16])
def test_the_message_is_the_stored_bytes(item):
    message = kv.voucher_message(item["user_id"], bytes.fromhex(item["signing_pk"]), item["entries"])
    assert message.hex() == item["message_hex"]


@pytest.mark.parametrize("entry", VECTORS["malformed_entries"], ids=str)
def test_a_malformed_entry_is_refused(entry):
    with pytest.raises(ValueError):
        kv.canonical_entries([entry])


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_only_a_list_of_the_current_key_vouches(case):
    vouched = kv.vouched(VECTORS["user_id"], bytes.fromhex(VECTORS["current_signing_pk"]), case["lists"])
    assert (tuple(case["entry"]) in vouched) is case["vouched"]
