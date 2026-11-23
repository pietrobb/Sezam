"""Key voucher vectors (review e443cbc, goal #443): the Python reference."""

import json

import pytest

from sezam import key_vouchers as kv
from sezam.vault.sync_vouchers import legacy_entries, legacy_post_allowed
from tests.key_vouchers_vectors import VECTORS_PATH, build

VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
# R16-M4: when a desktop or a phone posts its held versions (the phone runs
# the same file, mobile/test/key_vouchers_test.dart).
POST = json.loads((VECTORS_PATH.parent / "key_voucher_post.json").read_text(encoding="utf-8"))


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


@pytest.mark.parametrize("case", POST["cases"], ids=lambda c: c["name"])
def test_a_device_posts_its_held_versions_by_the_shared_rule(case):
    held = [tuple(e) for e in case["held"]]
    assert legacy_post_allowed(
        fingerprint=case["fingerprint"], checked=case["checked"],
        pending_identity=case["pending_identity"], own_key=case["own_key"],
        server_own_key=case["server_own_key"], held_count=len(held),
    ) is case["post"]
    own = [tuple(e) for e in case["own_listed"]]
    assert legacy_entries(held, own) == [tuple(e) for e in case["entries"]]
