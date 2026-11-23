// R16-Z (deep stateful run on 736ade3, INV-3, goal #443): a device vouches
// only for the server copies it holds. A desktop named its unsent tombstone
// (id, version 2, unchanged payload hash) in the list of held versions it
// posted; a server holding the account's retired key signed that version live
// and the web took it. The phone's list came from heldVoucherKeys, which named
// a queued row's own version the same way. Rows come from
// DatabaseService.getAllObjects, whose `queued` column says whether the
// outbox holds a write for the row.

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/key_vouchers.dart';
import 'package:sezam_mobile/services/sync_service.dart';

const _id = '01M84TV8KA51X75QJYNS3S1ECC';
final _hash1 = 'a' * 64;
final _hash2 = 'b' * 64;

void main() {
  test('a clean row is held as it is', () {
    final held = SyncService.heldVoucherKeys([
      {'id': _id, 'version': 1, 'payload_hash': _hash1, 'base_version': 1,
       'base_hash': _hash1, 'queued': 0},
    ]);
    expect(held, {keyVoucherKey(_id, 1, _hash1)});
  });

  test('an unsent tombstone with the same payload is not held', () {
    final held = SyncService.heldVoucherKeys([
      {'id': _id, 'version': 2, 'payload_hash': _hash1, 'is_deleted': 1,
       'base_version': 1, 'base_hash': _hash1, 'queued': 1},
    ]);
    expect(held, {keyVoucherKey(_id, 1, _hash1)});
  });

  test('an unsent edit is not held, its server copy is', () {
    final held = SyncService.heldVoucherKeys([
      {'id': _id, 'version': 2, 'payload_hash': _hash2, 'base_version': 1,
       'base_hash': _hash1, 'queued': 1},
    ]);
    expect(held, {keyVoucherKey(_id, 1, _hash1)});
  });
}
