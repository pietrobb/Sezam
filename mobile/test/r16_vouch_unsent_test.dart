// R16-Z (deep stateful run on 736ade3, INV-3, goal #443): a device vouches
// only for the server copies it holds. A desktop named its unsent tombstone
// (id, version 2, unchanged payload hash) in the list of held versions it
// posted; a server holding the account's retired key signed that version live
// and the web took it. The phone's list came from heldVoucherKeys, which named
// a queued row's own version the same way. Rows come from
// DatabaseService.getAllObjects, whose `queued` column says whether the
// outbox holds a write for the row.
//
// R17-N1: an entry names the whole signed message, its signer and key; a
// queued row's base is not held (its other signed fields are not kept).

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/key_vouchers.dart';
import 'package:sezam_mobile/services/sync_service.dart';

const _id = '01M84TV8KA51X75QJYNS3S1ECC';
const _signer = '01M84TV8KA51X75QJYNS3S1ECD';
const _parent = '01M84TV8KA51X75QJYNS3S1ECE';
final _hash1 = 'a' * 64;
final _hash2 = 'b' * 64;
final _key = Uint8List.fromList(List.filled(32, 7));

String _entry({int version = 1, int deleted = 0, String? parent = _parent}) {
  final e = keyVoucherObjectEntry(
    id: _id,
    objectType: 'node',
    parentRef: parent,
    targetUserId: null,
    isDeleted: deleted,
    version: version,
    payloadHash: _hash1,
    signerId: _signer,
    signingPk: _key,
  )!;
  return keyVoucherKey(e.$1, e.$2, e.$3);
}

Map<String, dynamic> _row(Map<String, dynamic> extra) => {
  'id': _id,
  'object_type': 'node',
  'parent_ref': _parent,
  'signer_id': _signer,
  'is_deleted': 0,
  ...extra,
};

Set<String> _held(Map<String, dynamic> extra) =>
    SyncService.heldVoucherKeys([_row(extra)], (_) => [_key]);

void main() {
  test('a clean row is held as it is', () {
    expect(
      _held({
        'version': 1,
        'payload_hash': _hash1,
        'base_version': 1,
        'base_hash': _hash1,
        'queued': 0,
      }),
      {_entry()},
    );
  });

  test('an unsent tombstone with the same payload is not held', () {
    expect(
      _held({
        'version': 2,
        'payload_hash': _hash1,
        'is_deleted': 1,
        'base_version': 1,
        'base_hash': _hash1,
        'queued': 1,
      }),
      isEmpty,
    );
  });

  test('an unsent edit is not held', () {
    expect(
      _held({
        'version': 2,
        'payload_hash': _hash2,
        'base_version': 1,
        'base_hash': _hash1,
        'queued': 1,
      }),
      isEmpty,
    );
  });

  test('the entry names the parent and the tombstone flag', () {
    final held = _held({'version': 1, 'payload_hash': _hash1, 'queued': 0});
    expect(held.contains(_entry(deleted: 1)), isFalse);
    expect(held.contains(_entry(parent: null)), isFalse);
  });
}
