// Review c02cc47 R17-L: Settings > import unsent changes puts an edit on the
// base the file names (VaultService.reapplyUnsentChanges, updateOnItsBase:
// rebaseOn entryBase(object)). Nothing authenticates that base; the phone
// vouched it as a held server copy. Rows come from
// DatabaseService.getAllObjects (`queued`: the outbox holds a write).
//
// heldVoucherKeys took the key ring as a second argument from R17-N1 on; the
// call goes through Function.apply so the same file runs on older trees.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/unsent_changes.dart';

const _id = '01M84TV8KA51X75QJYNS3S1ECC';
const _signer = '01M84TV8KA51X75QJYNS3S1ECD';
final _hash1 = 'a' * 64;
final _hash2 = 'b' * 64;
final _key = Uint8List.fromList(List.filled(32, 7));

Set<String> _held(List<Map<String, dynamic>> rows) {
  final Function held = SyncService.heldVoucherKeys;
  try {
    return Function.apply(held, [
          rows,
          (String _) => [_key],
        ])
        as Set<String>;
  } on NoSuchMethodError {
    return Function.apply(held, [rows]) as Set<String>;
  }
}

void main() {
  test('the base an imported file names is not held', () {
    final exported = parseUnsentExport(
      encodeUnsentExport([
        {
          'id': _id,
          'object_type': 'node',
          'version': 6,
          'payload': 'AA==',
          'base_version': 5,
          'base_hash': _hash1,
        },
      ]),
    ).single;
    final base = entryBase(exported)!;
    // The row the import leaves: the edit queued on the file's base.
    expect(
      _held([
        {
          'id': _id,
          'object_type': 'node',
          'parent_ref': null,
          'signer_id': _signer,
          'is_deleted': 0,
          'version': base.version + 1,
          'payload_hash': _hash2,
          'base_version': base.version,
          'base_hash': base.hash,
          'queued': 1,
        },
      ]),
      isEmpty,
    );
  });
}
