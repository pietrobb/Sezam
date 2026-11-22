// docs/ROOT_CAUSE_PLAN.md S4 (INV-3), review e443cbc goal #428: a pulled
// object counts as signed only when the values the phone keeps are exactly
// the ones its signature covers. buildSyncSignatureData wrote is_deleted into
// a Uint8List and version into ByteData.setUint32, both truncating: a server
// sending is_deleted 257 or version 2^32 + 1 verified as 1 and was kept as
// sent (a deleted row with is_deleted 257 reads as live: `== 1` checks).

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/crypto_service.dart';

void main() {
  final crypto = CryptoService();
  final hash = 'ab' * 32;

  List<int> message({required int isDeleted, required int version}) =>
      crypto.buildSyncSignatureData(
        id: '01HZZZZZZZZZZZZZZZZZZZZZZZ',
        objectType: 'node',
        parentRef: null,
        targetUserId: null,
        isDeleted: isDeleted,
        version: version,
        payloadHashHex: hash,
      );

  test('the signed values are packed as they are', () {
    expect(message(isDeleted: 1, version: 1), isNotEmpty);
    expect(message(isDeleted: 0, version: 0xFFFFFFFF), isNotEmpty);
  });

  test('a value the signature cannot cover is refused, not truncated', () {
    for (final isDeleted in [257, 256, -1, 2]) {
      expect(
        () => message(isDeleted: isDeleted, version: 1),
        throwsArgumentError,
        reason: 'is_deleted $isDeleted',
      );
    }
    for (final version in [0x100000001, -1]) {
      expect(
        () => message(isDeleted: 0, version: version),
        throwsArgumentError,
        reason: 'version $version',
      );
    }
  });
}
