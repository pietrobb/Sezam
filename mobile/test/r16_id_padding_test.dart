// R16-Z SM3 (INV-3), deep state machine run on 736ade3: a 26-byte id field of
// a signed or sealed value holds exactly one id. The phone cut a longer id to
// its first 26 bytes (_padToLength, padRight(26).substring(0, 26)), so a
// server appending one character to an entry's parent_ref kept the creator's
// signature valid and the phone kept the parent it was sent.

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/crypto_service.dart';

void main() {
  final crypto = CryptoService();
  const id = '01M84VW3C2YKNF1AHKTC84CS4C';
  const folder = '01M84VVY89SQQ6B0MXD8SBQWDE';
  const user = '01M84VVZ6FGBBBNETGYZRCY153';
  final hash = 'ab' * 32;

  List<int> message({String i = id, String? p = folder, String? t = user}) =>
      crypto.buildSyncSignatureData(
        id: i,
        objectType: 'entry',
        parentRef: p,
        targetUserId: t,
        isDeleted: 0,
        version: 1,
        payloadHashHex: hash,
      );

  test('an id of up to 26 bytes is packed as it is', () {
    expect(message().sublist(0, 26), id.codeUnits);
    expect(crypto.buildAAD(1, folder, 'ab', 1).sublist(29, 55),
        [97, 98, ...List.filled(24, 0)]);
  });

  test('a longer id is refused, not cut to one a signature covers', () {
    for (final tail in ['x', '\x00', 'AB']) {
      expect(() => message(i: id + tail), throwsArgumentError, reason: 'id+$tail');
      expect(() => message(p: folder + tail), throwsArgumentError, reason: 'parent+$tail');
      expect(() => message(t: user + tail), throwsArgumentError, reason: 'target+$tail');
      expect(() => crypto.buildAAD(1, folder, id + tail, 1), throwsArgumentError,
          reason: 'aad object+$tail');
      expect(() => crypto.buildAAD(1, folder + tail, id, 1), throwsArgumentError,
          reason: 'aad dek+$tail');
    }
    expect(() => message(p: 'a\u010d'), throwsArgumentError, reason: 'non-ASCII');
  });
}
