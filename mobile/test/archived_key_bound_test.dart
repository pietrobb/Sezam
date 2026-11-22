// Review 688edcb V4: the phone drops an archive whose rotation the old key
// itself did not authorize. Goal #443: an archived (leaked) identity key
// vouches only for what a voucher list of the current key names; the bound
// the server serves (retired_seq) is not read.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/key_vouchers.dart';
import 'package:sezam_mobile/services/sync_service.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;
  late CryptoService crypto;

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_archive_bound_');
    await setUpPhone(appDir.path);
    crypto = CryptoService();
    initPhoneCrypto();
  });

  tearDownAll(() => appDir.delete(recursive: true));

  const owner = '01ARZ3NDEKTSV4RRFFQ69G5FB0';

  ({Map<String, dynamic> keys, Uint8List oldSigningPk}) rotated({
    Object? retiredSeq = 10,
    bool forgeAuthorization = false,
  }) {
    final oldSigning = crypto.generateSigningKeypair();
    final oldEncryption = crypto.generateEncryptionKeypair();
    final newSigning = crypto.generateSigningKeypair();
    final newEncryption = crypto.generateEncryptionKeypair();
    final message = SyncService.keyRotationMessage(
      owner,
      oldSigning.pk,
      oldEncryption.pk,
      newSigning.pk,
      newEncryption.pk,
    );
    final authorization = crypto.signChallenge(
      forgeAuthorization ? Uint8List.fromList([1, 2, 3]) : message,
      oldSigning.sk,
    );
    return (
      keys: {
        'signing_pk': bytesToHex(newSigning.pk),
        'encryption_pk': bytesToHex(newEncryption.pk),
        'archived_keys': [
          {
            'signing_pk': bytesToHex(oldSigning.pk),
            'encryption_pk': bytesToHex(oldEncryption.pk),
            'key_fingerprint': crypto.computeFingerprint(
              oldSigning.pk,
              oldEncryption.pk,
            ),
            'archived_at': 1,
            'successor_signing_pk': bytesToHex(newSigning.pk),
            'rotation_signature': bytesToHex(
              crypto.signChallenge(message, newSigning.sk),
            ),
            'authorization_signature': bytesToHex(authorization),
            'retired_seq': retiredSeq,
          },
        ],
      },
      oldSigningPk: oldSigning.pk,
    );
  }

  Future<List<Uint8List>> resolve(Map<String, dynamic> keys) =>
      SyncService.resolveAuthorSigningKeys(
        ownerId: owner,
        currentUserId: 'local-user',
        currentUserSigningPk: Uint8List(32),
        loadKnownKey: (_) async => null,
        fetchPublicKeys: (_) async => keys,
        saveKnownKey: (_) async {},
      );

  test('an archived key vouches only for a vouched entry, the current key always', () async {
    final keys = rotated(retiredSeq: 1000000).keys;
    final ring = await resolve(keys);
    expect(ring, hasLength(2));
    final listed = keyVoucherKey('01JOBJ00000000000000000001', 3, 'ab' * 32);
    bool may(Uint8List pk, Set<String> vouched, String entry) =>
        SyncService.keyMayVouch(pk, ring, () => vouched, entry);

    expect(may(ring.first, const {}, listed), isTrue);
    expect(may(ring.last, {listed}, listed), isTrue);
    // Whatever retired_seq the server serves, nothing unlisted counts.
    expect(may(ring.last, const {}, listed), isFalse);
    expect(
      may(ring.last, {listed}, keyVoucherKey('01JOBJ00000000000000000001', 4, 'ab' * 32)),
      isFalse,
    );
  });

  test('an archive the old key did not authorize is not trusted', () async {
    final forged = rotated(forgeAuthorization: true);
    final ring = await resolve(forged.keys);
    expect(ring, hasLength(1));
    expect(
      ring.map(bytesToHex),
      isNot(contains(bytesToHex(forged.oldSigningPk))),
    );
  });
}
