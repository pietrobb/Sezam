// Review 688edcb V4: an archived (leaked) identity key vouches only for
// objects committed before its rotation. The phone takes the bound
// (retired_seq) from GET /api/users/:id/keys, pins the first one it saw so the
// server cannot stretch it later, and drops an archive whose rotation the old
// key itself did not authorize.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
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

  Future<List<Uint8List>> resolve(
    Map<String, dynamic> keys,
    Map<String, int> bounds,
    Map<String, String> settings,
  ) => SyncService.resolveAuthorSigningKeys(
    ownerId: owner,
    currentUserId: 'local-user',
    currentUserSigningPk: Uint8List(32),
    loadKnownKey: (_) async => null,
    fetchPublicKeys: (_) async => keys,
    saveKnownKey: (_) async {},
    archiveBoundsOut: bounds,
    loadSetting: (key) async => settings[key],
    saveSetting: (key, value) async => settings[key] = value,
  );

  test('archived key vouches only up to its rotation, current key always', () {
    final current = Uint8List.fromList(List<int>.filled(32, 1));
    final archived = Uint8List.fromList(List<int>.filled(32, 2));
    final bounds = {bytesToHex(archived): 10};
    bool may(Uint8List pk, int since, int seq) =>
        SyncService.keyMayVouch(pk, bounds, sinceSeq: since, commitSeq: seq);

    expect(may(current, 0, 999), isTrue);
    expect(may(archived, 0, 10), isTrue);
    expect(may(archived, 0, 11), isFalse);
    // A delta from seq 10 on never carries what the old key could sign.
    expect(may(archived, 10, 10), isFalse);
  });

  test('the first bound is pinned; a later, larger one is ignored', () async {
    final first = rotated(retiredSeq: 10);
    final bounds = <String, int>{};
    final settings = <String, String>{};
    final ring = await resolve(first.keys, bounds, settings);
    final oldHex = bytesToHex(first.oldSigningPk);
    expect(ring.map(bytesToHex), contains(oldHex));
    expect(bounds[oldHex], 10);

    final archive =
        (first.keys['archived_keys'] as List).single as Map<String, dynamic>;
    archive['retired_seq'] = 1000000;
    final stretched = <String, int>{};
    await resolve(first.keys, stretched, settings);
    expect(stretched[oldHex], 10);
  });

  test('without a bound the archived key vouches for nothing pulled', () async {
    final legacy = rotated(retiredSeq: null);
    final bounds = <String, int>{};
    await resolve(legacy.keys, bounds, {});
    expect(bounds[bytesToHex(legacy.oldSigningPk)], 0);
  });

  test('an archive the old key did not authorize is not trusted', () async {
    final forged = rotated(forgeAuthorization: true);
    final ring = await resolve(forged.keys, {}, {});
    expect(ring, hasLength(1));
    expect(
      ring.map(bytesToHex),
      isNot(contains(bytesToHex(forged.oldSigningPk))),
    );
  });
}
