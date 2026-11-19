import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

void main() {
  final crypto = CryptoService();

  test('idempotent push retry preserves an existing commit sequence', () {
    expect(buildMarkCleanUpdate(null, version: 3, payloadHash: 'h'), {
      'base_version': 3,
      'base_hash': 'h',
    });
    expect(buildMarkCleanUpdate(42, version: 3, payloadHash: 'h'), {
      'commit_seq': 42,
      'base_version': 3,
      'base_hash': 'h',
    });
  });

  test('foreign author key is pinned for signature verification', () async {
    final signingPk = Uint8List.fromList(List<int>.filled(32, 7));
    final encryptionPk = Uint8List.fromList(List<int>.generate(32, (i) => i));
    Map<String, dynamic>? pinned;

    final resolved = await SyncService.resolveAuthorSigningKeys(
      ownerId: 'foreign-user',
      currentUserId: 'local-user',
      currentUserSigningPk: Uint8List(32),
      loadKnownKey: (_) async => pinned,
      fetchPublicKeys: (_) async => {
        'signing_pk': bytesToHex(signingPk),
        'encryption_pk': bytesToHex(encryptionPk),
      },
      saveKnownKey: (key) async => pinned = key,
    );

    expect(resolved.single, orderedEquals(signingPk));
    expect(pinned?['user_id'], 'foreign-user');
    expect(
      pinned?['fingerprint'],
      crypto.computeFingerprint(signingPk, encryptionPk),
    );
  });

  test(
    'uncertified historical keys are ignored and the current pin is kept',
    () async {
      final currentSigningPk = Uint8List.fromList(List<int>.filled(32, 7));
      final currentEncryptionPk = Uint8List.fromList(List<int>.filled(32, 8));
      final oldSigningPk = Uint8List.fromList(List<int>.filled(32, 9));
      final oldEncryptionPk = Uint8List.fromList(List<int>.filled(32, 10));
      Map<String, dynamic>? pinned;

      final resolved = await SyncService.resolveAuthorSigningKeys(
        ownerId: 'foreign-user',
        currentUserId: 'local-user',
        currentUserSigningPk: Uint8List(32),
        loadKnownKey: (_) async => pinned,
        fetchPublicKeys: (_) async => {
          'signing_pk': bytesToHex(currentSigningPk),
          'encryption_pk': bytesToHex(currentEncryptionPk),
          'archived_keys': [
            {
              'signing_pk': bytesToHex(oldSigningPk),
              'encryption_pk': bytesToHex(oldEncryptionPk),
              'key_fingerprint': crypto.computeFingerprint(
                oldSigningPk,
                oldEncryptionPk,
              ),
              'archived_at': 1,
            },
          ],
        },
        saveKnownKey: (key) async => pinned = key,
      );

      // No rotation certificate from the successor key: the server alone
      // cannot make clients trust a "historical" key.
      expect(resolved, hasLength(1));
      expect(resolved.first, orderedEquals(currentSigningPk));
      expect(pinned?['signing_pk'], orderedEquals(currentSigningPk));
    },
  );

  test(
    'changed foreign key fails closed without replacing pinned key',
    () async {
      final originalSigningPk = Uint8List.fromList(List<int>.filled(32, 1));
      final originalEncryptionPk = Uint8List.fromList(List<int>.filled(32, 2));
      final changedSigningPk = Uint8List.fromList(List<int>.filled(32, 3));
      final changedEncryptionPk = Uint8List.fromList(List<int>.filled(32, 4));
      final pinned = <String, dynamic>{
        'user_id': 'foreign-user',
        'signing_pk': originalSigningPk,
        'encryption_pk': originalEncryptionPk,
        'fingerprint': crypto.computeFingerprint(
          originalSigningPk,
          originalEncryptionPk,
        ),
        'first_seen': 1,
        'last_verified': 1,
      };
      var writes = 0;

      await expectLater(
        SyncService.resolveAuthorSigningKeys(
          ownerId: 'foreign-user',
          currentUserId: 'local-user',
          currentUserSigningPk: Uint8List(32),
          loadKnownKey: (_) async => pinned,
          fetchPublicKeys: (_) async => {
            'signing_pk': bytesToHex(changedSigningPk),
            'encryption_pk': bytesToHex(changedEncryptionPk),
          },
          saveKnownKey: (_) async => writes++,
        ),
        throwsA(isA<TofuKeyChangeException>()),
      );
      expect(writes, 0);
      expect(pinned['signing_pk'], same(originalSigningPk));
    },
  );

  test('malformed or unavailable foreign keys fail closed', () async {
    Future<List<Uint8List>> resolve(
      Future<Map<String, dynamic>> Function(String) fetch,
    ) {
      return SyncService.resolveAuthorSigningKeys(
        ownerId: 'foreign-user',
        currentUserId: 'local-user',
        currentUserSigningPk: Uint8List(32),
        loadKnownKey: (_) async => null,
        fetchPublicKeys: fetch,
        saveKnownKey: (_) async {},
      );
    }

    await expectLater(
      resolve((_) async => {'signing_pk': '00', 'encryption_pk': '00'}),
      throwsA(isA<SyncIntegrityException>()),
    );
    await expectLater(
      resolve((_) async => throw Exception('network error')),
      throwsA(isA<SyncIntegrityException>()),
    );
  });

  test('recovery requires the canonical server user object ID', () {
    const canonicalUserObjectId = '01ARZ3NDEKTSV4RRFFQ69G5FB0';

    expect(
      requireCanonicalUserObjectId({'user_id': canonicalUserObjectId}),
      canonicalUserObjectId,
    );
    expect(
      () => requireCanonicalUserObjectId({}),
      throwsA(isA<FormatException>()),
    );
    expect(
      () => requireCanonicalUserObjectId({'user_id': 'local'}),
      throwsA(isA<FormatException>()),
    );
  });

  test('keypair AAD binds recovery to the canonical server ID', () {
    const kekDekId = '01ARZ3NDEKTSV4RRFFQ69G5FB1';
    const provisionalUserObjectId = '01ARZ3NDEKTSV4RRFFQ69G5FAV';
    const canonicalUserObjectId = '01ARZ3NDEKTSV4RRFFQ69G5FB0';

    final canonicalAad = crypto.buildAAD(
      BlobKind.keypairWrap,
      kekDekId,
      canonicalUserObjectId,
      1,
    );
    final provisionalAad = crypto.buildAAD(
      BlobKind.keypairWrap,
      kekDekId,
      provisionalUserObjectId,
      1,
    );

    expect(canonicalAad, hasLength(59));
    expect(
      String.fromCharCodes(canonicalAad.sublist(29, 55)),
      canonicalUserObjectId,
    );
    expect(canonicalAad, isNot(orderedEquals(provisionalAad)));
  });

  test('SEZAMK02 codec matches desktop offsets and round-trips metadata', () {
    const kekDekId = '01ARZ3NDEKTSV4RRFFQ69G5FB1';
    const userObjectId = '01ARZ3NDEKTSV4RRFFQ69G5FB0';
    final envelope = Uint8List(69)
      ..[0] = 1
      ..[1] = 1
      ..[2] = BlobKind.keypairWrap
      ..setRange(3, 29, kekDekId.codeUnits);
    final backup = SezamKeyBackup(
      argon2Salt: Uint8List.fromList(List<int>.generate(16, (i) => i)),
      timeCost: 2,
      memoryCost: 131072,
      parallelism: 4,
      signingPublicKey: Uint8List.fromList(List<int>.filled(32, 7)),
      encryptionPublicKey: Uint8List.fromList(List<int>.filled(32, 8)),
      kekDekId: kekDekId,
      userObjectId: userObjectId,
      encryptedEnvelope: envelope,
    );

    final encoded = encodeSezamKeyBackup(backup);
    final header = ByteData.sublistView(encoded);
    expect(String.fromCharCodes(encoded.sublist(0, 8)), 'SEZAMK02');
    expect(header.getUint16(8, Endian.big), 16);
    expect(header.getUint32(10, Endian.big), 2);
    expect(header.getUint32(14, Endian.big), 131072);
    expect(header.getUint32(18, Endian.big), 4);
    expect(header.getUint16(22, Endian.big), 64);
    expect(String.fromCharCodes(encoded.sublist(104, 130)), kekDekId);
    expect(String.fromCharCodes(encoded.sublist(130, 156)), userObjectId);

    final decoded = decodeSezamKeyBackup(encoded);
    expect(decoded.argon2Salt, orderedEquals(backup.argon2Salt));
    expect(decoded.signingPublicKey, orderedEquals(backup.signingPublicKey));
    expect(
      decoded.encryptionPublicKey,
      orderedEquals(backup.encryptionPublicKey),
    );
    expect(decoded.encryptedEnvelope, orderedEquals(envelope));
  });

  test('desktop 64-byte private key normalizes to mobile representation', () {
    const kekDekId = '01ARZ3NDEKTSV4RRFFQ69G5FB1';
    final signingSeed = Uint8List.fromList(List<int>.filled(32, 1));
    final signingPk = Uint8List.fromList(List<int>.filled(32, 2));
    final encryptionSk = Uint8List.fromList(List<int>.filled(32, 3));
    final encryptionPk = Uint8List.fromList(List<int>.filled(32, 4));
    final desktopPrivate = Uint8List(64)
      ..setRange(0, 32, signingSeed)
      ..setRange(32, 64, encryptionSk);
    final envelope = Uint8List(69)
      ..[0] = 1
      ..[1] = 1
      ..[2] = BlobKind.keypairWrap
      ..setRange(3, 29, kekDekId.codeUnits);
    final backup = SezamKeyBackup(
      argon2Salt: Uint8List(16),
      timeCost: 2,
      memoryCost: 131072,
      parallelism: 4,
      signingPublicKey: signingPk,
      encryptionPublicKey: encryptionPk,
      kekDekId: kekDekId,
      userObjectId: '01ARZ3NDEKTSV4RRFFQ69G5FB0',
      encryptedEnvelope: envelope,
    );
    Uint8List deriveSigningPk(Uint8List seed) {
      expect(seed, orderedEquals(signingSeed));
      return signingPk;
    }

    Uint8List deriveEncryptionPk(Uint8List secret) {
      expect(secret, orderedEquals(encryptionSk));
      return encryptionPk;
    }

    final normalized = normalizeSezamKeypair(
      backup,
      desktopPrivate,
      signingPublicKeyFromSeed: deriveSigningPk,
      encryptionPublicKeyFromSecret: deriveEncryptionPk,
    );

    expect(normalized, hasLength(96));
    expect(normalized.sublist(32, 64), orderedEquals(signingPk));
    expect(normalized.sublist(64, 96), orderedEquals(encryptionSk));

    final corruptedSigningPk = Uint8List.fromList(signingPk)..[0] ^= 1;
    var rejectedMaterialWasZeroized = false;
    expect(
      () => normalizeSezamKeypair(
        SezamKeyBackup(
          argon2Salt: backup.argon2Salt,
          timeCost: backup.timeCost,
          memoryCost: backup.memoryCost,
          parallelism: backup.parallelism,
          signingPublicKey: corruptedSigningPk,
          encryptionPublicKey: backup.encryptionPublicKey,
          kekDekId: backup.kekDekId,
          userObjectId: backup.userObjectId,
          encryptedEnvelope: backup.encryptedEnvelope,
        ),
        desktopPrivate,
        signingPublicKeyFromSeed: deriveSigningPk,
        encryptionPublicKeyFromSecret: deriveEncryptionPk,
        zeroize: (bytes) {
          bytes.fillRange(0, bytes.length, 0);
          rejectedMaterialWasZeroized = true;
        },
      ),
      throwsA(isA<FormatException>()),
    );
    expect(rejectedMaterialWasZeroized, isTrue);
  });

  test(
    'canonical envelope validation rejects every plaintext header field',
    () {
      final envelope = Uint8List(69)
        ..[0] = EnvelopeConstants.algXChaCha20Poly1305
        ..[1] = EnvelopeConstants.schemaVersion
        ..[2] = BlobKind.dekWrap;

      crypto.validateEnvelopeHeader(
        envelope,
        expectedBlobKind: BlobKind.dekWrap,
      );
      for (final index in [0, 1, 2]) {
        final tampered = Uint8List.fromList(envelope)..[index] ^= 1;
        expect(
          () => crypto.validateEnvelopeHeader(
            tampered,
            expectedBlobKind: BlobKind.dekWrap,
          ),
          throwsA(isA<ArgumentError>()),
        );
      }
    },
  );

  test('SEZAMK02 codec rejects legacy and unbounded KDF metadata', () {
    expect(
      () => decodeSezamKeyBackup(
        Uint8List.fromList('SEZAMKEY'.codeUnits + List<int>.filled(200, 0)),
      ),
      throwsA(isA<FormatException>()),
    );

    const kekDekId = '01ARZ3NDEKTSV4RRFFQ69G5FB1';
    final envelope = Uint8List(69)
      ..[0] = 1
      ..[1] = 1
      ..[2] = BlobKind.keypairWrap
      ..setRange(3, 29, kekDekId.codeUnits);
    expect(
      () => encodeSezamKeyBackup(
        SezamKeyBackup(
          argon2Salt: Uint8List(16),
          timeCost: 2,
          memoryCost: 262145,
          parallelism: 4,
          signingPublicKey: Uint8List(32),
          encryptionPublicKey: Uint8List(32),
          kekDekId: kekDekId,
          userObjectId: '01ARZ3NDEKTSV4RRFFQ69G5FB0',
          encryptedEnvelope: envelope,
        ),
      ),
      throwsA(isA<FormatException>()),
    );
  });

  test('folder envelope ACL derives read-only and write access', () {
    final objects = <Map<String, dynamic>>[
      {
        'id': 'dek-1',
        'object_type': 'dek',
        'parent_ref': 'folder-1',
        'is_deleted': 0,
      },
      {
        'id': 'read-envelope',
        'object_type': 'envelope',
        'parent_ref': 'dek-1',
        'target_user_id': 'reader',
        'access_level': 'read',
        'is_deleted': 0,
      },
      {
        'id': 'foreign-write-envelope',
        'object_type': 'envelope',
        'parent_ref': 'dek-1',
        'target_user_id': 'other-user',
        'access_level': 'write',
        'is_deleted': 0,
      },
      {
        'id': 'deleted-write-envelope',
        'object_type': 'envelope',
        'parent_ref': 'dek-1',
        'target_user_id': 'reader',
        'access_level': 'write',
        'is_deleted': 1,
      },
    ];

    expect(deriveFolderAccessLevels(objects, 'reader'), {'folder-1': 'read'});
    objects.add({
      'id': 'write-envelope',
      'object_type': 'envelope',
      'parent_ref': 'dek-1',
      'target_user_id': 'reader',
      'access_level': 'write',
      'is_deleted': 0,
    });
    expect(deriveFolderAccessLevels(objects, 'reader'), {'folder-1': 'write'});
  });

  test('shared entry editing fails closed without folder write access', () {
    VaultEntry sharedEntry(String? accessLevel) => VaultEntry(
      id: 'entry-1',
      name: 'Shared',
      fields: const [],
      parentRef: 'folder-1',
      ownerId: 'owner',
      writePolicy: 'shared',
      accessLevel: accessLevel,
    );

    expect(sharedEntry('read').canEdit('reader', false), isFalse);
    expect(sharedEntry(null).canEdit('reader', false), isFalse);
    expect(sharedEntry('write').canEdit('reader', false), isTrue);
    expect(sharedEntry('read').canEdit('owner', false), isTrue);
    expect(sharedEntry('read').canEdit('reader', true), isTrue);
  });

  test('canonical audit payload and signed bytes match desktop framing', () {
    const auditId = '01ARZ3NDEKTSV4RRFFQ69G5FB0';
    const actorId = '01ARZ3NDEKTSV4RRFFQ69G5FB1';
    final payload = Uint8List.fromList(
      utf8.encode(
        jsonEncode({
          'action': 'write',
          'actor_id': actorId,
          'encrypted_details': '',
          'format': 'sezam-audit-v1',
          'id': auditId,
          'parent_ids': <String>[],
          'signature': List.filled(64, '00').join(),
          'timestamp': 7,
        }),
      ),
    );
    final record = parseCanonicalAuditRecord(auditId, payload, 2);
    final canonical = buildAuditCanonical(record, crypto);

    expect(canonical.sublist(0, 26), orderedEquals(ascii.encode(auditId)));
    expect(canonical.sublist(26, 52), orderedEquals(ascii.encode(actorId)));
    expect(ByteData.sublistView(canonical).getUint16(52, Endian.big), 2);
    expect(utf8.decode(canonical.sublist(54, 56)), '[]');
    expect(ByteData.sublistView(canonical).getUint16(56, Endian.big), 5);
    expect(utf8.decode(canonical.sublist(58, 63)), 'write');
    expect(ByteData.sublistView(canonical).getUint64(63, Endian.big), 7);
    expect(canonical.sublist(71), orderedEquals(Uint8List(32)));
  });

  test('audit DAG rejects missing parents and cycles', () {
    const actorId = '01ARZ3NDEKTSV4RRFFQ69G5FB1';
    CanonicalAuditRecord record(String id, List<String> parents) =>
        CanonicalAuditRecord(
          id: id,
          actorId: actorId,
          parentIds: parents,
          action: 'write',
          timestamp: 1,
          encryptedDetails: Uint8List(0),
          signature: Uint8List(64),
        );

    const root = '01ARZ3NDEKTSV4RRFFQ69G5FB2';
    const child = '01ARZ3NDEKTSV4RRFFQ69G5FB3';
    validateAuditDag([
      record(root, const []),
      record(child, const [root]),
    ]);
    expect(
      () => validateAuditDag([
        record(child, const [root]),
      ]),
      throwsA(isA<SyncIntegrityException>()),
    );
    expect(
      () => validateAuditDag([
        record(root, const [child]),
        record(child, const [root]),
      ]),
      throwsA(isA<SyncIntegrityException>()),
    );
  });

  test('pull object keeps only canonical envelope access levels', () {
    Map<String, dynamic> pullJson(Object? accessLevel) => {
      'id': 'envelope-1',
      'object_type': 'envelope',
      'payload': '',
      'owner_id': 'owner',
      'signature_user_id': 'owner',
      'access_level': accessLevel,
      'version': 1,
      'commit_seq': 1,
      'is_deleted': 0,
      'payload_hash': '',
      'modified_at': 1,
    };

    expect(PullObject.fromJson(pullJson('read')).accessLevel, 'read');
    expect(PullObject.fromJson(pullJson('write')).accessLevel, 'write');
    expect(PullObject.fromJson(pullJson('invalid')).accessLevel, isNull);
  });
}
