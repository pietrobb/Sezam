// T5 (code review HEAD 2c7e809): the mobile client must reproduce the shared
// cross-client golden vectors byte for byte. The vectors are generated from
// the desktop reference (tests/test_cross_client_vectors.py) and also checked
// against the web client, so all three clients agree on these wire formats.
//
// libsodium is not available under `flutter test`, so only the pure-Dart
// framing is covered here: AAD, sync signature message, audit canonical form
// key-rotation certificate message and state_hash. The libsodium/Argon2
// vectors (DEK wrap v3, crypto_box, split KEK/auth proof) run on desktop + web.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/ai_brake_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';

void main() {
  final vectors =
      jsonDecode(File('../tests/vectors/cross_client.json').readAsStringSync())
          as Map<String, dynamic>;
  final crypto = CryptoService();

  test('AAD matches the shared vectors', () {
    for (final v in (vectors['aad'] as List).cast<Map<String, dynamic>>()) {
      final aad = crypto.buildAAD(
        v['blob_kind'] as int,
        v['dek_id'] as String,
        v['object_id'] as String,
        v['version'] as int,
      );
      expect(
        bytesToHex(aad),
        v['aad_hex'],
        reason: 'blob kind ${v['blob_kind']}',
      );
    }
  });

  test('sync signature message matches the shared vectors', () {
    for (final v
        in (vectors['sync_signature'] as List).cast<Map<String, dynamic>>()) {
      final message = crypto.buildSyncSignatureData(
        id: v['id'] as String,
        objectType: v['object_type'] as String,
        parentRef: v['parent_ref'] as String?,
        targetUserId: v['target_user_id'] as String?,
        isDeleted: v['is_deleted'] as int,
        version: v['version'] as int,
        payloadHashHex: v['payload_hash'] as String,
      );
      expect(
        bytesToHex(message),
        v['message_hex'],
        reason: v['object_type'] as String,
      );
    }
  });

  test('audit canonical form matches the shared vectors', () {
    for (final v
        in (vectors['audit_canonical'] as List).cast<Map<String, dynamic>>()) {
      final record = CanonicalAuditRecord(
        id: v['id'] as String,
        actorId: v['actor_id'] as String,
        parentIds: (v['parent_ids'] as List).cast<String>(),
        action: v['action'] as String,
        timestamp: v['timestamp'] as int,
        encryptedDetails: hexToBytes(v['encrypted_details_hex'] as String),
        signature: Uint8List(64),
      );
      expect(
        bytesToHex(buildAuditCanonical(record, crypto)),
        v['message_hex'],
        reason: v['action'] as String,
      );
    }
  });

  test('key rotation message matches the shared vectors', () {
    final v = vectors['key_rotation'] as Map<String, dynamic>;
    final message = SyncService.keyRotationMessage(
      v['user_id'] as String,
      hexToBytes(v['old_signing_pk_hex'] as String),
      hexToBytes(v['old_encryption_pk_hex'] as String),
      hexToBytes(v['new_signing_pk_hex'] as String),
      hexToBytes(v['new_encryption_pk_hex'] as String),
    );
    expect(bytesToHex(message), v['message_hex']);
  });

  test('ai_policy message matches the shared vector', () {
    final v = vectors['ai_policy'] as Map<String, dynamic>;
    final message = AiBrakeService.policyMessage(
      v['user_id'] as String,
      v['enabled'] as bool,
      v['epoch'] as int,
    );
    expect(bytesToHex(message), v['message_hex']);
  });

  test('entry envelope header is the canonical layout', () {
    final v = vectors['envelope'] as Map<String, dynamic>;
    final envelope = hexToBytes(v['envelope_hex'] as String);
    expect(envelope.sublist(0, 3), [1, 1, v['blob_kind']]);
    expect(ascii.decode(envelope.sublist(3, 29)), v['dek_id']);
    expect(crypto.isEncryptedEnvelope(envelope), isTrue);
  });

  test('state_hash matches the shared vector in any input order', () {
    final v = vectors['state_hash'] as Map<String, dynamic>;
    final objects = [
      for (final o in (v['objects'] as List).cast<Map<String, dynamic>>())
        <String, dynamic>{
          'id': o['id'] as String,
          'version': o['version'] as int,
          'payload': Uint8List.fromList(base64Decode(o['payload'] as String)),
        },
    ];
    expect(computeStateHash(objects, crypto, legacy: true), v['state_hash']);
    expect(
      computeStateHash(objects.reversed, crypto, legacy: true),
      v['state_hash'],
    );
  });

  test('R17-N1: the state hash covers the parent and the deleted flag', () {
    final v = vectors['state_hash_v2'] as Map<String, dynamic>;
    final objects = [
      for (final o in (v['objects'] as List).cast<Map<String, dynamic>>())
        <String, dynamic>{
          'id': o['id'] as String,
          'version': o['version'] as int,
          'payload': Uint8List.fromList(base64Decode(o['payload'] as String)),
          'parent_ref': o['parent_ref'],
          'is_deleted': o['is_deleted'],
        },
    ];
    expect(computeStateHash(objects.reversed, crypto), v['state_hash']);
    final first = objects.first;
    expect(
      computeStateHash([
        {...first, 'parent_ref': null},
        ...objects.skip(1),
      ], crypto),
      v['moved'],
    );
    expect(
      computeStateHash([
        {...first, 'is_deleted': 1},
        ...objects.skip(1),
      ], crypto),
      v['deleted'],
    );
  });

  test('desktop keypair payload expands to the 96-byte account layout', () {
    final v = vectors['keypair_wrap'] as Map<String, dynamic>;
    final envelopes = (v['envelopes'] as List).cast<Map<String, dynamic>>();
    final desktop = hexToBytes(envelopes.first['payload_hex'] as String);
    expect(desktop.length, 64);
    expect(
      bytesToHex(
        expandDesktopKeypair(
          desktop,
          hexToBytes(v['signing_pk_hex'] as String),
        ),
      ),
      v['keypair_hex'],
    );
    expect(envelopes.last['payload_hex'], v['keypair_hex']);
    for (final item in envelopes) {
      final envelope = hexToBytes(item['envelope_hex'] as String);
      expect(envelope.sublist(0, 3), [1, 1, BlobKind.keypairWrap]);
      expect(crypto.envelopeDekId(envelope), v['kek_id']);
    }
  });
}
