// tests/vectors/audit.json on the phone (docs/CORE_UNIFICATION.md U6d): an
// audit record's signed bytes, its pull-side parse and the DAG check are the
// core's.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';

void main() {
  final vectors =
      jsonDecode(File('../tests/vectors/audit.json').readAsStringSync())
          as Map<String, dynamic>;
  List<Map<String, dynamic>> cases(String name) =>
      (vectors[name] as List).cast<Map<String, dynamic>>();
  // A Dart int holds a timestamp up to 2**63 - 1.
  bool fits(Map<String, dynamic> v) => v['timestamp'] is int;

  CanonicalAuditRecord record(Map<String, dynamic> v) => CanonicalAuditRecord(
    id: v['id'] as String,
    actorId: v['actor_id'] as String,
    parentIds: (v['parent_ids'] as List).cast<String>(),
    action: v['action'] as String,
    timestamp: v['timestamp'] as int,
    encryptedDetails: hexToBytes(v['encrypted_details'] as String),
    signature: Uint8List(64),
  );

  test('signed bytes match the vectors', () {
    final all = cases('message');
    final checked = all.where(fits).toList();
    expect(checked.length, 18);
    for (final v in checked) {
      expect(bytesToHex(buildAuditCanonical(record(v))), v['message']);
    }
  });

  test('a pulled record parses as the desktop parsed it', () {
    for (final v in cases('parse').where(fits)) {
      final r = parseCanonicalAuditRecord(
        v['id'] as String,
        Uint8List.fromList(utf8.encode(v['payload'] as String)),
        v['version'] as int,
      );
      expect(r.actorId, v['actor_id']);
      expect(r.action, v['action']);
      expect(r.timestamp, v['timestamp']);
      expect(r.parentIds, v['parent_ids']);
      expect(bytesToHex(r.encryptedDetails), v['encrypted_details']);
      expect(bytesToHex(r.signature), v['signature']);
      expect(bytesToHex(buildAuditCanonical(r)), v['message']);
    }
  });

  test('a bad record is refused', () {
    for (final v in cases('parse_refused')) {
      expect(
        () => parseCanonicalAuditRecord(
          v['id'] as String,
          Uint8List.fromList(utf8.encode(v['payload'] as String)),
          v['version'] as int,
          isDeleted: v['is_deleted'] == true,
        ),
        throwsA(isA<SyncIntegrityException>()),
        reason: v['why'] as String,
      );
    }
  });

  test('the DAG check matches the vectors', () {
    for (final c in cases('dag')) {
      final records = [
        for (final r in (c['records'] as List).cast<Map<String, dynamic>>())
          CanonicalAuditRecord(
            id: r['id'] as String,
            actorId: 'a',
            parentIds: (r['parent_ids'] as List).cast<String>(),
            action: 'x',
            timestamp: 0,
            encryptedDetails: Uint8List(0),
            signature: Uint8List(64),
          ),
      ];
      if (c['ok'] == true) {
        validateAuditDag(records);
      } else {
        expect(
          () => validateAuditDag(records),
          throwsA(isA<SyncIntegrityException>()),
          reason: c['why'] as String,
        );
      }
    }
  });
}
