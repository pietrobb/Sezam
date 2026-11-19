// Review 526419e #1: the phone pushed every dirty object in one request. The
// server takes at most 1000 objects / 16 MiB per request and 1 MiB per
// object, so an import or one big note got a 422 on every sync and nothing
// was ever marked pushed. The push is now split, and an object the server
// can never take stays local, reported, without blocking the rest.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_limits.dart';
import 'package:sezam_mobile/services/sync_service.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;
  late SyncService sync;
  final requests = <List<Map<String, dynamic>>>[];

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_push_split_');
    await setUpPhone(appDir.path);
    final client = MockClient((request) async {
      if (request.bodyBytes.length > 16 * 1024 * 1024) {
        return http.Response('{"detail": "body too large"}', 413);
      }
      final objects = ((jsonDecode(request.body) as Map)['objects'] as List)
          .cast<Map<String, dynamic>>();
      if (objects.length > 1000) {
        return http.Response('{"detail": "too many objects"}', 422);
      }
      requests.add(objects);
      return http.Response(
        jsonEncode({
          'accepted': [
            for (final o in objects) {'id': o['id'], 'commit_seq': 1},
          ],
          'conflicts': [],
        }),
        200,
      );
    });
    http.runWithClient(() {
      sync = SyncService()..configure('https://sezam.test');
    }, () => client);
    sync.setToken('jwt');
  });

  tearDownAll(() async {
    await DatabaseService().close();
    await appDir.delete(recursive: true);
  });

  Future<void> dirty(String id, int size) => DatabaseService().upsertObject(
    id: id,
    objectType: 'entry',
    payload: Uint8List(size),
    version: 1,
    payloadHash: '0' * 64,
    clientSignature: Uint8List(64),
    queued: true,
  );

  String id(int i) => i.toString().padLeft(26, '0');

  test('1206 objects go out in chunks and all are marked pushed', () async {
    // Seed one import transaction, not 1206 individual durable commits.
    // The push below still exercises the real per-object acknowledgements.
    final batch = (await DatabaseService().database).batch();
    for (var i = 0; i < 1206; i++) {
      batch.insert('vault_objects', {
        'id': id(i), 'object_type': 'entry', 'payload': Uint8List(100),
        'version': 1, 'is_deleted': 0,
        'payload_hash': '0' * 64, 'client_signature': Uint8List(64),
        'modified_at': DateTime.now().millisecondsSinceEpoch,
      });
      batch.insert('outbox', {'kind': 'write', 'object_id': id(i)});
    }
    await batch.commit(noResult: true);
    final result = await sync.push();
    expect(result.accepted, 1206);
    expect(requests.length, greaterThan(1));
    expect(requests.every((r) => r.length <= maxPushObjects), isTrue);
    expect(await DatabaseService().getDirtyObjects(), isEmpty);
  });

  test('over 16 MiB is split by bytes; an object over 1 MiB stays', () async {
    requests.clear();
    for (var i = 0; i < 20; i++) {
      await dirty(id(5000 + i), 900 * 1024);
    }
    await dirty(id(9999), 1100 * 1024);
    final result = await sync.push();
    expect(result.accepted, 20);
    expect(result.conflicts, 1);
    expect(result.errors.single, contains('1 MiB'));
    expect(requests.length, greaterThan(1));
    final left = await DatabaseService().getDirtyObjects();
    expect(left.map((r) => r['id']), [id(9999)]);
  });

  test('an entry over 1 MiB is refused when saved', () {
    expect(
      () => requireSyncablePayload(Uint8List(1100 * 1024)),
      throwsA(isA<SyncObjectTooLargeException>()),
    );
    requireSyncablePayload(Uint8List(1024 * 1024));
  });
}
