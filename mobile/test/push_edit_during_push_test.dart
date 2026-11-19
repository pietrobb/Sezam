// Review 526419e #2: an edit saved while a push was out was marked clean
// with the version that was sent, so it never reached the server. Only the
// sent version is marked clean now; the newer edit stays dirty.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;
  late SyncService sync;
  final entryId = '1'.padLeft(26, '0');
  Future<void> Function()? duringRequest;

  Future<void> save(int version) => DatabaseService().upsertObject(
    id: entryId,
    objectType: 'entry',
    payload: Uint8List(100 + version),
    version: version,
    payloadHash: '0' * 64,
    clientSignature: Uint8List(64),
    queued: true,
  );

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_push_edit_');
    await setUpPhone(appDir.path);
    final client = MockClient((request) async {
      final objects = ((jsonDecode(request.body) as Map)['objects'] as List)
          .cast<Map<String, dynamic>>();
      final hook = duringRequest;
      duringRequest = null;
      if (hook != null) await hook();
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

  test('an edit saved during the push stays dirty and goes out next', () async {
    await save(2);
    duringRequest = () => save(3);
    await sync.push();
    var dirty = await DatabaseService().getDirtyObjects();
    expect(dirty.map((r) => [r['id'], r['version']]), [
      [entryId, 3],
    ]);

    await sync.push();
    dirty = await DatabaseService().getDirtyObjects();
    expect(dirty, isEmpty);
  });

  test('a failed acknowledgement transaction leaves the whole chunk retryable', () async {
    final otherId = '2'.padLeft(26, '0');
    await save(4);
    await DatabaseService().upsertObject(
      id: otherId, objectType: 'entry', payload: Uint8List(100),
      version: 1, payloadHash: '0' * 64,
      clientSignature: Uint8List(64), queued: true,
    );
    final db = await DatabaseService().database;
    await db.execute('''
      CREATE TRIGGER fail_ack BEFORE DELETE ON outbox
      WHEN OLD.object_id = '$otherId'
      BEGIN SELECT RAISE(ABORT, 'simulated ack failure'); END
    ''');
    try {
      await expectLater(sync.push(), throwsA(predicate<Object>(
        (e) => e.toString().contains('simulated ack failure'),
      )));
      final dirty = await DatabaseService().getDirtyObjects();
      expect(dirty.map((row) => row['id']).toSet(), {entryId, otherId});
    } finally {
      await db.execute('DROP TRIGGER fail_ack');
    }
    await sync.push();
    expect(await DatabaseService().getDirtyObjects(), isEmpty);
  });
}
