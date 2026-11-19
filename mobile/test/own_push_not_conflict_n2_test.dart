// Review d150605 N2: an edit saved while a push of the same entry was out
// stayed dirty (526419e #2), and the next pull brought back this device's own
// pushed copy as a "conflict" against it. Only a server copy other than the
// one the edit is based on is a conflict.

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
  final entryId = '2'.padLeft(26, '0');
  Future<void> Function()? duringRequest;
  // The content hash of a version this phone (or another device, [by]) wrote.
  String hash(int version, [String by = 'a']) => '$by$version'.padLeft(64, '0');

  Future<void> save(int version) => DatabaseService().upsertObject(
    id: entryId,
    objectType: 'entry',
    payload: Uint8List(100 + version),
    version: version,
    payloadHash: hash(version),
    clientSignature: Uint8List(64),
    queued: true,
  );

  Map<String, Object?> serverCopy(
    int version,
    int commitSeq, {
    String by = 'a',
  }) => {
    'id': entryId,
    'object_type': 'entry',
    'payload': Uint8List(100 + version),
    'version': version,
    'is_deleted': 0,
    'payload_hash': hash(version, by),
    'client_signature': Uint8List(64),
    'commit_seq': commitSeq,
  };

  Future<List<Map<String, dynamic>>> pull(
    int version,
    int commitSeq, {
    String by = 'a',
  }) => DatabaseService().applyPullAndCommitCheckpoint(
    objects: [serverCopy(version, commitSeq, by: by)],
    seq: commitSeq,
    checkpointKey: 'sync_checkpoint:test',
    encryptedCheckpoint: 'enc:v1:test',
  );

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_own_push_');
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
            for (final o in objects) {'id': o['id'], 'commit_seq': 7},
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

  test(
    'own pushed copy pulled back under a newer edit is no conflict',
    () async {
      await save(2);
      duringRequest = () => save(3);
      await sync.push();

      expect(await pull(2, 7), isEmpty);
      expect(await DatabaseService().getSyncConflicts(), isEmpty);
      final dirty = await DatabaseService().getDirtyObjects();
      expect(dirty.map((r) => [r['id'], r['version']]), [
        [entryId, 3],
      ]);
    },
  );

  test('a change from another device still is a conflict', () async {
    final conflicts = await pull(3, 8, by: 'b');
    expect(conflicts.map((c) => c['id']), [entryId]);
    expect(await DatabaseService().getSyncConflicts(), hasLength(1));
  });
}
