// Review d150605 N3: markClean dropped every conflict shadow of the object.
// A pull that ran while the push was out could hold aside a later change
// from another device; its shadow was wiped and the conflict never shown.

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
  Future<void> Function()? duringRequest;
  var acceptedSeq = 0;

  Future<void> save(String id, int version) => DatabaseService().upsertObject(
    id: id,
    objectType: 'entry',
    payload: Uint8List(100 + version),
    version: version,
    payloadHash: '0' * 64,
    clientSignature: Uint8List(64),
    queued: true,
  );

  Future<List<Map<String, dynamic>>> pull(String id, int version, int seq) =>
      DatabaseService().applyPullAndCommitCheckpoint(
        objects: [
          {
            'id': id,
            'object_type': 'entry',
            'payload': Uint8List(200 + version),
            'version': version,
            'is_deleted': 0,
            'payload_hash': '1' * 64,
            'client_signature': Uint8List(64),
            'commit_seq': seq,
          },
        ],
        seq: seq,
        checkpointKey: 'sync_checkpoint:test',
        encryptedCheckpoint: 'enc:v1:test',
      );

  Future<List<int?>> shadowSeqs(String id) async => [
    for (final row in await DatabaseService().getSyncConflicts())
      if (row['object_id'] == id) row['server_commit_seq'] as int?,
  ];

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_mark_clean_');
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
            for (final o in objects) {'id': o['id'], 'commit_seq': acceptedSeq},
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

  test('a later change pulled during the push keeps its conflict', () async {
    final id = '3'.padLeft(26, '0');
    await save(id, 3);
    acceptedSeq = 7;
    duringRequest = () async {
      expect(await pull(id, 4, 9), hasLength(1));
    };
    await sync.push();
    expect(await shadowSeqs(id), [9]);
  });

  test('a shadow the accepted copy superseded goes', () async {
    final id = '4'.padLeft(26, '0');
    await save(id, 3);
    // Not v2: an edit queued without a base takes the copy one below it as
    // its base (review c78fd19), and that is no conflict.
    expect(await pull(id, 1, 10), hasLength(1));
    acceptedSeq = 11;
    await sync.push();
    expect(await shadowSeqs(id), isEmpty);
    expect(
      (await DatabaseService().getDirtyObjects()).where((r) => r['id'] == id),
      isEmpty,
    );
  });
}
