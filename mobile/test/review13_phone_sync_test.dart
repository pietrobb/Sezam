// Review c78fd19 (R13-5, as on the web):
// * an edit after a push whose reply was lost was a conflict with the phone's
//   own push: the phone now remembers what it sent (own_earlier_push);
// * an edit queued before the base was kept (schema v8) was refused as a new
//   object on every push: the server's copy one version below is its base;
// * a delta pull could take a folder or entry back to an older version.

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
  var requests = 0;
  String hash(int version, [String by = 'a']) => '$by$version'.padLeft(64, '0');

  Future<void> save(String id, int version) => DatabaseService().upsertObject(
    id: id,
    objectType: 'entry',
    payload: Uint8List(100 + version),
    version: version,
    payloadHash: hash(version),
    clientSignature: Uint8List(64),
    queued: true,
  );

  Future<List<Map<String, dynamic>>> pull(
    String id,
    int version,
    int commitSeq, {
    String by = 'a',
  }) => DatabaseService().applyPullAndCommitCheckpoint(
    objects: [
      {
        'id': id,
        'object_type': 'entry',
        'payload': Uint8List(100 + version),
        'version': version,
        'is_deleted': 0,
        'payload_hash': hash(version, by),
        'client_signature': Uint8List(64),
        'commit_seq': commitSeq,
      },
    ],
    seq: commitSeq,
    checkpointKey: 'sync_checkpoint:test',
    encryptedCheckpoint: 'enc:v1:test',
  );

  Future<Map<String, dynamic>> row(String id) async =>
      (await DatabaseService().getObject(id))!;

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_r13_sync_');
    await setUpPhone(appDir.path);
    // The server takes every push; its reply never arrives.
    final client = MockClient((request) async {
      requests += 1;
      throw http.ClientException('connection reset');
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

  test('an edit after a push whose reply was lost is no conflict', () async {
    final id = '3'.padLeft(26, '0');
    await pull(id, 1, 5);
    await save(id, 2); // made on v1
    await expectLater(sync.push(), throwsA(anything));
    expect(requests, 1);
    await save(id, 3); // edited again, still on v1
    // The server committed v2: this phone's own push.
    expect(await pull(id, 2, 7), isEmpty); // c78fd19: a conflict
    expect(await DatabaseService().getSyncConflicts(), isEmpty);
    final queued = await row(id);
    expect([queued['version'], queued['queued']], [3, 1]);
    expect([queued['base_version'], queued['base_hash']], [2, hash(2)]);
  });

  test('another device\'s copy still is a conflict', () async {
    final id = '4'.padLeft(26, '0');
    await pull(id, 1, 8);
    await save(id, 2);
    await expectLater(sync.push(), throwsA(anything));
    await save(id, 3);
    final conflicts = await pull(id, 2, 9, by: 'b');
    expect(conflicts.map((c) => c['id']), [id]);
  });

  test('an edit queued without its base gets the copy below it', () async {
    final id = '5'.padLeft(26, '0');
    await save(id, 5); // as queued before schema v8: no base
    expect((await row(id))['base_version'], isNull);
    expect(await pull(id, 4, 10), isEmpty); // c78fd19: a conflict for good
    final queued = await row(id);
    expect([queued['version'], queued['queued']], [5, 1]);
    expect([queued['base_version'], queued['base_hash']], [4, hash(4)]);
    // A server that moved past it: a conflict, as before.
    final other = '6'.padLeft(26, '0');
    await save(other, 5);
    expect((await pull(other, 5, 11, by: 'b')).map((c) => c['id']), [other]);
  });

  test('a delta pull never takes a held copy back', () {
    Map<String, dynamic> held({int deleted = 0, int queued = 0}) => {
      'version': 5,
      'payload_hash': 'h5',
      'is_deleted': deleted,
      'commit_seq': 40,
      'queued': queued,
    };
    bool stale(Map<String, dynamic>? h, int v, String hash, {int floor = 10}) =>
        pulledIsStale(
          h,
          objectType: 'entry',
          version: v,
          hash: hash,
          gcFloor: floor,
        );
    expect(stale(held(), 4, 'h4'), isTrue);
    expect(stale(held(), 5, 'other'), isTrue);
    expect(stale(held(), 5, 'h5'), isFalse);
    expect(stale(held(), 6, 'h6'), isFalse);
    expect(stale(null, 1, 'h1'), isFalse);
    // A queued change meets every copy in the core's decision.
    expect(stale(held(queued: 1), 4, 'h4'), isFalse);
    // A tombstone the server collected may come back (SM8).
    expect(stale(held(deleted: 1), 3, 'h3', floor: 50), isFalse);
    expect(stale(held(deleted: 1), 3, 'h3'), isTrue);
  });
}
