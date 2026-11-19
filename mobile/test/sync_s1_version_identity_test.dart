// Sync redesign S1 (docs/SYNC_SINGLE_SOURCE.md, point 1): a version is the
// pair (number, payload hash). The phone keeps the server copy a row builds
// on (base_version, base_hash) on the row itself, sends it with every update
// and compares the pair - never the number alone - when it decides whether a
// copy is its own.

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
  final newId = '2'.padLeft(26, '0');
  final sentBodies = <Map<String, dynamic>>[];
  Future<void> Function()? duringRequest;

  Future<void> save(String id, int version, String hash, {int dirty = 1}) =>
      DatabaseService().upsertObject(
        id: id,
        objectType: 'entry',
        payload: Uint8List(100),
        version: version,
        commitSeq: dirty == 0 ? version : null,
        payloadHash: hash,
        clientSignature: Uint8List(64),
        queued: dirty == 1,
      );

  Future<Map<String, dynamic>> row(String id) async =>
      (await DatabaseService().getObject(id))!;

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_s1_');
    await setUpPhone(appDir.path);
    final client = MockClient((request) async {
      final body = jsonDecode(request.body) as Map<String, dynamic>;
      sentBodies.add(body);
      final hook = duringRequest;
      duringRequest = null;
      if (hook != null) await hook();
      return http.Response(
        jsonEncode({
          'accepted': [
            for (final o in body['objects'] as List)
              {'id': o['id'], 'commit_seq': 10},
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

  test('an update names its server copy as (version, hash); a create names none', () async {
    await save(entryId, 2, 'a' * 64, dirty: 0);
    await save(entryId, 3, 'b' * 64);
    await save(entryId, 4, 'c' * 64); // a second local edit keeps the base
    await save(newId, 1, 'd' * 64);
    sentBodies.clear();
    await sync.push();
    final sent = {
      for (final o in sentBodies.single['objects'] as List)
        o['id'] as String: o as Map<String, dynamic>,
    };
    expect(sent[entryId]!['base_version'], 2);
    expect(sent[entryId]!['base_payload_hash'], 'a' * 64);
    expect(sent[newId]!.containsKey('base_version'), isFalse);
    expect(sent[newId]!.containsKey('base_payload_hash'), isFalse);
    // Accepted: the pushed copy is the new base.
    expect((await row(entryId))['queued'], 0);
    expect((await row(entryId))['base_version'], 4);
    expect((await row(entryId))['base_hash'], 'c' * 64);
  });

  test('same number, other content saved during the push stays unsent', () async {
    await save(entryId, 5, 'e' * 64);
    // A re-seal while the push is out: same version number, other content.
    duringRequest = () => save(entryId, 5, 'f' * 64);
    await sync.push();
    final local = await row(entryId);
    expect(local['queued'], 1);
    expect(local['payload_hash'], 'f' * 64);
    // It now builds on what the server took: (5, e), not on (4, c).
    expect(local['base_version'], 5);
    expect(local['base_hash'], 'e' * 64);
  });

  test('a pulled copy is this edit\'s base only when number and hash match', () async {
    // The local row: dirty (5, f) on base (5, e), from the test above.
    Map<String, Object?> served(String hash) => {
      'id': entryId,
      'object_type': 'entry',
      'payload': Uint8List(100),
      'version': 5,
      'commit_seq': 10,
      'is_deleted': 0,
      'payload_hash': hash,
      'client_signature': Uint8List(64),
    };
    final db = DatabaseService();
    var conflicts = await db.applyPullAndCommitCheckpoint(
      objects: [served('e' * 64)],
      seq: 10,
      checkpointKey: 's1_checkpoint',
      encryptedCheckpoint: 'x',
    );
    expect(conflicts, isEmpty);
    expect((await row(entryId))['payload_hash'], 'f' * 64);

    conflicts = await db.applyPullAndCommitCheckpoint(
      objects: [served('9' * 64)],
      seq: 11,
      checkpointKey: 's1_checkpoint',
      encryptedCheckpoint: 'x',
    );
    expect(conflicts.map((c) => c['id']), [entryId]);
    expect((await db.getSyncConflict(entryId))!['server_payload_hash'], '9' * 64);
    expect((await row(entryId))['payload_hash'], 'f' * 64);
  });
}
