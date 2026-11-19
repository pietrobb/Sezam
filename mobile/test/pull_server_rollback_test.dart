// Review d150605 #5: the phone never read head_commit_seq. After the server
// was restored from a backup and other devices pushed past the old
// checkpoint, delta pulls skipped what the server committed again under
// sequence numbers the phone had already passed, without a word. A server
// head behind the checkpoint now asks for a full resync, and keeps asking
// after the head moves on.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;
  late SyncService sync;
  var head = 0;
  var requests = 0;

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_pull_rollback_');
    await setUpPhone(appDir.path);
    await VaultService().unlock(
      kek: Uint8List(32),
      signingSecretKey: Uint8List(64),
      signingPublicKey: Uint8List(32),
      userId: 'U' * 26,
    );
    final client = MockClient((request) async {
      requests += 1;
      return http.Response(
        jsonEncode({
          'objects': [],
          'max_commit_seq': 10,
          'key_epoch': 0,
          'has_more': false,
          'head_commit_seq': head,
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

  test('a server head behind the checkpoint asks for a full resync', () async {
    await DatabaseService().setLastCommitSeq(10);
    head = 6;
    await expectLater(
      sync.pull(),
      throwsA(
        isA<FullResyncRequiredException>().having(
          (e) => e.message,
          'message',
          contains('rollback detected'),
        ),
      ),
    );

    // Another device pushed past the old checkpoint: still a full resync,
    // and no delta is fetched that would skip the reused numbers.
    head = 14;
    final before = requests;
    await expectLater(sync.pull(), throwsA(isA<FullResyncRequiredException>()));
    expect(requests, before);
    expect(await DatabaseService().getLastCommitSeq(), 10);
  });
}
