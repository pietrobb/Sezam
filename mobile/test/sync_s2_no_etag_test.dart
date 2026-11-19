// Sync redesign S2 (docs/SYNC_SINGLE_SOURCE.md point 2): the checkpoint is
// the only pull state. No ETag is sent, and a 304 is not "nothing new" that
// would leave the checkpoint behind what the server left out: it is an error.

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
  var status = 304;
  final sent = <http.BaseRequest>[];

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_s2_no_etag_');
    await setUpPhone(appDir.path);
    await VaultService().unlock(
      kek: Uint8List(32),
      signingSecretKey: Uint8List(64),
      signingPublicKey: Uint8List(32),
      userId: 'U' * 26,
    );
    final client = MockClient((request) async {
      sent.add(request);
      if (status == 304) return http.Response('', 304, headers: {'etag': '"10"'});
      return http.Response(
        jsonEncode({
          'objects': [],
          'max_commit_seq': 10,
          'key_epoch': 0,
          'has_more': false,
          'head_commit_seq': 10,
        }),
        200,
      );
    });
    http.runWithClient(() {
      sync = SyncService()..configure('https://sezam.test');
      initPhoneCrypto();
    }, () => client);
    sync.setToken('jwt');
  });

  tearDownAll(() async {
    await DatabaseService().close();
    await appDir.delete(recursive: true);
  });

  test('a 304 is refused, and no pull sends If-None-Match', () async {
    await DatabaseService().setLastCommitSeq(4);
    await expectLater(sync.pull(), throwsA(anything));
    expect(await DatabaseService().getLastCommitSeq(), 4);

    status = 200;
    await sync.pull();
    expect(await DatabaseService().getLastCommitSeq(), 10);
    for (final request in sent) {
      expect(
        request.headers.keys.map((k) => k.toLowerCase()),
        isNot(contains('if-none-match')),
      );
    }
  });
}
