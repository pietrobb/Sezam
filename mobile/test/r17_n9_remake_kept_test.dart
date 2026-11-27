// R17-N9 (review c02cc47): the phone made its lost team changes again when it
// followed a fork, and every 4xx but 409 - also 401 and 429 - withdrew them
// and set them aside, where nothing read them: a member.remove was lost and
// the admin never learned of it. The signature held the live key, which
// lock() zeroes. Only the log's own refusal sets them aside now, any other
// answer throws (the phone keeps them, a 401 signs in again), the key is read
// under the pull's lock generation, and settings show what was set aside.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;
  late SyncService sync;
  var status = 200;
  var answer = <String, Object?>{};

  Future<void> unlock() => VaultService().unlock(
    kek: Uint8List(32),
    signingSecretKey: Uint8List.fromList(List.generate(64, (i) => i + 1)),
    signingPublicKey: Uint8List(32),
    userId: 'U' * 26,
  );

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_r17_n9_');
    await setUpPhone(appDir.path);
    await unlock();
    final client = MockClient((request) async {
      if (request.method == 'POST' && request.url.path == '/api/team-log') {
        return http.Response(jsonEncode(answer), status);
      }
      return http.Response('{}', 404);
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

  final body = <String, Object?>{
    'v': 1,
    'seq': 3,
    'prev': '00' * 32,
    'type': 'member.remove',
    'author': 'U' * 26,
    'data': {'user_id': 'M' * 26},
  };

  test('only the log refusing them sets the remade changes aside', () async {
    final remake = sync.teamLogRemakeForTest()!;
    final record = remake.sign(body);
    for (final (code, detail) in [
      (401, {'detail': 'token expired', 'code': 'token_invalid'}),
      (429, {'detail': 'too many requests'}),
      (403, {'detail': 'not allowed'}),
      (400, {'detail': 'bad request'}),
      (503, {'detail': 'unavailable'}),
    ]) {
      status = code;
      answer = detail;
      await expectLater(
        remake.append([record]),
        throwsA(
          isA<SyncException>().having((e) => e.statusCode, 'status', code),
        ),
        reason: 'HTTP $code',
      );
      expect(
        await DatabaseService().getSetting(SyncService.teamLogWithdrawnSetting),
        isNull,
        reason: 'HTTP $code withdrew the record',
      );
    }
    status = 409;
    answer = {'detail': 'head moved', 'code': 'team_log_head_moved'};
    expect(await remake.append([record]), RemakeOutcome.moved);
    status = 400;
    answer = {
      'detail': {'message': 'not an active member'},
      'code': 'team_log_refused',
    };
    expect(await remake.append([record]), RemakeOutcome.refused);
    expect(
      await DatabaseService().getSetting(SyncService.teamLogWithdrawnSetting),
      isNotNull,
    );
  });

  test('settings read what was set aside', () async {
    final remake = sync.teamLogRemakeForTest()!;
    await remake.setAside([
      {
        'type': 'member.remove',
        'data': {'user_id': 'M' * 26},
      },
    ], 'the server refused them');
    expect(await sync.teamChangesSetAside(), [
      {
        'type': 'member.remove',
        'data': {'user_id': 'M' * 26},
        'reason': 'the server refused them',
      },
    ]);
  });

  test('a remake never signs with the key a lock zeroed', () async {
    final remake = sync.teamLogRemakeForTest()!;
    final before = remake.sign(body);
    VaultService().lock();
    try {
      expect(() => remake.sign(body), throwsA(isA<VaultLockedMeanwhile>()));
    } finally {
      await unlock();
    }
    // Unlocked again: a remake made before the lock still refuses to sign.
    expect(() => remake.sign(body), throwsA(isA<VaultLockedMeanwhile>()));
    expect(sync.teamLogRemakeForTest()!.sign(body), before);
  });
}
