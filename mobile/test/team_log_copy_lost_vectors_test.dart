// INV-7 (docs/ROOT_CAUSE_PLAN.md): from every blocking state there is a way
// out from where the user is stuck, here the locked phone. The phone keeps a
// copy of the team log; the pins it holds (the confirmed genesis, the head its
// checkpoint saw) are what bind the log. Before, a checkpoint that pinned a
// log made a copy that was missing or did not verify fatal: prepareInitialTeamLog
// fetched nothing and every unlock, the server sign-in included, failed on
// 'cached copy cannot be verified' (no cause, no way out but wiping the app).
//
// Property: for every case of tests/vectors/team_log_mismatch.json where the
// phone held a log (the oracle knows no client code), a phone whose copy is
// lost, empty or damaged gets, signing in and following the server's log, the
// same answer as one with its copy intact: it follows the honest server, and refuses the lying one with the same cause.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/team_log.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final vectors = jsonDecode(File('../tests/vectors/team_log_mismatch.json').readAsStringSync())
      as Map<String, dynamic>;
  final cases = [
    for (final c in vectors['cases'] as List)
      if ((c as Map)['device']['records'] != null) c as Map<String, dynamic>,
  ];
  final uid = 'U' * 26;
  late Directory appDir;
  late SyncService sync;
  late VaultService vault;
  Map<String, dynamic> served = const {};

  List<Map<String, dynamic>> recordsOf(Object? list) =>
      [for (final r in (list as List? ?? const [])) Map<String, dynamic>.from(r as Map)];

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_copy_lost_');
    await setUpPhone(appDir.path);
    final client = MockClient((request) async {
      if (request.method == 'GET' && request.url.path == '/api/team-log') {
        final since = int.parse(request.url.queryParameters['since']!);
        return http.Response(jsonEncode({
          'head': served['head'],
          'records': [
            for (final r in recordsOf(served['records']))
              if ((jsonDecode(r['body'] as String) as Map)['seq'] as int > since) r,
          ],
        }), 200);
      }
      return http.Response('{"detail": "refused"}', 409); // a restore that lands is INV-2
    });
    http.runWithClient(() {
      vault = VaultService();
      sync = SyncService()..configure('https://sezam.test');
      initPhoneCrypto();
    }, () => client);
    sync.setToken('jwt');
  });

  tearDownAll(() async {
    await DatabaseService().close();
    await appDir.delete(recursive: true);
  });

  String checkpointWith(Map<String, Object?> pin) {
    final crypto = CryptoService();
    final nonce = crypto.randomBytes(crypto.aeadNonceBytes);
    final sealed = crypto.aeadEncrypt(
      plaintext: Uint8List.fromList(utf8.encode(jsonEncode({
        'last_sync_seq': 0,
        'state_hash': '0' * 64,
        'timestamp': 1,
        'team_log': pin,
      }))),
      additionalData: Uint8List.fromList(utf8.encode('sezam-sync-checkpoint-v1:$uid')),
      nonce: nonce,
      key: Uint8List(32),
    );
    return 'enc:v1:${base64Encode([...nonce, ...sealed])}';
  }

  // The phone's copy as this case leaves it: intact, or what a lost or
  // damaged copy looks like on disk.
  String? copy(List<Map<String, dynamic>> held, String damage) => switch (damage) {
        'intact' => jsonEncode(held),
        'missing' => null,
        'empty' => '[]',
        'bad_signature' => jsonEncode([
            ...held.take(held.length - 1),
            {...held.last, 'sig': (held.last['sig'] as String).replaceRange(0, 2, '00')},
          ]),
        _ => throw ArgumentError(damage),
      };

  // Signing in on the locked phone, then following the server's log: what it ends at.
  Future<String> signIn(Map<String, dynamic> c, String damage) async {
    final device = c['device'] as Map<String, dynamic>;
    served = c['server'] as Map<String, dynamic>;
    vault.lock();
    const storage = FlutterSecureStorage();
    await storage.delete(key: 'sezam_confirmed_team_genesis:$uid');
    await storage.delete(key: 'sezam_forgotten_team_genesis:$uid');
    final forgotten = [for (final g in device['forgotten_genesis'] as List) g as String];
    if (forgotten.isNotEmpty) await forgetConfirmedTeamGenesis(uid, forgotten);
    final confirmed = device['confirmed_genesis'] as String?;
    if (confirmed != null) await confirmTeamGenesis(uid, confirmed);
    final held = recordsOf(device['records']);
    final db = DatabaseService();
    await db.replaceSnapshotAndCommitCheckpoint(
      objects: const [],
      seq: 0,
      checkpointKey: 'sync_checkpoint:$uid',
      encryptedCheckpoint: checkpointWith(teamLogPin(TeamLog(vault.verifyEd25519).replay(held))!),
    );
    final cached = copy(held, damage);
    if (cached == null) {
      await db.deleteSetting(teamLogRecordsSetting);
    } else {
      await db.setSetting(teamLogRecordsSetting, cached);
    }
    try {
      await sync.prepareInitialTeamLog(uid, kek: Uint8List(32));
      await vault.unlock(
        kek: Uint8List(32),
        signingSecretKey: Uint8List(64),
        signingPublicKey: Uint8List(32),
        userId: uid,
      );
      final refusal = await sync.teamLogRefusal();
      if (refusal != null) return 'refused ${refusal.cause}';
      return vault.teamLog == null ? 'follows without its log' : 'follows';
    } on TeamLogMismatch catch (e) {
      return 'refused ${e.cause}';
    }
  }

  test('a lost or damaged copy of the team log never ends the phone at the lock screen', () async {
    final got = <String, String>{};
    final want = <String, String>{};
    for (final c in cases) {
      final expected = c['expect'] as Map<String, dynamic>;
      for (final damage in ['intact', 'missing', 'empty', 'bad_signature']) {
        final name = '${c['name']} ($damage copy)';
        got[name] = await signIn(c, damage);
        want[name] = expected.containsKey('follows')
            ? 'follows'
            : 'refused ${expected['refused']}';
      }
    }
    expect(got, want);
  });

  // The lock screen: an unlock this phone refused on its team log goes on to
  // the server sign-in (above), as a wrong password does; never a dead end.
  test('the lock screen leads a team log refusal on to the server sign-in', () {
    final screen = File('lib/screens/unlock_screen.dart').readAsStringSync();
    expect(screen, contains("(result.error == 'Wrong password' || result.teamLog != null)"));
    final auth = File('lib/services/auth_service.dart').readAsStringSync();
    expect(RegExp(r'on TeamLogMismatch catch \(e\) \{\s*return AuthResult\.teamLogRefused\(e\);')
        .allMatches(auth).length, 3);
  });
}
