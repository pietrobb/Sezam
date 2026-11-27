// Review c02cc47 R17-L: opening Settings asks the phone whether it refuses
// the server's team log (teamLogRefusal), and the forget asked the same
// before it went on. Both ran the pull's sync of the log, which posts a
// restore of what the server lost, sends lost changes again and withdraws
// records: a look at Settings wrote to the team log. Now the judgment posts
// nothing; only a forget that goes on (no unsent changes in the way) runs the
// pull's own judgment, where a restore the server takes makes the log not lost.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/team_log.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final vectors = jsonDecode(File('../tests/vectors/team_log_mismatch.json').readAsStringSync())
      as Map<String, dynamic>;
  final cases = [for (final c in vectors['cases'] as List) c as Map<String, dynamic>];
  final uid = 'U' * 26;
  late Directory appDir;
  late SyncService sync;
  late VaultService vault;
  Map<String, dynamic> served = const {};
  final writes = <String>[];

  List<Map<String, dynamic>> recordsOf(Object? list) =>
      [for (final r in (list as List? ?? const [])) Map<String, dynamic>.from(r as Map)];

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_r17_judge_');
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
      writes.add('${request.method} ${request.url.path}');
      return http.Response('{"detail": "refused"}', 409);
    });
    http.runWithClient(() {
      vault = VaultService();
      sync = SyncService()..configure('https://sezam.test');
      initPhoneCrypto();
    }, () => client);
    sync.setToken('jwt');
    await vault.unlock(
      kek: Uint8List(32),
      signingSecretKey: Uint8List(64),
      signingPublicKey: Uint8List(32),
      userId: uid,
    );
  });

  tearDownAll(() async {
    await DatabaseService().close();
    await appDir.delete(recursive: true);
  });

  test('settings judge the team log without a write to it', () async {
    final judged = <String>[];
    for (final c in cases) {
      final device = c['device'] as Map<String, dynamic>;
      served = c['server'] as Map<String, dynamic>;
      const storage = FlutterSecureStorage();
      await storage.delete(key: 'sezam_confirmed_team_genesis:$uid');
      await storage.delete(key: 'sezam_forgotten_team_genesis:$uid');
      final confirmed = device['confirmed_genesis'] as String?;
      if (confirmed != null) await confirmTeamGenesis(uid, confirmed);
      final held = device['records'] == null ? null : recordsOf(device['records']);
      vault.teamLog = held == null ? null : LocalTeamLog(held, TeamLog(vault.verifyEd25519).replay(held));
      try {
        await sync.teamLogRefusal();
      } catch (_) {
        // a judgment that fails is still no write
      }
      judged.add(c['name'] as String);
    }
    expect(judged, isNotEmpty);
    expect(writes, isEmpty);
  });
}
