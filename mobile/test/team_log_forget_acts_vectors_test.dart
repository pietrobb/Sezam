// INV-8 (docs/ROOT_CAUSE_PLAN.md, review 8bc70f7 H4): "Zabudnúť pripnutý
// tímový denník" acts exactly where the phone, following the server's log now,
// refuses it as lost for good (tests/vectors/team_log_mismatch.json), never
// for a server that lies (a fork, a log going back) or one it follows. The
// same cases run through the desktop's and the page's forget in
// tests/test_inv8_forget_acts_only_on_lost.py. Before, the phone's forget
// checked only the typed genesis and unsent changes: the settings tile left
// any pinned log, a forked one included.

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

  List<Map<String, dynamic>> recordsOf(Object? list) =>
      [for (final r in (list as List? ?? const [])) Map<String, dynamic>.from(r as Map)];

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_forget_acts_');
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

  Future<void> prepare(Map<String, dynamic> c) async {
    final device = c['device'] as Map<String, dynamic>;
    served = c['server'] as Map<String, dynamic>;
    const storage = FlutterSecureStorage();
    await storage.delete(key: 'sezam_confirmed_team_genesis:$uid');
    await storage.delete(key: 'sezam_forgotten_team_genesis:$uid');
    final forgotten = [for (final g in device['forgotten_genesis'] as List) g as String];
    if (forgotten.isNotEmpty) await forgetConfirmedTeamGenesis(uid, forgotten);
    final confirmed = device['confirmed_genesis'] as String?;
    if (confirmed != null) await confirmTeamGenesis(uid, confirmed);
    final held = device['records'] == null ? null : recordsOf(device['records']);
    vault.teamLog = held == null ? null : LocalTeamLog(held, TeamLog(vault.verifyEd25519).replay(held));
  }

  Future<bool> forgets(Map<String, dynamic> c) async {
    await prepare(c);
    final pins = await sync.pinnedTeamGenesis();
    var typed = pins.isEmpty ? '0' * 16 : pins.first;
    for (final pin in pins) {
      while (!pin.startsWith(typed)) {
        typed = typed.substring(0, typed.length - 1);
      }
    }
    try {
      await sync.forgetTeamLogPin(typed);
    } catch (_) {
      return false;
    }
    expect(await sync.pinnedTeamGenesis(), isEmpty, reason: c['name'] as String);
    return true;
  }

  test('the phone forgets exactly where the team log is lost for good', () async {
    final got = <String, bool>{};
    final want = <String, bool>{};
    for (final c in cases) {
      got[c['name'] as String] = await forgets(c);
      want[c['name'] as String] = (c['expect'] as Map)['forget'] == true;
    }
    expect(got, want);
  });

  // INV-7 on the phone: the settings tile is offered from the same judgment,
  // never shown for a log the phone follows or a server that lies. Before,
  // the tile was always there.
  test('settings offer the forget exactly where the team log is lost for good', () async {
    final got = <String, bool>{};
    final want = <String, bool>{};
    for (final c in cases) {
      await prepare(c);
      got[c['name'] as String] = (await sync.teamLogRefusal())?.offersForget ?? false;
      want[c['name'] as String] = (c['expect'] as Map)['forget'] == true;
    }
    expect(got, want);
    final screen = File('lib/screens/settings_screen.dart').readAsStringSync();
    final tile = screen.indexOf("title: 'Zabudnúť pripnutý tímový denník'");
    expect(screen.lastIndexOf('if (_teamLogLost)', tile), greaterThan(screen.lastIndexOf('_settingsTile(', tile) - 40));
    expect(screen, contains('lost = (await _sync.teamLogRefusal())?.offersForget ?? false;'));
  });
}
