// Review 18c300f R16-H2, phone: a member's top-level folder sealed with a key
// this account shares, whose sealed meta says personal, is no personal folder
// of this account. tests/test_r16_phone_personal_mark.py plants it on the
// server and runs this file with SEZAM_X3_* set; without them it is skipped.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'a member folder that says personal is no personal folder here',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final forged = cfg['forged'] as String;
      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        final auth = AuthService();
        final sync = SyncService();
        final vault = VaultService();
        initPhoneCrypto();
        await vault.init();

        final c = await auth.connectToServer(
          serverUrl: serverUrl!,
          password: cfg['password'] as String,
          username: cfg['username'] as String,
        );
        expect(c.outcome, ConnectOutcome.connected, reason: c.message);
        await net.settle();

        void expectNotPersonal() {
          final personal = vault.allNodes
              .where((n) => n.personal)
              .map((n) => n.id);
          expect(personal, isNot(contains(forged)));
        }

        expectNotPersonal();
        await sync.pull();
        await vault.reloadData();
        expectNotPersonal();
        await sync.fullResync(confirmed: true);
        await vault.reloadData();
        expectNotPersonal();
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_r16_phone_personal_mark.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
