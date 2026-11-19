// Review 1141a20 H2 (capability run 264): the phone publishes the founder it
// confirmed to the account's new devices only with a NEW password.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  test(
    'publishes the confirmed founder only with a new password',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      var password = cfg['password'] as String;
      final newPassword = cfg['new_password'] as String;
      final uid = cfg['user_id'] as String;
      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        final auth = AuthService();
        final sync = SyncService();
        final vault = VaultService();
        initPhoneCrypto();
        await vault.init();
        final unlocked = await auth.unlockWithPassword(
          serverUrl: server!,
          username: 'bob',
          password: password,
        );
        expect(unlocked.success, isTrue, reason: unlocked.error);
        await net.settle();

        // Nothing to publish before this phone confirmed the founder itself.
        var result = await auth.publishTeamAnchor(
          currentPassword: password,
          newPassword: newPassword,
        );
        expect(result.success, isFalse);
        expect(result.error, contains('founder'));
        final review = await vault.reviewTeamFounder();
        await vault.confirmTeamFounder(review, cfg['fingerprint'] as String);
        expect(await readConfirmedTeamGenesis(uid), cfg['genesis']);
        expect(passwords(vault)['published'], 'actual-shared-secret');

        if (cfg['case'] == 'adopted') {
          // Capability run 273: A -> B on the desktop before any anchor; the
          // phone takes it over and must remember that A opened bundles too.
          await handshake(dir!, 'changed_elsewhere');
          password = cfg['between_password'] as String;
          final adopted = await auth.adoptPasswordChangedElsewhere(currentPassword: password);
          expect(adopted.success, isTrue, reason: adopted.error);
          await net.settle();
        }

        result = await auth.publishTeamAnchor(
          currentPassword: password,
          newPassword: password,
        );
        expect(result.success, isFalse);
        expect(result.error, contains('new password'));
        result = await auth.publishTeamAnchor(
          currentPassword: 'not-the-password-at-all',
          newPassword: newPassword,
        );
        expect(result.success, isFalse);
        expect(result.error, contains('Wrong current password'));
        await handshake(dir!, 'unchanged');

        if (cfg['case'] == 'lost') net.dropResponsePath = '/api/sync';
        result = await auth.publishTeamAnchor(
          currentPassword: password,
          newPassword: newPassword,
        );
        expect(result.success, isTrue, reason: result.error);
        expect(net.dropResponsePath, isNull);
        await net.settle();
        expect(await readConfirmedTeamGenesis(uid), cfg['genesis']);
        expect(passwords(vault)['published'], 'actual-shared-secret');
        await sync.sync();

        // The phone itself now runs on the new password, offline too.
        await auth.lock();
        await net.settle();
        await DatabaseService().close();
        expect((await auth.unlockOffline(password: password)).success, isFalse);
        final offline = await auth.unlockOffline(password: newPassword);
        expect(offline.success, isTrue, reason: offline.error);
        expect(passwords(vault)['published'], 'actual-shared-secret');
        await auth.lock();
        await net.settle();
        await DatabaseService().close();
        await handshake(dir, 'published');
      }, () => net);
      net.close();
    },
    skip: server == null || dir == null,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
