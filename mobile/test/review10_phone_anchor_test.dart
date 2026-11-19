// Review 8595ec1 #6 (R10-F): a phone that last pulled before the team log was
// founded takes over the password an anchor publication set, and fetches the
// log the anchor names instead of locking itself out ('cached log is missing').
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
    'a phone without the team log takes over an anchor password',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final username = cfg['username'] as String;
      final password = cfg['password'] as String;
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
          username: username,
          password: password,
        );
        expect(unlocked.success, isTrue, reason: unlocked.error);
        await net.settle();
        await sync.sync();
        expect(vault.teamLog, isNull);
        expect(passwords(vault)['before-log'], 'pre-log-secret');

        // The log is founded and the admin publishes its anchor (a new password).
        await handshake(dir!, 'anchored');
        final genesis = File('$dir/genesis.txt').readAsStringSync();
        await expectLater(sync.sync(), throwsA(isA<KeyEpochStaleException>()));

        final adopted = await auth.adoptPasswordChangedElsewhere(
          currentPassword: newPassword,
        );
        expect(adopted.success, isTrue, reason: adopted.error);
        await net.settle();
        expect(await readConfirmedTeamGenesis(uid), genesis);
        expect(vault.teamLog?.team.genesisHash, genesis);
        await sync.sync();
        expect(passwords(vault)['after-log'], 'post-log-secret');

        // Offline on the new password too, with the log it fetched.
        await auth.lock();
        await net.settle();
        await DatabaseService().close();
        final offline = await auth.unlockOffline(password: newPassword);
        expect(offline.success, isTrue, reason: offline.error);
        expect(vault.teamLog?.team.genesisHash, genesis);
        expect(passwords(vault)['after-log'], 'post-log-secret');
        // A checkpoint that pins the log and lost its copy stays fail-closed
        // (phone_invitation_team_anchor_test, restart-none).
        await auth.lock();
        await net.settle();
        await DatabaseService().close();
      }, () => net);
      net.close();
    },
    skip: server == null || dir == null,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
