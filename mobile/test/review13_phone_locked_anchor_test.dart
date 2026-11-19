// Review c78fd19 high #4: a LOCKED phone that last pulled before the team log
// was founded. The admin publishes the anchor (a new password); unlocking with
// it brought no log (prepareInitialTeamLog had no current KEK to read the
// checkpoint with) and every unlock then failed on 'cached log is missing'.
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
    'a locked phone without the team log unlocks with an anchor password',
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
        await auth.lock();
        await net.settle();

        // Locked: the log is founded and the admin publishes its anchor.
        await handshake(dir!, 'anchored');
        final genesis = File('$dir/genesis.txt').readAsStringSync();
        final opened = await auth.unlockWithPassword(
          serverUrl: server,
          username: username,
          password: newPassword,
          previousPassword: password,
        );
        expect(opened.success, isTrue, reason: opened.error);
        await net.settle();
        expect(await readConfirmedTeamGenesis(uid), genesis);
        expect(vault.teamLog?.team.genesisHash, genesis);
        await sync.sync();
        expect(passwords(vault)['after-log'], 'post-log-secret');
        expect(passwords(vault)['before-log'], 'pre-log-secret');

        await auth.lock();
        await net.settle();
        await DatabaseService().close();
        final offline = await auth.unlockOffline(password: newPassword);
        expect(offline.success, isTrue, reason: offline.error);
        expect(vault.teamLog?.team.genesisHash, genesis);
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
