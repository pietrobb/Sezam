// Review e443cbc R15 (goal #429): the phone's keys carry the team anchor;
// another device of the account, which never held it, changes the password
// (an org recovery while the anchored change had not landed). The server's
// keys name no log under a password state this phone never left: taking
// them over was refused ('Wrong password or corrupted keypair') and the
// phone stayed on a key epoch every sync refused. It takes them over now
// and keeps the anchor pinned.
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
    'a phone with the anchor takes over a password change made without it',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final username = cfg['username'] as String;
      final password = cfg['password'] as String;
      final newPassword = cfg['new_password'] as String;
      final thirdPassword = cfg['third_password'] as String;
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

        // The log is founded and the admin publishes its anchor (a new password).
        await handshake(dir!, 'anchored');
        final genesis = File('$dir/genesis.txt').readAsStringSync();
        await expectLater(sync.sync(), throwsA(isA<KeyEpochStaleException>()));
        final anchored = await auth.adoptPasswordChangedElsewhere(currentPassword: newPassword);
        expect(anchored.success, isTrue, reason: anchored.error);
        await net.settle();
        expect(await readConfirmedTeamGenesis(uid), genesis);

        // A server back on a backup from before the anchor serves those keys:
        // a state this phone left without the anchor stays a downgrade.
        await handshake(dir, 'replay');
        final replayed = await auth.adoptPasswordChangedElsewhere(currentPassword: password);
        expect(replayed.success, isFalse, reason: 'a pre-anchor state was taken over');
        expect(await readConfirmedTeamGenesis(uid), genesis);
        await net.settle();
        await handshake(dir, 'unreplay');

        // A device that never held the anchor changes the password.
        await handshake(dir, 'anchorless');
        await expectLater(sync.sync(), throwsA(isA<KeyEpochStaleException>()));
        final adopted = await auth.adoptPasswordChangedElsewhere(currentPassword: thirdPassword);
        expect(adopted.success, isTrue, reason: adopted.error);
        await net.settle();
        expect(await readConfirmedTeamGenesis(uid), genesis);
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
