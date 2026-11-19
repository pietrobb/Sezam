// Review 4acfdde R11 (low), phone: the server is restored from a backup
// older than this member, and a new account registers under the member's
// name. The rejoin said only "the account exists; sign in" (every 409); the
// phone now reports the name as taken and rejoins under another one.
// tests/test_review11_rejoin_name_taken.py runs this file with SEZAM_X3_* set.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'support/real_server_phone.dart';

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'a member whose name was taken rejoins from the phone under another',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final password = cfg['password'] as String;
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
          password: password,
          username: cfg['username'] as String,
        );
        expect(c.outcome, ConnectOutcome.connected, reason: c.message);
        await net.settle();
        await vault.confirmTeamFounder(
          await vault.reviewTeamFounder(),
          cfg['fingerprint'] as String,
        );
        await sync.pull();
        final mine = await vault.createPersonalFolder(name: 'Phone');
        await vault.createEntry(
          parentRef: mine.id,
          name: 'phone-mine',
          fields: [EntryField(key: 'password', value: 'from-phone', sensitive: true)],
        );
        expect((await sync.sync()).push.errors, isEmpty);

        await handshake(dir!, 'restore'); // and another account takes "bob"
        await expectLater(sync.sync(), throwsA(isA<AccountLostOnServerException>()));

        final taken = await auth.rejoinServer(password: password);
        expect(taken.success, isFalse);
        expect(taken.usernameTaken, isTrue, reason: taken.error);
        final prefs = await SharedPreferences.getInstance();
        expect(prefs.getString(SyncService.usernamePrefKey), 'bob');

        final rejoined = await auth.rejoinServer(password: password, newUsername: 'bob2');
        expect(rejoined.success, isTrue, reason: rejoined.error);
        expect(prefs.getString(SyncService.usernamePrefKey), 'bob2');
        await handshake(dir, 'admin_sync');
        await sync.sync();
        await vault.reloadData();
        expect(passwords(vault), containsPair('vpn', 'ops-pw'));
        expect(passwords(vault), containsPair('phone-mine', 'from-phone'));

        await handshake(dir, 'check');
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review11_rejoin_name_taken.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
