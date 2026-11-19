// Review 8595ec1 #1 (R10-B), phone: the server is restored from a backup
// older than this member's account. The admin's device puts the team log
// back; the member, with only this phone, could never sign in again (the
// server assigns ids). The log names the account's id and keys, so the phone
// brings it back under that id (AuthService.rejoinServer), and what it wrote
// after the backup goes to the server again.
// tests/test_review10_rejoin_phone.py sets it up and runs this file with
// SEZAM_X3_* set; without them the test is skipped.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'a member with only a phone rejoins a server restored from before the account',
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
        await vault.reloadData();
        expect(passwords(vault), containsPair('vpn', 'ops-pw'));

        // Written after the backup the server goes back to.
        final mine = await vault.createPersonalFolder(name: 'Phone');
        await vault.createEntry(
          parentRef: mine.id,
          name: 'phone-mine',
          fields: [EntryField(key: 'password', value: 'from-phone', sensitive: true)],
        );
        final pushed = await sync.sync();
        expect(pushed.push.errors, isEmpty);

        await handshake(dir!, 'restore');
        await expectLater(sync.sync(), throwsA(isA<AccountLostOnServerException>()));

        // The rejoin reaches the server, its answer is lost: run again.
        net.dropResponsePath = '/api/auth/rejoin';
        await expectLater(
          auth.rejoinServer(password: password),
          throwsA(isA<SocketException>()),
        );
        final rejoined = await auth.rejoinServer(password: password);
        expect(rejoined.success, isTrue, reason: rejoined.error);
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
        ? 'run by tests/test_review10_rejoin_phone.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
