// Review 7c10379 H4, phone: a folder a read-only member wrote directly below
// the shared root (the server before b8c3cb8 took it, a lying server serves
// it again), sealed with the root's shared key, and the item in it. The phone
// showed both as the company's own; it now leaves out what its signer could
// not write there (write_authority.dart), after a pull and a full resync.
// tests/test_review7_forged_root_folder_phone_h4.py plants them on the server
// and runs this file with SEZAM_X3_* set; without them the test is skipped.

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
    'the phone leaves out a member folder sealed with the shared root key',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
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

        void expectLeftOut() {
          final names = vault.allNodes.map((n) => n.name).toSet();
          expect(names, isNot(contains('IT - nove VPN prihlasenie')));
          expect(passwords(vault), isNot(contains('VPN')));
          expect(passwords(vault), {'db01': 's3cret'});
        }

        expectLeftOut();
        await sync.pull();
        await vault.reloadData();
        expectLeftOut();
        await sync.fullResync(confirmed: true);
        await vault.reloadData();
        expectLeftOut();
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review7_forged_root_folder_phone_h4.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
