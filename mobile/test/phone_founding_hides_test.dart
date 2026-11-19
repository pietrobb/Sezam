// Review 8595ec1 (R10-C), phone: founding the log hid an older item of a
// member left at read. Given write access in the log, the desktop and the web
// show it again on their next pull; the phone had dropped the refused copy
// and showed it only after a full resync. It now keeps that copy and judges
// it again on every pull.
// tests/test_review10_phone_founding_hides.py sets it up and runs this file
// with SEZAM_X3_* set; without them the test is skipped.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'an item founding hid is shown once its author may write',
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
        await vault.confirmTeamFounder(
          await vault.reviewTeamFounder(),
          cfg['fingerprint'] as String,
        );
        final db = DatabaseService();
        final entry = cfg['entry'] as String;
        Future<bool> held() async => (await db.getAllObjects()).any(
          (row) => row['id'] == entry && row['is_deleted'] != 1,
        );
        await sync.pull();
        // The reproduction: the log gives Bob no write access to Ops.
        expect(await held(), isFalse);

        await handshake(dir!, 'granted');
        await sync.pull();
        expect(await held(), isTrue, reason: 'Bob may write in Ops now');
        await sync.pull(); // and it stays, the checkpoint agreeing
        expect(await held(), isTrue);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review10_phone_founding_hides.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
