// Review a159e97 (mobile): lock() did not stop a running password take-over.
// The take-over waits on the network (recover, authenticate) and then unlocks
// the vault with the new KEK, so an auto-lock in between was undone and the
// vault stood open again. The take-over now finishes on disk and leaves the
// vault locked; the current password opens it.
// tests/test_review8_phone_takeover_autolock.py starts the server, plays
// desktop A and runs this file with SEZAM_X3_* set; without them it is skipped.

import 'dart:async';
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
    'an auto-lock during a password take-over keeps the vault locked',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final oldPassword = cfg['old_password'] as String;
      final newPassword = cfg['new_password'] as String;
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
          password: oldPassword,
          username: cfg['username'] as String,
        );
        expect(c.outcome, ConnectOutcome.connected, reason: c.message);
        await net.settle();
        await auth.lock();
        await net.settle();

        await handshake(dir!, 'changed'); // A changes the password

        var r = await auth.unlockOffline(password: oldPassword);
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        await expectLater(sync.sync(), throwsA(isA<KeyEpochStaleException>()));

        var locked = false;
        net.onSend = (path) {
          if (path == '/api/auth/verify') {
            net.onSend = null;
            locked = true;
            unawaited(auth.lock()); // the auto-lock fires mid take-over
          }
        };
        r = await auth.adoptPasswordChangedElsewhere(
          currentPassword: newPassword,
        );
        expect(locked, isTrue, reason: 'the take-over never authenticated');
        expect(r.success, isFalse);
        expect(vault.isUnlocked, isFalse, reason: 'the take-over unlocked again');
        await net.settle();

        // Taken over on disk: the current password opens everything.
        r = await auth.unlockOffline(password: newPassword);
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        expect(passwords(vault), {'db01': 's3cret'});
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review8_phone_takeover_autolock.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
