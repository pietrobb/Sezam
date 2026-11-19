// Review 1141a20 (R9-G), phone: a QR provisioning that fails before the
// sign-in (the scanned server refuses the token, or answers garbage) left the
// phone pointed at the scanned server with the session of its own server:
// the next sync sent that JWT to the scanned server.
// tests/test_review9_phone_qr_foreign_server.py starts the real server and
// runs this file with SEZAM_X3_* set; without them the test is skipped.

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
    'a failed QR provisioning sends nothing of this phone to the scanned server',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      await setUpPhone('$dir/app');
      // The scanned server: records what reaches it.
      final foreign = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final seen = <String>[];
      var answer = 'refuse';
      foreign.listen((request) async {
        await request.drain<void>();
        seen.add(
          '${request.method} ${request.uri.path} '
          'auth=${request.headers.value('authorization')}',
        );
        request.response.headers.contentType = ContentType.json;
        if (answer == 'refuse' || !request.uri.path.endsWith('/provision')) {
          request.response.statusCode = 403;
          request.response.write('{"detail": "no"}');
        } else {
          request.response.write('{"encrypted_keypair": "00"}');
        }
        await request.response.close();
      });
      final foreignUrl = 'http://127.0.0.1:${foreign.port}';
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
        final session = sync.token!;

        for (final mode in ['refuse', 'garbage']) {
          answer = mode;
          final p = await auth.provisionFromQR(
            provisionToken: 'scanned-token',
            username: cfg['username'] as String,
            password: cfg['password'] as String,
            serverUrl: foreignUrl,
          );
          expect(p.success, isFalse, reason: mode);
          Object? pulled;
          try {
            await sync.pull();
          } catch (e) {
            pulled = e;
          }
          await net.settle();
          expect(seen.join(), isNot(contains(session)), reason: mode);
          expect(pulled, isNull, reason: mode);
          expect(sync.serverUrl, serverUrl, reason: mode);
          expect(sync.token, session, reason: mode);
        }
        expect(seen, [
          for (var i = 0; i < 2; i++) 'POST /api/auth/provision auth=null',
        ]);
        await auth.lock();
        await net.settle();
      }, () => net);
      await foreign.close(force: true);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review9_phone_qr_foreign_server.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
