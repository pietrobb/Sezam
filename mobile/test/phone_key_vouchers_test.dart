// Goal #443: a new phone takes an object the account's retired key signed
// only when a voucher list of its current key names it, whatever bound
// (retired_seq) the server serves. Run by tests/test_key_vouchers_phone.py.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  test(
    'a new phone takes what the retired key signed only as vouched',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        initPhoneCrypto();
        final auth = AuthService();
        final vault = VaultService();
        await vault.init();
        final c = await auth.connectToServer(
          serverUrl: server!,
          password: cfg['password'] as String,
          username: cfg['username'] as String,
        );
        await net.settle();
        final forged = (cfg['forged'] as List).cast<String>();
        final ids = {
          for (final row in await DatabaseService().getAllObjects())
            row['id'] as String,
        };
        if (forged.isEmpty) {
          expect(c.outcome, isNot(ConnectOutcome.error), reason: c.message);
          for (final id in (cfg['vouched'] as List).cast<String>()) {
            expect(ids, contains(id));
          }
        } else {
          expect(c.outcome, ConnectOutcome.error, reason: c.message);
          expect(c.message, contains('invalid Ed25519 signature'));
          expect(forged.any((id) => c.message.contains(id)), isTrue);
          expect(ids.intersection(forged.toSet()), isEmpty);
        }
        await net.settle();
      }, () => net);
    },
    skip: server == null || dir == null
        ? 'run by tests/test_key_vouchers_phone.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
