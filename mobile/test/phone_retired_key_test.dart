// Capability runs 294/300: after a restore from before an identity rotation,
// a server that still calls the retired key current gets no write signed with
// it onto the phone. Run by tests/test_review9_retired_key_after_restore.py.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  test(
    'a write signed by a key the team log retired never lands on the phone',
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
        await confirmTeamGenesis(
          cfg['user_id'] as String,
          cfg['genesis'] as String,
        );
        final c = await auth.connectToServer(
          serverUrl: server!,
          password: cfg['password'] as String,
          username: cfg['username'] as String,
        );
        await net.settle();
        // The first pull refuses the object; the phone keeps nothing of it.
        expect(c.outcome, ConnectOutcome.error, reason: c.message);
        final forged = (cfg['forged'] as List).cast<String>();
        expect(c.message, contains('SyncIntegrityException'));
        expect(c.message, contains('invalid Ed25519 signature'));
        expect(forged.any((id) => c.message.contains(id)), isTrue);
        final ids = {
          for (final row in await DatabaseService().getAllObjects())
            row['id'] as String,
        };
        expect(ids.intersection(forged.toSet()), isEmpty);
        expect(vault.isUnlocked, isFalse);
        await net.settle();
      }, () => net);
    },
    skip: server == null || dir == null
        ? 'run by tests/test_review9_retired_key_after_restore.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
