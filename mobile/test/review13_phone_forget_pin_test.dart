// Review c78fd19 (medium): a phone pinned to a team log the server lost for
// good (reseeded) stayed on TEAM LOG MISMATCH with no way out. Forgetting the
// pin (the user types the pinned genesis) lets it follow the new log.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  test(
    'a phone leaves a team log the server lost for good',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final uid = cfg['user_id'] as String;
      final old = cfg['genesis'] as String;
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
          username: cfg['username'] as String,
          password: cfg['password'] as String,
        );
        expect(unlocked.success, isTrue, reason: unlocked.error);
        await net.settle();
        await sync.sync();
        expect(vault.teamLog?.team.genesisHash, old);
        // The keypair stored here carries the anchor too (capability #374).
        Future<String?> storedAnchor() async {
          final envelope = await const FlutterSecureStorage().read(key: 'sezam_encrypted_keypair');
          final account = CryptoService().openAccountKeypair(hexToBytes(envelope!), vault.currentKek!, uid);
          return account.confirmedGenesis;
        }
        expect(await storedAnchor(), old);

        await handshake(dir!, 'reseed');
        final fresh = File('$dir/new_genesis.txt').readAsStringSync();
        await expectLater(
          sync.sync(),
          throwsA(predicate((e) => '$e'.contains('Zabudnúť pripnutý tímový denník'))),
        );
        expect(await sync.pinnedTeamGenesis(), [old]);
        for (final typed in ['', old.substring(0, 15), fresh.substring(0, 16)]) {
          await expectLater(sync.forgetTeamLogPin(typed), throwsA(isA<FormatException>()));
        }
        expect(await sync.pinnedTeamGenesis(), [old]);

        expect(await sync.forgetTeamLogPin(old.substring(0, 16).toUpperCase()), [old]);
        expect(vault.teamLog, isNull);
        expect(await readForgottenTeamGenesis(uid), [old]);
        // The account bundle may still name it: not pinned again from there.
        await importAccountTeamGenesis(uid, old);
        expect(await readConfirmedTeamGenesis(uid), isNull);

        await sync.sync();
        expect(vault.teamLog?.team.genesisHash, fresh);
        expect(await sync.pinnedTeamGenesis(), [fresh]);

        // Unlocked again later, it still follows the new log.
        await auth.lock();
        await net.settle();
        await DatabaseService().close();
        final offline = await auth.unlockOffline(password: cfg['password'] as String);
        expect(offline.success, isTrue, reason: offline.error);
        expect(vault.teamLog?.team.genesisHash, fresh);
        // Still named by the stored keypair, but left: not pinned from there.
        expect(await storedAnchor(), old);

        // Another device anchors the account to the new log; logging in
        // online must take it (the left anchor is no continuity break).
        await auth.lock();
        await net.settle();
        await DatabaseService().close();
        await handshake(dir, 'anchor_new');
        final online = await auth.unlockWithPassword(
          serverUrl: server,
          username: cfg['username'] as String,
          password: cfg['new_password'] as String,
          previousPassword: cfg['password'] as String,
        );
        expect(online.success, isTrue, reason: online.error);
        await net.settle();
        await sync.sync();
        expect(vault.teamLog?.team.genesisHash, fresh);
        expect(await storedAnchor(), fresh);
        expect(await sync.pinnedTeamGenesis(), [fresh]);
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
