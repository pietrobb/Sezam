// INV-7 against a real server (tests/test_inv7_phone_way_out.py): a team log
// this phone refuses never keeps the vault locked, and each cause has a way
// out that runs on the unlocked vault. A damaged cached copy is fetched again
// by the next sync, held to its pins, and what was written meanwhile goes out;
// account keys naming another log are forgotten together with the own pin.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
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
    'a phone refusing its team log unlocks and finds the way out',
    () async {
      final cfg = jsonDecode(File('$dir/config.json').readAsStringSync()) as Map<String, dynamic>;
      final uid = cfg['user_id'] as String;
      final password = cfg['password'] as String;
      final genesis = cfg['genesis'] as String;
      final other = 'ab' * 32;
      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        final auth = AuthService();
        final sync = SyncService();
        final vault = VaultService();
        final db = DatabaseService();
        initPhoneCrypto();
        await vault.init();
        final unlocked = await auth.unlockWithPassword(
          serverUrl: server!, username: cfg['username'] as String, password: password);
        expect(unlocked.success, isTrue, reason: unlocked.error);
        await net.settle();
        await sync.sync();
        expect(vault.teamLog?.team.genesisHash, genesis);
        final personal = await vault.createPersonalFolder(name: 'mine');
        await sync.sync();
        expect(await sync.getDirtyObjectCount(), 0);

        Future<void> relock() async {
          await auth.lock();
          await net.settle();
          await DatabaseService().close();
        }

        // 1. A damaged cached copy: offline the vault opens, the team is refused.
        await relock();
        await db.setSetting(teamLogRecordsSetting, '{');
        final damaged = await auth.unlockOffline(password: password);
        expect(damaged.success, isTrue, reason: damaged.error);
        expect(vault.teamLogRefusal?.cause, 'local_damaged');
        final written = await vault.createEntry(parentRef: personal.id, name: 'while-damaged', fields: const []);
        await net.settle();
        // The way out: the next sync fetches the copy again before it pushes.
        await sync.sync();
        expect(vault.teamLogRefusal, isNull);
        expect(vault.teamLog?.team.genesisHash, genesis);
        expect(await sync.getDirtyObjectCount(), 0);
        File('$dir/pushed_id.txt').writeAsStringSync(written.id);
        await handshake(dir!, 'pushed');

        // 2. The account keys name another log than this phone holds and pins.
        const storage = FlutterSecureStorage();
        final keys = Uint8List.fromList([...vault.signingSecretKey!, ...vault.encryptionSecretKey!]);
        await storage.write(key: 'sezam_encrypted_keypair', value: bytesToHex(CryptoService().wrapAccountKeypair(
            keys, other, Uint8List.fromList(vault.currentKek!), (await db.getSetting('kek_dek_id'))!, uid)));
        await relock();
        final conflict = await auth.unlockOffline(password: password); // before: "Wrong password"
        expect(conflict.success, isTrue, reason: conflict.error);
        expect(vault.teamLogRefusal?.cause, 'anchor_conflict');
        expect(vault.nodes[personal.id]?.name, 'mine');
        await net.settle();
        await expectLater(sync.sync(),
            throwsA(isA<TeamLogMismatch>().having((e) => e.cause, 'cause', 'anchor_conflict')),
            reason: 'conflicting pins are never followed; the refusal names its way out');
        final refusal = await sync.teamLogRefusal();
        expect(refusal?.cause, 'anchor_conflict');
        expect(refusal!.offersForget, isTrue);
        final pins = await sync.pinnedTeamGenesis();
        expect(pins, ([genesis, other]..sort()));
        // Each conflicting pin is typed; one alone forgets nothing.
        await expectLater(sync.forgetTeamLogPin(genesis.substring(0, 16)), throwsA(isA<FormatException>()));
        expect(await sync.forgetTeamLogPin('${genesis.substring(0, 16)} ${other.substring(0, 16)}'), pins);
        expect(vault.teamLogRefusal, isNull);
        expect(await readAccountTeamGenesis(uid), isNull);
        expect(await readConfirmedTeamGenesis(uid), isNull);
        await sync.sync();
        expect(vault.teamLog?.team.genesisHash, genesis, reason: 'followed again, as a new log');
        expect(vault.nodes[personal.id]?.name, 'mine');

        // Unlocked again later: the left anchor refuses nothing.
        await relock();
        final again = await auth.unlockOffline(password: password);
        expect(again.success, isTrue, reason: again.error);
        expect(vault.teamLogRefusal, isNull);
        await relock();
      }, () => net);
      net.close();
    },
    skip: server == null || dir == null,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
