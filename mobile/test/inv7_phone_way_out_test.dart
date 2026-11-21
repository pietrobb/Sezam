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
        final kept = await vault.createEntry(parentRef: personal.id, name: 'while-conflict', fields: const []);
        await net.settle();
        // The push sends the personal tree first; the pull then names the refusal.
        await expectLater(sync.sync(),
            throwsA(isA<SyncIntegrityException>().having((e) => e.teamLog?.cause, 'cause', 'anchor_conflict')),
            reason: 'conflicting pins are never followed; the refusal names its way out');
        // Before: the push refused it too, so it stayed here until a risky forget.
        File('$dir/pushed_id.txt').writeAsStringSync(kept.id);
        await handshake(dir, 'pushed_while_conflict');
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

        // 3. Capability run 411, online: trust records that cannot be read
        // (the left genesis hashes, the pin) are no password error.
        await relock();
        await storage.write(key: 'sezam_forgotten_team_genesis:$uid', value: '{');
        await storage.write(key: 'sezam_confirmed_team_genesis:$uid', value: '{');
        final online = await auth.unlockWithPassword(
            serverUrl: server, username: cfg['username'] as String, password: password);
        expect(online.success, isTrue, reason: online.error); // before: "Wrong password or corrupted keypair"
        await net.settle();
        expect(vault.teamLogRefusal?.cause, 'local_damaged');
        expect(vault.nodes[personal.id]?.name, 'mine');
        // The way out: the founder confirmed again replaces both.
        final records = jsonDecode((await db.getSetting(teamLogRecordsSetting))!) as List;
        final founder = (jsonDecode((records.first as Map)['body'] as String) as Map)['data'] as Map;
        await vault.confirmTeamFounder(await vault.reviewTeamFounder(), CryptoService().computeFingerprint(
            hexToBytes(founder['signing_pk'] as String), hexToBytes(founder['encryption_pk'] as String)));
        expect(await readConfirmedTeamGenesis(uid), genesis);
        expect(await readForgottenTeamGenesis(uid), isEmpty);
        // Only the unreadable list remembered that `other` (still in the keys,
        // step 2) was left: it is a named conflict again, forgotten as before.
        expect(vault.teamLogRefusal?.cause, 'anchor_conflict');
        expect(await sync.forgetTeamLogPin('${genesis.substring(0, 16)} ${other.substring(0, 16)}'),
            ([genesis, other]..sort()));
        expect(vault.teamLogRefusal, isNull);
        await sync.sync();
        expect(vault.teamLog?.team.genesisHash, genesis);

        // 4. Capability run 412: the password unlock that takes the keys from
        // the server (none opens here) with a trust record that cannot be read.
        // The server's keys name the genesis (published), so they are imported.
        await vault.confirmTeamFounder(await vault.reviewTeamFounder(), CryptoService().computeFingerprint(
            hexToBytes(founder['signing_pk'] as String), hexToBytes(founder['encryption_pk'] as String)));
        final anchored = '$password anchored';
        final published = await auth.publishTeamAnchor(currentPassword: password, newPassword: anchored);
        expect(published.success, isTrue, reason: published.error);
        await net.settle();
        await sync.sync();
        for (final record in ['forgotten', 'confirmed']) {
          await relock();
          await storage.delete(key: 'sezam_encrypted_keypair');
          await storage.write(key: 'sezam_${record}_team_genesis:$uid', value: '{');
          final fetched = await auth.unlockWithPassword(
              serverUrl: server, username: cfg['username'] as String, password: anchored);
          expect(fetched.success, isTrue, reason: '$record: ${fetched.error}'); // before: "Wrong password or corrupted keypair"
          await net.settle();
          expect(vault.teamLogRefusal?.cause, 'local_damaged', reason: record);
          expect(vault.nodes[personal.id]?.name, 'mine');
          await vault.confirmTeamFounder(await vault.reviewTeamFounder(), CryptoService().computeFingerprint(
              hexToBytes(founder['signing_pk'] as String), hexToBytes(founder['encryption_pk'] as String)));
          expect(await readConfirmedTeamGenesis(uid), genesis);
          if (vault.teamLogRefusal?.cause == 'anchor_conflict') {
            // As in step 3: only the replaced list remembered leaving `other`.
            expect(record, 'forgotten');
            await sync.forgetTeamLogPin('${genesis.substring(0, 16)} ${other.substring(0, 16)}');
          }
          expect(vault.teamLogRefusal, isNull, reason: record);
          await sync.sync();
          expect(vault.teamLog?.team.genesisHash, genesis, reason: record);
        }
        await relock();
      }, () => net);
      net.close();
    },
    skip: server == null || dir == null,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
