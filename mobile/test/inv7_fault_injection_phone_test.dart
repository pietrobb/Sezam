// INV-7 / INV-5 precedence (docs/ROOT_CAUSE_PLAN.md, R15-P4), phone against a
// real server (tests/test_inv7_fault_injection_phone.py): a fault at any
// request of a sync after a personal write, while the admin moves a member's
// access on the desktop (no answer, 500, 503), never
// offers or does a forget, never moves a pin, and holds the personal change
// back at most until the next clean sync; a fault anywhere but the push itself
// does not hold it at all.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  test(
    'a fault at any request of a sync never forgets and never holds the personal tree',
    () async {
      final cfg = jsonDecode(File('$dir/config.json').readAsStringSync()) as Map<String, dynamic>;
      final uid = cfg['user_id'] as String;
      final genesis = cfg['genesis'] as String;
      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        final auth = AuthService();
        final sync = SyncService();
        final vault = VaultService();
        initPhoneCrypto();
        await vault.init();
        final unlocked = await auth.unlockWithPassword(
            serverUrl: server!, username: cfg['username'] as String, password: cfg['password'] as String);
        expect(unlocked.success, isTrue, reason: unlocked.error);
        await net.settle();
        await sync.sync();
        expect(vault.teamLog?.team.genesisHash, genesis);
        final confirmed = await readConfirmedTeamGenesis(uid);
        final personal = await vault.createPersonalFolder(name: 'mine');
        await net.settle();
        await sync.sync();
        expect(await sync.getDirtyObjectCount(), 0);
        final pins = await sync.pinnedTeamGenesis();
        expect(pins, contains(genesis));

        // The requests of one clean round: the desktop admin moves a member's
        // access (a new log record, keys and an envelope), then a personal
        // write and a sync here.
        var moves = 0;
        await handshake(dir!, 'move${moves++}');
        await vault.createEntry(parentRef: personal.id, name: 'clean', fields: const []);
        await net.settle();
        final start = net.paths.length;
        await sync.sync();
        final round = net.paths.sublist(start);
        expect(round, contains('/api/team-log'), reason: 'the round fetches the log');
        expect(await sync.getDirtyObjectCount(), 0);
        File('$dir/rounds.txt').writeAsStringSync('${round.length * 3}');
        await handshake(dir, 'rounds');

        var n = 0;
        for (var k = 0; k < round.length; k++) {
          for (final fault in ['network', '500', '503']) {
            final label = '$fault at request $k (${round[k]})';
            await handshake(dir, 'move${moves++}');
            var seen = 0;
            String? faulted;
            net.onSend = (path) {
              if (seen++ != k) return;
              faulted = path;
              if (fault == 'network') {
                net.failPath = path;
              } else {
                net.refuseStatus = int.parse(fault);
                net.refusePath = path;
              }
            };
            await vault.createEntry(parentRef: personal.id, name: 'entry-${n++}', fields: const []);
            await net.settle();
            try {
              await sync.sync();
            } on Exception {
              // The fault is reported; what it may hold is checked below.
            }
            await net.settle();
            net.onSend = null;
            net.refuseStatus = 401;
            // INV-8: a fault is no lost log; nothing is forgotten or offered.
            final refusal = vault.teamLogRefusal;
            expect(refusal?.offersForget ?? false, isFalse, reason: '$label: ${refusal?.cause}');
            expect(await sync.pinnedTeamGenesis(), pins, reason: label);
            expect(await readConfirmedTeamGenesis(uid), confirmed, reason: label);
            if (faulted != null && faulted != '/api/sync') {
              // INV-7: only the push's own request can hold the personal change.
              expect(await sync.getDirtyObjectCount(), 0, reason: '$label: the personal change went out');
            }
            // The next clean sync sends whatever waited and follows the log again.
            await sync.sync();
            expect(await sync.getDirtyObjectCount(), 0, reason: label);
            expect(vault.teamLogRefusal, isNull, reason: label);
            expect(vault.teamLog?.team.genesisHash, genesis, reason: label);
          }
        }
        // The unlock: a sign-in with a fault at each request of a clean one.
        // Only the sign-in's own requests may keep it locked; once open, the
        // personal tree is there, and nothing is forgotten.
        Future<AuthResult> signIn() async {
          await auth.lock();
          await net.settle();
          await handshake(dir, 'move${moves++}');
          return auth.unlockWithPassword(
              serverUrl: server, username: cfg['username'] as String, password: cfg['password'] as String);
        }
        final signInStart = net.paths.length;
        final clean = await signIn();
        expect(clean.success, isTrue, reason: clean.error);
        await net.settle();
        final signin = net.paths.sublist(signInStart);
        File('$dir/signins.txt').writeAsStringSync('${signin.length * 3}');
        await handshake(dir, 'signins');
        const ownRequests = {'/api/meta', '/api/auth/challenge', '/api/auth/verify'};
        for (var k = 0; k < signin.length; k++) {
          for (final fault in ['network', '500', '503']) {
            final label = 'sign-in: $fault at request $k (${signin[k]})';
            String? faulted;
            final at = net.paths.length;
            net.onSend = (path) {
              if (net.paths.length - 1 - at != k) return;
              faulted = path;
              if (fault == 'network') {
                net.failPath = path;
              } else {
                net.refuseStatus = int.parse(fault);
                net.refusePath = path;
              }
            };
            final opened = await signIn();
            await net.settle();
            net.onSend = null;
            net.refuseStatus = 401;
            final refusal = vault.teamLogRefusal;
            expect(refusal?.offersForget ?? false, isFalse, reason: '$label: ${refusal?.cause}');
            expect(await readConfirmedTeamGenesis(uid), confirmed, reason: label);
            if (!opened.success || sync.token == null) {
              // Opened offline at most (this phone's own vault), never by a team request.
              expect(ownRequests, contains(faulted), reason: '$label: ${opened.error}');
              if (opened.success) {
                expect(vault.nodes[personal.id]?.name, 'mine', reason: label);
                await auth.lock();
                await net.settle();
              }
              final again = await auth.unlockWithPassword(
                  serverUrl: server, username: cfg['username'] as String, password: cfg['password'] as String);
              expect(again.success, isTrue, reason: again.error);
              await net.settle();
            }
            expect(await sync.pinnedTeamGenesis(), pins, reason: label);
            expect(vault.nodes[personal.id]?.name, 'mine', reason: label);
            await sync.sync();
            expect(vault.teamLogRefusal, isNull, reason: label);
            expect(await sync.getDirtyObjectCount(), 0, reason: label);
          }
        }
        await auth.lock();
        await net.settle();
      }, () => net);
      net.close();
    },
    skip: server == null || dir == null,
    timeout: const Timeout(Duration(minutes: 10)),
  );
}
