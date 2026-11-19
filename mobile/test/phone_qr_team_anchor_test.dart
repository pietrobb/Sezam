// Real QR provisioning and restart, driven by test_team_log_phone.py.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

class LyingNet extends Net {
  String lie = 'none';

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final response = await super.send(request);
    if (request.method != 'GET' ||
        request.url.path != '/api/sync' ||
        lie == 'none')
      return response;
    final body =
        jsonDecode(await response.stream.bytesToString())
            as Map<String, dynamic>;
    if (lie == 'missing') {
      body['team_log_head'] = null;
    } else {
      body['team_log_head'] = {
        ...body['team_log_head'] as Map,
        'genesis_hash': 'ff' * 32,
      };
    }
    return http.StreamedResponse(
      Stream.value(utf8.encode(jsonEncode(body))),
      response.statusCode,
      headers: response.headers,
    );
  }
}

void main() {
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  test(
    'QR trust survives failed pull, DB replacement and offline restart',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      await setUpPhone('$dir/app');
      final net = LyingNet();
      await http.runWithClient(() async {
        final auth = AuthService();
        final vault = VaultService();
        final db = DatabaseService();
        final sync = SyncService();
        initPhoneCrypto();
        await vault.init();
        if (cfg['local'] == true) {
          final created = await auth.createNewVault(
            password: 'phone-only-Pw-1234',
          );
          expect(created.success, isTrue, reason: created.error);
          final folder = await vault.createNode(
            name: 'Mine',
            parentRef: vault.rootNodeId!,
          );
          await vault.createEntry(
            parentRef: folder.id,
            name: 'offline',
            fields: const [
              EntryField(key: 'password', value: 'o1', sensitive: true),
            ],
          );
        }
        final before = await db.getAllObjects();
        final userId = cfg['user_id'] as String;
        final genesis = cfg['genesis'] as String;
        final lie = cfg['lie'] as String;
        final conflict = (cfg['trust'] as String).endsWith('conflict');
        const storage = FlutterSecureStorage();
        if (cfg['trust'] == 'pinned-conflict') {
          await confirmTeamGenesis(userId, genesis);
        }
        final beforeSecure = await storage.readAll();
        Future<AuthResult> provision(String step) async {
          await handshake(dir!, step);
          final uri = Uri.parse(File('$dir/qr.txt').readAsStringSync());
          return auth.provisionFromQR(
            provisionToken: uri.queryParameters['token']!,
            genesisFragment: uri.fragment,
            username: uri.queryParameters['username']!,
            password: cfg['password'] as String,
            serverUrl: uri.queryParameters['server']!,
          );
        }

        if (lie == 'network') {
          net.failPath = '/api/sync';
        } else if (lie == 'storage') {
          secureWriteKillsApp = 'sezam_confirmed_team_genesis:$userId';
        } else {
          net.lie = lie;
        }
        final first = await provision('token');
        await net.settle();
        expect(
          await readConfirmedTeamGenesis(userId),
          lie == 'storage' || cfg['trust'] == 'conflict' ? isNull : genesis,
        );
        if (lie != 'none' || conflict) {
          expect(
            first.success,
            isFalse,
            reason: 'lying or failed pull must not provision',
          );
          if (conflict) expect(await storage.readAll(), beforeSecure);
          if (lie == 'missing' || lie == 'foreign' || conflict) {
            expect(first.error, contains('TEAM LOG MISMATCH'));
          }
          expect(
            await db.getAllObjects(),
            before,
            reason: 'no server rows accepted; local DB restored',
          );
          if (cfg['local'] == true) {
            expect(passwords(vault), {'offline': 'o1'});
          } else {
            expect(vault.isUnlocked, isFalse);
          }
          net.lie = 'none';
          final retry = await provision('retry');
          expect(retry.success, isTrue, reason: retry.error);
        } else {
          expect(first.success, isTrue, reason: first.error);
        }
        await net.settle();
        await vault.reloadData();
        expect(vault.teamLog!.team.genesisHash, genesis);
        expect(passwords(vault)['vpn'], 'ops-pw');
        final heldLog = vault.teamLog;
        final heldRows = await db.getAllObjects();
        vault.teamLog = null;
        await expectLater(sync.push(), throwsA(isA<TeamLogMismatch>()));
        await expectLater(
          vault.createNode(name: 'blocked', parentRef: vault.rootNodeId!),
          throwsA(isA<TeamLogMismatch>()),
        );
        expect(await db.getAllObjects(), heldRows);
        vault.teamLog = heldLog;
        if (cfg['local'] == true) expect(passwords(vault)['offline'], 'o1');
        await auth.lock();
        await net.settle();
        await db.close();
        if (cfg['trust'] != 'fragment') {
          await const FlutterSecureStorage().delete(
            key: 'sezam_confirmed_team_genesis:$userId',
          );
          expect(await readConfirmedTeamGenesis(userId), isNull);
        }
        final reopened = await auth.unlockOffline(
          password: cfg['password'] as String,
        );
        expect(reopened.success, isTrue, reason: reopened.error);
        expect(vault.teamLog!.team.genesisHash, genesis);
        expect(passwords(vault)['vpn'], 'ops-pw');
        await expectLater(
          confirmTeamGenesis(userId, 'ff' * 32),
          throwsA(isA<TeamLogMismatch>()),
        );
        expect(await readConfirmedTeamGenesis(userId), genesis);
        // A pull remains constrained after the provisioning call and restart.
        await sync.authenticate(
          username: cfg['username'] as String,
          signingSecretKey: vault.signingSecretKey!,
        );
        net.lie = 'missing';
        await expectLater(sync.pull(), throwsA(isA<SyncIntegrityException>()));
        expect(await readConfirmedTeamGenesis(userId), genesis);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: server == null || dir == null
        ? 'run by tests/test_team_log_phone.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
