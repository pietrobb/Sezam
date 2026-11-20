// Invitation onboarding through the real AuthService and real server.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'phone_qr_team_anchor_test.dart' show LyingNet;
import 'support/real_server_phone.dart';

class InvitationNet extends LyingNet {
  String fault = 'none';
  String initialLie = 'none';
  String? registeredUserId;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final response = await super.send(request);
    if (request.url.path == '/api/team-log' && initialLie != 'none') {
      final body = jsonDecode(await response.stream.bytesToString()) as Map<String, dynamic>;
      if (initialLie == 'missing') {
        body['head'] = null;
      } else if (initialLie == 'foreign') {
        body['head'] = {...body['head'] as Map, 'genesis_hash': 'ff' * 32};
      } else if (initialLie == 'signature') {
        (body['records'] as List).first['sig'] = '00' * 64;
      } else if (initialLie == 'short') {
        (body['records'] as List).clear();
      }
      return http.StreamedResponse(Stream.value(utf8.encode(jsonEncode(body))), response.statusCode,
          headers: response.headers);
    }
    if (request.url.path == '/api/me/keypair' && response.statusCode < 300 && fault == 'after-upload-storage') {
      secureWriteKillsApp = 'sezam_encrypted_keypair';
    }
    if (request.url.path == '/api/me/keypair' && response.statusCode < 300 && fault == 'upload-response-loss') {
      await response.stream.drain<void>();
      fault = 'retry-upload';
      throw const SocketException('lost successful upload response');
    }
    if (request.url.path != '/api/users/register' || response.statusCode >= 300) return response;
    final bytes = await response.stream.toBytes();
    registeredUserId = (jsonDecode(utf8.decode(bytes)) as Map)['user_id'] as String;
    if (fault == 'response-loss') {
      fault = 'retry-response';
      throw const SocketException('lost successful register response');
    }
    if (fault == 'pending-storage') secureWriteKillsApp = 'sezam_pending_invitation_registration';
    if (fault == 'storage') secureWriteKillsApp = 'sezam_confirmed_team_genesis:$registeredUserId';
    if (fault == 'conflict') await confirmTeamGenesis(registeredUserId!, 'ff' * 32);
    return http.StreamedResponse(Stream.value(bytes), response.statusCode, headers: response.headers);
  }
}

void main() {
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  test('invitation anchor constrains approval pull and offline restart', () async {
    final cfg = jsonDecode(File('$dir/config.json').readAsStringSync()) as Map<String, dynamic>;
    await setUpPhone('$dir/app');
    final portable = (cfg['lie'] as String).startsWith('portable-');
    final pinned = (cfg['lie'] as String).startsWith('pinned-');
    final locked = (cfg['lie'] as String).contains('-locked-');
    final net = InvitationNet()..fault = (cfg['lie'] as String).replaceFirst('portable-', '').replaceFirst('pinned-', '').replaceFirst('locked-', '');
    await http.runWithClient(() async {
      const storage = FlutterSecureStorage();
      final auth = AuthService();
      final vault = VaultService();
      final db = DatabaseService();
      final sync = SyncService();
      initPhoneCrypto();
      await vault.init();
      final created = await auth.createNewVault(password: cfg['password'] as String);
      expect(created.success, isTrue, reason: created.error);
      if (pinned) {
        await confirmTeamGenesis((await storage.read(key: 'sezam_user_object_id'))!,
          net.fault == 'conflict' ? 'ee' * 32 : cfg['genesis'] as String);
      }
      if (portable) {
        final keys = Uint8List.fromList([...vault.signingSecretKey!, ...vault.encryptionSecretKey!]);
        final crypto = CryptoService();
        await storage.write(key: 'sezam_encrypted_keypair', value: bytesToHex(crypto.wrapAccountKeypair(
          keys, net.fault == 'conflict' ? 'ee' * 32 : cfg['genesis'] as String,
          vault.currentKek!, vault.kekDekId!, (await storage.read(key: 'sezam_user_object_id'))!,
        )));
        crypto.zeroize(keys);
      }
      if (locked) {
        final folder = await vault.createNode(name: 'Mine', parentRef: vault.rootNodeId!);
        await vault.createEntry(parentRef: folder.id, name: 'unsent', fields: const [
          EntryField(key: 'password', value: 'local-secret', sensitive: true),
        ]);
      }
      final beforeRegistration = await db.getAllObjects();
      Future<ConnectResult> register([String? invitation]) => auth.registerWithInvitation(
        serverUrl: server!, username: 'invited-phone', password: cfg['password'] as String,
        invitationToken: invitation ?? (net.fault == 'no-fragment' ? (cfg['invitation'] as String).split('#').first : cfg['invitation'] as String),
      );
      Future<ConnectResult> resumeLocked() async {
        await auth.lock();
        await net.settle();
        await db.close();
        final offline = await auth.unlockOffline(password: cfg['password'] as String);
        expect(offline.success, isFalse, reason: 'missing trusted log must still prevent unlock');
        expect(vault.isUnlocked, isFalse);
        final saved = await storage.readAll();
        final requests = net.paths.length;
        for (final context in [
          (server!, 'invited-phone', 'wrong-password'),
          (server, 'another-user', cfg['password'] as String),
          ('https://elsewhere.invalid', 'invited-phone', cfg['password'] as String),
        ]) {
          final rejected = await auth.connectToServer(serverUrl: context.$1,
              username: context.$2, password: context.$3);
          expect(rejected.outcome, isNot(ConnectOutcome.needsApproval));
          expect(net.paths.length, requests, reason: 'wrong password/context rejected before network');
          expect(await storage.readAll(), saved);
          expect(await db.getAllObjects(), beforeRegistration);
        }
        final resumed = await auth.connectToServer(serverUrl: server,
            username: 'invited-phone', password: cfg['password'] as String);
        expect(vault.isUnlocked, isFalse, reason: 'enrollment must not unlock data');
        expect(await db.getAllObjects(), beforeRegistration);
        expect(await db.getSetting(teamLogRecordsSetting), isNull);
        expect(await storage.read(key: 'sezam_pending_invitation_registration'), isNotNull);
        return resumed;
      }
      for (final invalid in [
        (cfg['invitation'] as String).replaceFirst('#g=', '#g=0'),
        (cfg['invitation'] as String).replaceFirst(server!, 'https://elsewhere.invalid'),
      ]) {
        final refused = await register(invalid);
        expect(refused.outcome, ConnectOutcome.error);
        expect(net.paths, isEmpty, reason: 'invalid external trust refused before networking');
      }
      if ((portable || pinned) && net.fault == 'conflict') {
        final saved = await storage.readAll();
        net.fault = 'none';
        final refused = await register();
        expect(refused.outcome, ConnectOutcome.error, reason: refused.message);
        expect(net.paths, isEmpty, reason: 'conflicting authenticated anchor must fail before consuming invitation');
        expect(await storage.readAll(), saved);
        expect(await db.getAllObjects(), beforeRegistration);
        await handshake(dir!, 'refused');
        await auth.lock();
        return;
      }
      if (['upload', 'expired', 'pending-carrier'].contains(net.fault)) net.failPath = '/api/me/keypair';
      final resumeFault = ['response-loss', 'pending-storage', 'expired', 'upload-response-loss', 'after-upload-storage'].contains(net.fault);
      var result = await register();
      if (net.fault == 'pending-carrier') {
        expect(result.outcome, ConnectOutcome.error);
        final original = (await storage.read(key: 'sezam_pending_invitation_registration'))!;
        final saved = jsonDecode(original) as Map<String, dynamic>;
        final crypto = CryptoService();
        final keys = Uint8List.fromList([...vault.signingSecretKey!, ...vault.encryptionSecretKey!]);
        for (final wrongKek in [false, true]) {
          final canonical = (saved['response'] as Map)['user_id'] as String;
          saved['encrypted_keypair'] = bytesToHex(wrongKek
            ? crypto.wrapAccountKeypair(keys, cfg['genesis'] as String,
                Uint8List(32), vault.kekDekId!, canonical)
            : crypto.wrapKeypair(keys, vault.currentKek!, vault.kekDekId!, canonical));
          await storage.write(key: 'sezam_pending_invitation_registration', value: jsonEncode(saved));
          final uploads = net.paths.where((p) => p == '/api/me/keypair').length;
          final refused = await register();
          expect(refused.outcome, ConnectOutcome.error, reason: 'stale pending carrier must be refused');
          expect(net.paths.where((p) => p == '/api/me/keypair').length, uploads);
          expect(await db.getAllObjects(), beforeRegistration);
        }
        crypto.zeroize(keys);
        await storage.write(key: 'sezam_pending_invitation_registration', value: original);
        result = await register();
      }
      if (resumeFault) {
        expect(result.outcome, ConnectOutcome.error, reason: result.message);
        expect(await db.getAllObjects(), beforeRegistration);
        if (net.fault == 'expired') {
          final saved = jsonDecode((await storage.read(key: 'sezam_pending_invitation_registration'))!) as Map<String, dynamic>;
          await handshake(dir!, 'expire');
          final expired = File('$dir/expired-token.txt').readAsStringSync();
          final rejected = await http.put(Uri.parse('$server/api/me/keypair'),
              headers: {'Authorization': 'Bearer $expired', 'Content-Type': 'application/json'},
              body: jsonEncode({}));
          expect(rejected.statusCode, 401, reason: 'correctly signed expired token must be refused');
          (saved['response'] as Map)['token'] = expired;
          await storage.write(key: 'sezam_pending_invitation_registration', value: jsonEncode(saved));
        }
        if (locked) {
          result = await resumeLocked();
        } else {
          result = await register();
        }
        expect(result.outcome, ConnectOutcome.needsApproval, reason: result.message);
        expect(net.paths.where((p) => p == '/api/users/register').length, 1);
      }
      if (['storage', 'upload', 'conflict'].contains(net.fault)) {
        expect(result.outcome, ConnectOutcome.error, reason: result.message);
        expect(await db.getAllObjects(), beforeRegistration);
        expect(await readConfirmedTeamGenesis(net.registeredUserId!),
            net.fault == 'storage' ? isNull : net.fault == 'conflict' ? 'ff' * 32 : cfg['genesis']);
        final attempts = net.paths.length;
        final conflicting = await register((cfg['invitation'] as String).replaceFirst(cfg['genesis'] as String, 'ee' * 32));
        expect(conflicting.outcome, ConnectOutcome.error);
        expect(conflicting.message, contains(portable ? 'Account anchor changed or removed' : 'Finish the pending invitation registration first'));
        expect(net.paths.length, attempts);
        if (net.fault == 'conflict') {
          expect(net.paths, isNot(contains('/api/me/keypair')));
          await handshake(dir!, 'refused');
          await auth.lock();
          return;
        }
        if (!portable) {
          await auth.lock();
          await db.close();
          final local = await auth.unlockOffline(password: cfg['password'] as String);
          expect(local.success, isTrue, reason: local.error);
        }
        result = locked ? await resumeLocked() : await register();
        expect(net.paths.where((p) => p == '/api/users/register').length, 1,
            reason: 'retry reuses the scoped response, not the spent invitation');
      }
      expect(result.outcome, ConnectOutcome.needsApproval, reason: result.message);
      if (locked && ['none', 'login'].contains(net.fault)) {
        result = await resumeLocked();
        expect(result.outcome, ConnectOutcome.needsApproval, reason: result.message);
      }
      Future<bool> approvedLogin() async => net.fault == 'login'
          ? (await auth.unlockWithPassword(password: cfg['password'] as String,
              username: 'invited-phone', serverUrl: server)).success
          : auth.pollForApproval(username: 'invited-phone',
              password: cfg['password'] as String, serverUrl: server);
      if (locked) {
        expect(await approvedLogin(), isFalse);
        expect(vault.isUnlocked, isFalse);
        expect(await db.getAllObjects(), beforeRegistration);
      }
      if (portable && !locked) {
        final crypto = CryptoService();
        final account = crypto.openAccountKeypair(
          hexToBytes((await storage.read(key: 'sezam_encrypted_keypair'))!),
          vault.currentKek!, (await storage.read(key: 'sezam_user_object_id'))!,
        );
        expect(account.confirmedGenesis, cfg['genesis']);
        crypto.zeroize(account.keypairData);
      }
      await handshake(dir!, 'approve');
      final userId = File('$dir/user-id.txt').readAsStringSync();
      final genesis = cfg['genesis'] as String;
      expect(await readConfirmedTeamGenesis(userId), genesis);
      if (locked) {
        for (final lie in ['missing', 'foreign', 'signature', 'short']) {
          net.initialLie = lie;
          expect(await approvedLogin(), isFalse, reason: lie);
          expect(vault.isUnlocked, isFalse);
          expect(await db.getAllObjects(), beforeRegistration);
          expect(await db.getSetting(teamLogRecordsSetting), isNull);
          expect(await db.getSyncState('sync_checkpoint:$userId'), isNull);
          expect(await readConfirmedTeamGenesis(userId), genesis);
          expect(await storage.read(key: 'sezam_pending_invitation_registration'), isNotNull);
        }
        net.initialLie = 'none';
      }
      if (net.fault == 'login') {
        await auth.lock();
        final saved = await storage.readAll();
        final requests = net.paths.length;
        for (final context in [(server, 'other-user'), ('https://elsewhere.invalid', 'invited-phone')]) {
          final refused = await auth.unlockWithPassword(password: cfg['password'] as String,
              username: context.$2, serverUrl: context.$1);
          expect(refused.success, isFalse);
          expect(net.paths.length, requests);
          expect(await storage.readAll(), saved);
        }
        for (final path in ['/api/auth/verify', '/api/team-log']) {
          net.failPath = path;
          expect(await approvedLogin(), isFalse, reason: path);
          expect(vault.isUnlocked, isFalse);
          expect(await storage.read(key: 'sezam_pending_invitation_registration'), isNotNull);
          expect(await db.getAllObjects(), beforeRegistration);
        }
        final opened = await auth.unlockWithPassword(password: cfg['password'] as String,
            username: 'invited-phone', serverUrl: server);
        expect(opened.success, isTrue, reason: opened.error);
        expect(await storage.read(key: 'sezam_pending_invitation_registration'), isNull,
            reason: 'ordinary authenticated login must finish approved registration');
        await net.settle();
        final registrations = net.paths.where((p) => p == '/api/users/register').length;
        final connected = await auth.connectToServer(serverUrl: server,
            username: 'invited-phone', password: cfg['password'] as String);
        expect(connected.outcome, ConnectOutcome.connected, reason: connected.message);
        expect(net.paths.where((p) => p == '/api/users/register').length, registrations);
      } else {
        expect(await auth.pollForApproval(username: 'invited-phone',
            password: locked ? cfg['password'] as String : null, serverUrl: locked ? server : null), isTrue);
      }
      if (locked) {
        await net.settle();
        expect(passwords(vault)['unsent'], 'local-secret');
      }
      final before = await db.getAllObjects();
      if (net.fault.startsWith('restart-')) {
        final viaQR = net.fault.startsWith('restart-qr-');
        final qrTokens = <String>[];
        if (viaQR) {
          for (var i = 0; i < 2; i++) {
            final issued = await http.post(Uri.parse('$server/api/auth/provisioning-token'),
                headers: {'Authorization': 'Bearer ${sync.token}'});
            expect(issued.statusCode, 200);
            qrTokens.add((jsonDecode(issued.body) as Map)['token'] as String);
          }
        }
        await auth.lock();
        await db.close();
        final offline = await auth.unlockOffline(password: cfg['password'] as String);
        expect(offline.success, isFalse, reason: 'no log yet: offline must stay fail-closed');
        expect(await db.getAllObjects(), before);
        final failure = net.fault.split('-').last;
        Future<AuthResult> online() async {
          if (!viaQR) {
            return auth.unlockWithPassword(password: cfg['password'] as String,
                username: 'invited-phone', serverUrl: server);
          }
          return auth.provisionFromQR(
              provisionToken: qrTokens.removeAt(0),
              genesisFragment: 'g=$genesis', username: 'invited-phone',
              password: cfg['password'] as String, serverUrl: server);
        }
        if (failure == 'network') {
          net.failPath = '/api/team-log';
        } else {
          net.initialLie = failure;
        }
        var opened = await online();
        if (failure != 'none') {
          expect(opened.success, isFalse, reason: opened.error);
          expect(vault.isUnlocked, isFalse);
          expect(await db.getAllObjects(), before);
          expect(await db.getSetting(teamLogRecordsSetting), isNull);
          expect(await db.getSyncState('sync_checkpoint:$userId'), isNull);
          expect(await readConfirmedTeamGenesis(userId), genesis);
          net.initialLie = 'none';
          opened = await online();
        }
        expect(opened.success, isTrue, reason: opened.error);
        await net.settle();
      }
      net.lie = ['missing', 'foreign'].contains(cfg['lie']) ? cfg['lie'] as String : 'none';
      if (net.lie != 'none') {
        await expectLater(sync.pull(), throwsA(isA<SyncIntegrityException>()));
        final refused = await auth.connectToServer(serverUrl: server, username: 'invited-phone', password: cfg['password'] as String);
        expect(refused.outcome, ConnectOutcome.error, reason: 'a rejected trust anchor must not report connected: ${refused.message}');
        expect(refused.message, contains('TEAM LOG MISMATCH'));
        expect(await db.getAllObjects(), before);
        expect(await readConfirmedTeamGenesis(userId), genesis);
        net.lie = 'none';
      }
      await sync.pull();
      await vault.reloadData();
      expect(await db.getObjectsByType('envelope'), isNotEmpty, reason: 'accepted shared envelope');
      expect(vault.userId, userId);
      expect(vault.teamLog!.team.genesisHash, genesis);
      expect(passwords(vault)['vpn'], 'ops-pw');
      if (locked) expect(passwords(vault)['unsent'], 'local-secret');
      if (net.fault == 'none') {
        final sql = await db.database;
        final envelope = (await db.getObjectsByType('envelope')).firstWhere((r) => r['target_user_id'] == userId);
        for (final damage in [
          {'access_level': 'write'},
          {'signer_id': userId},
          {'client_signature': Uint8List(64)},
          {'target_user_id': '01JM0000000000000000000004'},
        ]) {
          await sql.update('vault_objects', damage, where: 'id = ?', whereArgs: [envelope['id']]);
          await vault.reloadData();
          expect(passwords(vault), isNot(contains('vpn')), reason: damage.keys.single);
          await sql.update('vault_objects', {...envelope}..remove('queued'), where: 'id = ?', whereArgs: [envelope['id']]);
          await vault.reloadData();
          expect(passwords(vault)['vpn'], 'ops-pw');
        }
      }
      await auth.lock();
      await net.settle();
      await db.close();
      final reopened = await auth.unlockOffline(password: cfg['password'] as String);
      expect(reopened.success, isTrue, reason: reopened.error);
      expect(vault.teamLog!.team.genesisHash, genesis);
      expect(passwords(vault)['vpn'], 'ops-pw');
      if (locked) expect(passwords(vault)['unsent'], 'local-secret');
      if (net.fault == 'restart-none') {
        final cached = (await db.getSetting(teamLogRecordsSetting))!;
        final checkpoint = await db.getSyncState('sync_checkpoint:$userId');
        expect(checkpoint, isNotNull);
        final rows = await db.getAllObjects();
        for (final damaged in [null, '{bad-json']) {
          await auth.lock();
          if (damaged == null) {
            await db.deleteSetting(teamLogRecordsSetting);
          } else {
            await db.setSetting(teamLogRecordsSetting, damaged);
          }
          // INV-7: the copy only caches what the pins bind. The sign-in
          // fetches the log again under them (before, it refused with no way
          // out); a server that lies is refused there
          // (team_log_copy_lost_vectors_test.dart).
          final requests = net.paths.length;
          final opened = await auth.unlockWithPassword(password: cfg['password'] as String,
              username: 'invited-phone', serverUrl: server);
          expect(opened.success, isTrue, reason: opened.error);
          expect(net.paths.skip(requests), contains('/api/team-log'));
          expect(jsonDecode((await db.getSetting(teamLogRecordsSetting))!), jsonDecode(cached));
          expect(vault.teamLog!.team.genesisHash, genesis);
          expect(passwords(vault)['vpn'], 'ops-pw');
          expect(await readConfirmedTeamGenesis(userId), genesis);
          await auth.lock();
          await net.settle();
          expect(await db.getAllObjects(), rows);
        }
        await db.setSetting(teamLogRecordsSetting, cached);
        final restored = await auth.unlockOffline(password: cfg['password'] as String);
        expect(restored.success, isTrue, reason: restored.error);
        expect(passwords(vault)['vpn'], 'ops-pw');
      }
      await auth.lock();
      await net.settle();
    }, () => net);
  }, skip: server == null || dir == null ? 'run by tests/test_team_log_phone.py' : false,
      timeout: const Timeout(Duration(minutes: 5)));
}
