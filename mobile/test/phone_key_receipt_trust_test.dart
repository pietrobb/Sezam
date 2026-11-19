// Real server KEK/box receipt and cached authorization, driven by Python.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/services.dart';
import 'package:biometric_storage/biometric_storage.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

class _ReleasedBiometricKek extends MethodChannelBiometricStorage {
  _ReleasedBiometricKek(this.kek);
  final String kek;
  @override
  Future<String?> read(String name, PromptInfo promptInfo) async => kek;
}

void main() {
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  test(
    'team keys require confirmed authority on receipt and restart',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final mode = cfg['case'] as String;
      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        final auth = AuthService();
        final sync = SyncService();
        final vault = VaultService();
        initPhoneCrypto();
        await vault.init();
        if (!mode.endsWith('unconfirmed') && !mode.startsWith('founder-') && !mode.startsWith('portable-')) {
          await confirmTeamGenesis(
            cfg['user_id'] as String,
            cfg['genesis'] as String,
          );
        }
        if (mode == 'portable-conflict') {
          await confirmTeamGenesis(cfg['user_id'] as String, 'cd' * 32);
        }
        if (mode == 'portable-storage') {
          secureWriteKillsApp = 'sezam_confirmed_team_genesis:${cfg['user_id']}';
        }
        var connected = await auth.unlockWithPassword(
          serverUrl: server!,
          username: mode.startsWith('founder-') ? 'admin' : 'bob',
          password: cfg['password'] as String,
        );
        if (mode == 'portable-storage' || mode == 'portable-conflict' || mode == 'portable-foreign') {
          expect(connected.success, isFalse, reason: mode);
          expect(passwords(vault)['anchor-secret'], isNull);
          expect(net.paths.where((p) => p == '/api/sync'), isEmpty);
          if (mode != 'portable-storage') return;
          expect(await readConfirmedTeamGenesis(cfg['user_id'] as String), isNull);
          connected = await auth.unlockWithPassword(serverUrl: server, username: 'bob', password: cfg['password'] as String);
        }
        expect(connected.success, isTrue, reason: connected.error);
        await net.settle();
        await sync.sync();
        if (mode.startsWith('portable-connect')) {
          expect(passwords(vault)['anchor-secret'], isNull);
          expect(await readConfirmedTeamGenesis(cfg['user_id'] as String), isNull);
          await handshake(dir!, 'anchor_account');
          if (mode.contains('crash')) secureWriteKillsApp = 'sezam_encrypted_keypair';
          final reconnected = await auth.connectToServer(
            serverUrl: server, username: 'bob', password: cfg['password'] as String,
          );
          if (mode.contains('crash')) {
            expect(reconnected.outcome, isNot(ConnectOutcome.connected));
            await auth.lock();
            await net.settle();
            await DatabaseService().close();
            connected = await auth.unlockOffline(password: cfg['password'] as String);
            expect(connected.success, isTrue, reason: connected.error);
            await sync.authenticate(username: 'bob', signingSecretKey: vault.signingSecretKey!);
          } else {
            expect(reconnected.outcome, ConnectOutcome.connected, reason: reconnected.message);
          }
          await sync.sync();
        }
        if (mode.startsWith('portable-backup')) {
          expect(passwords(vault)['anchor-secret'], isNull);
          expect(await readConfirmedTeamGenesis(cfg['user_id'] as String), isNull);
          final file = File('$dir/account.sezam-key')
            ..writeAsBytesSync(hexToBytes(cfg['backup'] as String));
          if (mode.contains('crash')) {
            secureWriteKillsApp = 'sezam_encrypted_keypair';
            await expectLater(auth.importSezamKey(filePath: file.path, password: cfg['password'] as String),
              throwsA(anything));
            await auth.lock();
            connected = await auth.unlockOffline(password: cfg['password'] as String);
            expect(connected.success, isTrue, reason: connected.error);
            await sync.authenticate(username: 'bob', signingSecretKey: vault.signingSecretKey!);
          } else {
            final imported = await auth.importSezamKey(filePath: file.path, password: cfg['password'] as String);
            CryptoService().zeroize(imported.kek);
            CryptoService().zeroize(imported.keypairBytes);
          }
          await sync.sync();
        }
        if (mode.startsWith('portable-')) {
          expect(await readConfirmedTeamGenesis(cfg['user_id'] as String), cfg['genesis']);
        }
        void readable(bool expected) => expect(
          passwords(vault)['anchor-secret'],
          expected ? 'must-stay-sealed' : isNull,
          reason: mode,
        );
        final cached = mode == 'kek-cached-withdrawn';
        readable(mode.endsWith('honest') || mode == 'portable-storage' || cached);
        if (cached) {
          await handshake(dir!, 'withdraw');
          await sync.pull();
          await vault.reloadData();
          readable(false);
          await handshake(dir, 'regrant');
          await sync.pull();
          await vault.reloadData();
          readable(true);
        }
        final biometricKek = bytesToHex(vault.currentKek!);
        await auth.lock();
        await net.settle();
        if (mode.startsWith('portable-')) {
          await const FlutterSecureStorage().delete(key: 'sezam_confirmed_team_genesis:${cfg['user_id']}');
        }
        await DatabaseService().close();
        final restarted = await auth.unlockOffline(
          password: cfg['password'] as String,
        );
        expect(restarted.success, isTrue, reason: restarted.error);
        readable(mode.endsWith('honest') || mode == 'portable-storage' || cached);
        if (mode.startsWith('portable-')) {
          expect(await readConfirmedTeamGenesis(cfg['user_id'] as String), cfg['genesis']);
          await auth.lock();
          await net.settle();
          await const FlutterSecureStorage().delete(key: 'sezam_confirmed_team_genesis:${cfg['user_id']}');
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
            const MethodChannel('biometric_storage'), (call) async => call.method == 'read' ? biometricKek : true,
          );
          final originalBiometrics = BiometricStorage();
          BiometricStorage.instance = _ReleasedBiometricKek(biometricKek);
          addTearDown(() => BiometricStorage.instance = originalBiometrics);
          final biometric = await auth.unlockWithBiometrics();
          expect(biometric.success, isTrue, reason: biometric.error);
          expect(await readConfirmedTeamGenesis(cfg['user_id'] as String), cfg['genesis']);
          readable(true);
        }
        if (mode.endsWith('unconfirmed')) {
          // Confirmation must recover the same cached ciphertext, not require a new grant.
          await confirmTeamGenesis(
            cfg['user_id'] as String,
            cfg['genesis'] as String,
          );
          await vault.reloadData();
          readable(true);
        }
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
