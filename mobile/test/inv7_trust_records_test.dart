// INV-7 (capability run 411): every piece of team-log trust this phone keeps
// in secure storage (its confirmed pin, the genesis hashes it left, the
// account anchor it noted), damaged in every way, still lets the correct
// password open the vault, offline and by biometrics. The team is refused with
// a named cause and a way out that runs on the unlocked vault and clears it.
// Before: an unreadable list of left genesis hashes read "Wrong password"
// (recordAccountTeamGenesis threw inside the keypair open), and an unreadable
// pin had no way out (the founder confirmation read it first and threw).
// The online unlock (unlockWithPassword) is in inv7_phone_way_out_test.dart.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:biometric_storage/biometric_storage.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/team_log.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'support/real_server_phone.dart' show setUpPhone, initPhoneCrypto;

class _ReleasedBiometricKek extends MethodChannelBiometricStorage {
  _ReleasedBiometricKek(this.kek);
  final String kek;
  @override
  Future<String?> read(String name, PromptInfo promptInfo) async => kek;
}

/// The secure-storage key of each trust record.
String recordKey(String record, String uid) => switch (record) {
      'confirmed_pin' => 'sezam_confirmed_team_genesis:$uid',
      'forgotten_list' => 'sezam_forgotten_team_genesis:$uid',
      _ => 'sezam_account_team_anchor:$uid',
    };

/// A damaged value of a record: broken JSON, another account's, a bad genesis.
String damagedValue(String damage, String uid, String genesis) => switch (damage) {
      'broken_json' => '{',
      'other_user' => jsonEncode({'user_id': '01JZZZZZZZZZZZZZZZZZZZZZZZ', 'genesis_hash': genesis, 'genesis': [genesis]}),
      _ => jsonEncode({'user_id': uid, 'genesis_hash': 'zz', 'genesis': ['zz']}),
    };

List<Map<String, dynamic>> basicRecords() {
  final scenarios = {
    for (final s in jsonDecode(File('../tests/vectors/team_log.json').readAsStringSync())['scenarios'] as List)
      (s as Map)['name'] as String: s,
  };
  return [for (final r in scenarios['basic']!['records'] as List) Map<String, dynamic>.from(r as Map)];
}

void main() {
  final recs = basicRecords();
  const password = 'inv7 trust records battery';

  for (final path in ['offline', 'biometric']) {
    for (final record in ['confirmed_pin', 'forgotten_list', 'account_anchor']) {
      for (final damage in ['broken_json', 'other_user', 'bad_genesis']) {
        test('$path unlock with a damaged $record ($damage) opens and names its way out', () async {
          final dir = await Directory.systemTemp.createTemp('sezam_inv7_trust_');
          await setUpPhone(dir.path);
          initPhoneCrypto();
          final crypto = CryptoService();
          final db = DatabaseService();
          final vault = VaultService();
          final auth = AuthService();
          try {
            await vault.init();
            await vault.createVault(password);
            const storage = FlutterSecureStorage();
            final uid = (await storage.read(key: 'sezam_user_object_id'))!;
            final kek = Uint8List.fromList(vault.currentKek!);
            final genesis = TeamLog(vault.verifyEd25519).replay(recs).genesisHash;
            // A connected account whose keys name the log this phone holds and pins.
            await storage.write(key: 'sezam_encrypted_keypair', value: bytesToHex(crypto.wrapAccountKeypair(
                Uint8List.fromList([...vault.signingSecretKey!, ...vault.encryptionSecretKey!]),
                genesis, kek, (await db.getSetting('kek_dek_id'))!, uid)));
            SharedPreferences.setMockInitialValues({'sezam_server_url': 'http://127.0.0.1:9'});
            await db.setSetting(teamLogRecordsSetting, jsonEncode(recs));
            await confirmTeamGenesis(uid, genesis);
            final personal = await vault.createPersonalFolder(name: 'mine');
            if (path == 'biometric') {
              TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
                const MethodChannel('biometric_storage'), (call) async => call.method == 'read' ? bytesToHex(kek) : true,
              );
              final original = BiometricStorage();
              BiometricStorage.instance = _ReleasedBiometricKek(bytesToHex(kek));
              addTearDown(() => BiometricStorage.instance = original);
            }
            Future<AuthResult> unlock() async {
              vault.lock();
              return path == 'offline' ? auth.unlockOffline(password: password) : auth.unlockWithBiometrics();
            }

            final clean = await unlock();
            expect(clean.success, isTrue, reason: clean.error);
            expect(vault.teamLogRefusal, isNull);

            await storage.write(key: recordKey(record, uid), value: damagedValue(damage, uid, genesis));
            final opened = await unlock(); // before: "Wrong password" for a damaged forgotten list
            expect(opened.success, isTrue, reason: opened.error);
            expect(vault.isUnlocked, isTrue);
            expect(vault.userId, uid);
            await expectLater(vault.createEntry(parentRef: personal.id, name: 'kept', fields: const []), completes);
            if (record == 'account_anchor') {
              // Noted again from the keys just opened: nothing left to refuse.
              expect(vault.teamLogRefusal, isNull);
              expect(await readAccountTeamGenesis(uid), genesis);
              return;
            }
            final refusal = vault.teamLogRefusal;
            expect(refusal?.cause, 'local_damaged');
            expect(refusal!.offersForget, isFalse, reason: 'nothing to forget: the trust record is unreadable');
            expect('$refusal', contains("confirming the team's founder again"));
            expect(vault.teamLog, isNull);
            // Still refused across a restart: nothing replaced on its own.
            expect((await unlock()).success, isTrue);
            expect(vault.teamLogRefusal?.cause, 'local_damaged');
            expect(await storage.read(key: recordKey(record, uid)), damagedValue(damage, uid, genesis));

            // The way out: the founder confirmed again replaces what cannot be read.
            final founder = (jsonDecode(recs.first['body'] as String) as Map)['data'] as Map;
            await vault.confirmTeamFounder(await vault.reviewTeamFounder(), crypto.computeFingerprint(
                TeamLog.fromHex(founder['signing_pk'] as String), TeamLog.fromHex(founder['encryption_pk'] as String)));
            expect(vault.teamLogRefusal, isNull);
            expect(vault.teamLog?.team.genesisHash, genesis);
            expect(await readConfirmedTeamGenesis(uid), genesis);
            expect(await readForgottenTeamGenesis(uid), isEmpty);
            expect((await unlock()).success, isTrue);
            expect(vault.teamLogRefusal, isNull);
          } finally {
            vault.lock();
            await db.close();
            await dir.delete(recursive: true);
          }
        });
      }
    }
  }

  test('forgetting a pin overwrites an unreadable list of left genesis hashes', () async {
    final dir = await Directory.systemTemp.createTemp('sezam_inv7_trust_forget_');
    await setUpPhone(dir.path);
    const uid = '01JM0000000000000000000002';
    final left = 'cd' * 32;
    try {
      await const FlutterSecureStorage().write(key: recordKey('forgotten_list', uid), value: '{');
      await forgetConfirmedTeamGenesis(uid, [left]);
      expect(await readForgottenTeamGenesis(uid), [left]);
      expect(await readConfirmedTeamGenesis(uid), isNull);
    } finally {
      await dir.delete(recursive: true);
    }
  });
}
