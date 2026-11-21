// INV-7 (docs/ROOT_CAUSE_PLAN.md, capability run 397): a team log this phone
// refuses never keeps the vault locked. It refuses the team; the personal tree
// opens and takes writes, no team key opens, and each cause names its way out.
// Before: account keys naming another log read "Wrong password" offline, and a
// damaged cached copy stopped every unlock in VaultService._loadTeamLog.
// The phone side of tests/test_inv7_unlock_never_blocked.py.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/team_log.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'support/real_server_phone.dart' show setUpPhone, initPhoneCrypto;

const b = '01JM0000000000000000000002'; // write in F1 of the 'basic' log
const a = '01JM0000000000000000000001'; // its admin
const f1 = '01JF0000000000000000000001';
const k1 = '01JD0000000000000000000001';
final otherGenesis = 'ab' * 32;

/// How this phone comes to refuse its log, and the cause it names.
const states = {
  'damaged_json': 'local_damaged',
  'damaged_signature': 'local_damaged',
  // Capability run 418: account keys naming this log's genesis, whose first
  // record is damaged, read anchor_conflict (the damaged record's own hash).
  'damaged_genesis_anchored': 'local_damaged',
  'anchor_conflict': 'anchor_conflict',
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

  Future<void> breakIt(String state, DatabaseService db, String userId, String genesis) async {
    switch (state) {
      case 'damaged_genesis_anchored':
        await recordAccountTeamGenesis(userId, genesis);
        await db.setSetting(teamLogRecordsSetting, jsonEncode([{...recs.first, 'sig': '00' * 64}, ...recs.skip(1)]));
      case 'damaged_json':
        await db.setSetting(teamLogRecordsSetting, '{');
      case 'damaged_signature':
        await db.setSetting(teamLogRecordsSetting,
            jsonEncode([...recs.take(recs.length - 1), {...recs.last, 'sig': '00' * 64}]));
      case 'anchor_conflict':
        await recordAccountTeamGenesis(userId, otherGenesis);
    }
  }

  void expectRefused(VaultService vault, String state) {
    final refusal = vault.teamLogRefusal;
    expect(refusal?.cause, states[state]);
    expect(vault.teamLog, isNull);
    // INV-8: forgetting is offered, marked as a risk, only for conflicting pins.
    expect(refusal!.offersForget, state == 'anchor_conflict');
    expect('$refusal'.contains('RISK:'), state == 'anchor_conflict');
    expect('$refusal', state == 'anchor_conflict' ? contains('Zabudnúť pripnutý tímový denník') : contains('next sync'));
  }

  for (final state in states.keys) {
    test('$state: the vault opens, personal writes go through, the team is refused', () async {
      final dir = await Directory.systemTemp.createTemp('sezam_inv7_');
      await setUpPhone(dir.path);
      initPhoneCrypto();
      final crypto = CryptoService();
      final db = DatabaseService();
      final vault = VaultService();
      final signing = crypto.generateSigningKeypair();
      final encryption = crypto.generateEncryptionKeypair();
      final kek = Uint8List.fromList(List.filled(32, 41));
      final teamKey = Uint8List.fromList(List.filled(32, 42));
      Future<void> unlock() => vault.unlock(
            kek: Uint8List.fromList(kek),
            signingSecretKey: Uint8List.fromList(signing.sk),
            signingPublicKey: signing.pk,
            encryptionSecretKey: Uint8List.fromList(encryption.sk),
            encryptionPublicKey: encryption.pk,
            userId: b,
          );
      try {
        await vault.init();
        await unlock();
        // The organisation's root (under a key of no folder, as a web-made
        // root) and team folder F1 under the key the log names for it.
        const orgRoot = '01JR0000000000000000000009';
        const rootKeyId = '01JD000000000000000000000R';
        final rootKey = Uint8List.fromList(List.filled(32, 43));
        const kekId = '01JD000000000000000000000E';
        await db.upsertObject(
          id: rootKeyId, objectType: 'dek', ownerId: b, version: 1, queued: false,
          payload: crypto.wrapDEK(rootKey, rootKeyId, kek, kekId),
        );
        await db.upsertObject(
          id: orgRoot, objectType: 'node', ownerId: b, version: 1, queued: false,
          payload: crypto.encryptEnvelope({'name': 'Org'}, rootKey, rootKeyId, orgRoot, 1, BlobKind.nodeMeta),
        );
        await db.upsertObject(
          id: k1, objectType: 'dek', ownerId: b, version: 1, parentRef: f1, queued: false,
          payload: crypto.wrapDEK(teamKey, k1, kek, kekId),
        );
        await db.upsertObject(
          id: f1, objectType: 'node', ownerId: a, version: 1, parentRef: orgRoot, queued: false,
          payload: crypto.encryptEnvelope({'name': 'shared'}, teamKey, k1, f1, 1, BlobKind.nodeMeta),
        );
        await vault.reloadData();
        final orgEntry = await vault.createEntry(parentRef: orgRoot, name: 'org', fields: const []);
        final personal = await vault.createPersonalFolder(name: 'mine');
        final sub = await vault.createNode(name: 'sub', parentRef: personal.id);
        final kept = await vault.createEntry(parentRef: personal.id, name: 'kept', fields: const []);
        final gone = await vault.createEntry(parentRef: sub.id, name: 'gone', fields: const []);
        final emptySub = await vault.createNode(name: 'empty', parentRef: personal.id);
        // Then the trusted log arrives.
        final genesis = TeamLog(vault.verifyEd25519).replay(recs).genesisHash;
        await db.setSetting(teamLogRecordsSetting, jsonEncode(recs));
        await confirmTeamGenesis(b, genesis);
        await vault.reloadData();
        expect(vault.teamLogRefusal, isNull);
        expect(vault.nodes[f1]?.name, 'shared', reason: 'the trusted log lets F1 open');
        expect(vault.entries[orgEntry.id]?.name, 'org');

        await breakIt(state, db, b, genesis);
        final copy = await db.getSetting(teamLogRecordsSetting);
        vault.lock();
        await unlock(); // before: TEAM LOG MISMATCH, the vault locked again
        expect(vault.isUnlocked, isTrue);
        expectRefused(vault, state);
        expect(vault.nodes, isNot(contains(f1)), reason: 'no team key opens from a refused log');
        expect(vault.nodes[personal.id]?.name, 'mine');
        expect(vault.entries[kept.id]?.name, 'kept');

        // Each personal operation, in the personal tree.
        final ops = <String, Future<Object?> Function()>{
          'create personal folder': () => vault.createPersonalFolder(name: 'mine-2'),
          'create folder': () => vault.createNode(name: 'sub-2', parentRef: personal.id),
          'create entry': () => vault.createEntry(parentRef: personal.id, name: 'new', fields: const []),
          'create entry in a subfolder': () => vault.createEntry(parentRef: sub.id, name: 'deep', fields: const []),
          'update entry': () => vault.updateEntry(entryId: kept.id, name: 'kept-2'),
          'delete entry': () => vault.deleteEntry(gone.id),
          'delete folder': () => vault.deleteNode(emptySub.id),
        };
        for (final op in ops.entries) {
          await expectLater(op.value(), completes, reason: op.key);
        }
        expect(vault.entries[kept.id]?.name, 'kept-2');

        // Team operations are refused with the cause, never queued.
        final dirty = (await db.getDirtyObjects()).length;
        final team = <String, Future<Object?> Function()>{
          'create entry in the org root': () => vault.createEntry(parentRef: orgRoot, name: 'x', fields: const []),
          'create folder in the org root': () => vault.createNode(name: 'x', parentRef: orgRoot),
          'update an org entry': () => vault.updateEntry(entryId: orgEntry.id, name: 'x'),
          'delete an org entry': () => vault.deleteEntry(orgEntry.id),
        };
        for (final op in team.entries) {
          await expectLater(op.value(),
              throwsA(isA<TeamLogMismatch>().having((e) => e.cause, 'cause', states[state])), reason: op.key);
        }
        expect((await db.getDirtyObjects()).length, dirty);

        // Nothing fetched or forgotten meanwhile: still refused, across a restart.
        expect(await db.getSetting(teamLogRecordsSetting), copy);
        vault.lock();
        await unlock();
        expectRefused(vault, state);
        expect(await readConfirmedTeamGenesis(b), genesis, reason: 'no pin dropped or replaced');

        // The way out: a damaged copy fetched again (here restored) ends the
        // refusal; conflicting pins end once forgotten (review13_phone_forget_pin).
        if (state != 'anchor_conflict') {
          await db.setSetting(teamLogRecordsSetting, jsonEncode(recs));
          await vault.reloadData();
          expect(vault.teamLogRefusal, isNull);
          expect(vault.nodes[f1]?.name, 'shared');
        } else {
          await forgetConfirmedTeamGenesis(b, [genesis, otherGenesis]);
          await db.deleteSetting(teamLogRecordsSetting);
          await vault.reloadData();
          expect(vault.teamLogRefusal, isNull);
          expect(await readAccountTeamGenesis(b), isNull, reason: 'a left anchor names nothing');
        }
      } finally {
        vault.lock();
        await db.close();
        await dir.delete(recursive: true);
      }
    });
  }

  for (final pinned in [true, false]) {
    test('offline unlock with account keys naming another log${pinned ? ' (pinned here)' : ''} '
        'is no "Wrong password"', () async {
      final dir = await Directory.systemTemp.createTemp('sezam_inv7_auth_');
      await setUpPhone(dir.path);
      initPhoneCrypto();
      final crypto = CryptoService();
      final db = DatabaseService();
      final vault = VaultService();
      final auth = AuthService();
      const password = 'inv7 correct horse battery';
      try {
        await vault.init();
        await vault.createVault(password);
        const storage = FlutterSecureStorage();
        final uid = (await storage.read(key: 'sezam_user_object_id'))!;
        final kekDekId = (await db.getSetting('kek_dek_id'))!;
        final kek = Uint8List.fromList(vault.currentKek!);
        final keys = Uint8List.fromList([...vault.signingSecretKey!, ...vault.encryptionSecretKey!]);
        final personal = await vault.createPersonalFolder(name: 'mine');
        // A connected account whose keys name OTHER_GENESIS; this phone holds 'basic'.
        await storage.write(key: 'sezam_encrypted_keypair',
            value: bytesToHex(crypto.wrapAccountKeypair(keys, otherGenesis, kek, kekDekId, uid)));
        SharedPreferences.setMockInitialValues({'sezam_server_url': 'http://127.0.0.1:9'});
        final genesis = TeamLog(vault.verifyEd25519).replay(recs).genesisHash;
        await db.setSetting(teamLogRecordsSetting, jsonEncode(recs));
        if (pinned) await confirmTeamGenesis(uid, genesis);
        vault.lock();

        final result = await auth.unlockOffline(password: password);
        expect(result.success, isTrue, reason: result.error);
        expect(vault.userId, uid);
        expect(vault.teamLogRefusal?.cause, 'anchor_conflict');
        expect(vault.teamLogRefusal!.offersForget, isTrue);
        expect(await readAccountTeamGenesis(uid), otherGenesis);
        expect(await readConfirmedTeamGenesis(uid), pinned ? genesis : otherGenesis,
            reason: 'a pin held here is never replaced by the account keys');
        await expectLater(
            vault.createEntry(parentRef: personal.id, name: 'offline', fields: const []), completes);
        vault.lock();
        expect((await auth.unlockOffline(password: 'a wrong password here')).error, 'Wrong password',
            reason: 'a wrong password still reads so');
      } finally {
        vault.lock();
        await db.close();
        await dir.delete(recursive: true);
      }
    });
  }
}
