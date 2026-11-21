// The phone follows the signed team log (TL5, goal #346; docs/DESIGN_TEAM_LOG.md
// §4.3, §6): the log a lying server serves is checked against what this phone
// saw, and in a team folder the log alone decides what is applied, shown and
// sent - write envelopes and accounts the server takes for admins decide
// nothing there. Logs are scenarios of tests/vectors/team_log.json.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/services.dart' show MethodChannel;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/team_log.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';
import 'package:sezam_mobile/services/write_authority.dart';
import 'package:sodium/sodium_sumo.dart';

import 'support/real_server_phone.dart' show hostLibsodium, setUpPhone, initPhoneCrypto;

const a = '01JM0000000000000000000001'; // admin, founded the log
const b = '01JM0000000000000000000002'; // write in F1
const c = '01JM0000000000000000000003'; // read in F1
const d = '01JM0000000000000000000004'; // not in the log
const f1 = '01JF0000000000000000000001';
const k1 = '01JD0000000000000000000001';
const k2 = '01JD0000000000000000000002';
const k9 = '01JD0000000000000000000009';
const own = '01JD000000000000000000000E'; // a key with no folder
const root = '01JR0000000000000000000001';
const other = '01JR0000000000000000000002'; // outside every team folder

/// A sealed node / entry payload whose header names [dekId].
Uint8List sealed(String dekId, [String kind = 'node']) {
  final env = Uint8List(60)
    ..[0] = 1
    ..[1] = 1
    ..[2] = 1
    ..setRange(3, 29, ascii.encode(dekId));
  return kind == 'entry' ? Uint8List.fromList([0, 0, 0, 60, ...env]) : env;
}

Map<String, dynamic> row(
  String id,
  String type,
  String? parent,
  String signer, [
  String? dek,
  Map<String, dynamic> extra = const {},
]) => {
  'id': id,
  'object_type': type,
  'parent_ref': parent,
  'signer_id': signer,
  'owner_id': signer,
  'is_deleted': 0,
  'payload': dek == null ? Uint8List(0) : sealed(dek, type),
  ...extra,
};

Map<String, Map<String, dynamic>> byId(Iterable<Map<String, dynamic>> rows) => {
  for (final r in rows) r['id'] as String: r,
};

/// Root, F1 (a team folder) and OTHER, as the admin wrote them.
List<Map<String, dynamic>> base() => [
  row(root, 'node', null, a, k9),
  row(k9, 'dek', root, a),
  row(f1, 'node', root, a, k1),
  row(k1, 'dek', f1, a),
  row(other, 'node', root, a, k9),
];

void main() {
  final scenarios = {
    for (final s
        in (jsonDecode(
                  File('../tests/vectors/team_log.json').readAsStringSync(),
                )
                as Map<String, dynamic>)['scenarios']
            as List)
      (s as Map<String, dynamic>)['name'] as String: s,
  };
  List<Map<String, dynamic>> records(String name) => [
    for (final r in scenarios[name]!['records'] as List)
      Map<String, dynamic>.from(r as Map),
  ];
  late TeamLog log;

  test('founder trust follows signed rotations, never unrelated re-add keys', () async {
    final dir = await Directory.systemTemp.createTemp('sezam_founder_trust_');
    await setUpPhone(dir.path);
    initPhoneCrypto();
    final crypto = CryptoService();
    final founder = crypto.generateSigningKeypair();
    final admin = crypto.generateSigningKeypair();
    final replacement = crypto.generateSigningKeypair();
    final successor = crypto.generateSigningKeypair();
    final enc = crypto.generateEncryptionKeypair();
    var encHex = TeamLog.toHex(enc.pk);
    final recs = <Map<String, dynamic>>[];
    var state = TeamState();
    void append(String type, String author, Map<String, Object?> data, Uint8List sk) {
      recs.add(TeamLog.signRecord(TeamLog.nextBody(state, type, author, data),
          (message) => crypto.signChallenge(message, sk)));
      state = log.replay(recs);
    }
    bool trusted(Uint8List pk, [String? pin]) => localTeamLogTrusted(
        LocalTeamLog(recs, state), pin, a, TeamLog.toHex(pk), encHex);
    try {
      append('genesis', a, {'org': '01JG0000000000000000000001', 'user_id': a,
        'signing_pk': TeamLog.toHex(founder.pk), 'encryption_pk': encHex}, founder.sk);
      expect(trusted(founder.pk), isTrue);
      expect(trusted(replacement.pk), isFalse);
      expect(trusted(founder.pk, 'ff' * 32), isFalse);
      encHex = TeamLog.toHex(crypto.generateEncryptionKeypair().pk);
      append('member.keys', a, {'user_id': a, 'signing_pk': TeamLog.toHex(successor.pk),
        'encryption_pk': encHex, 'new_key_sig': TeamLog.toHex(crypto.signChallenge(
          TeamLog.newKeyMessage(state.headHash, a, TeamLog.toHex(successor.pk), encHex), successor.sk))}, founder.sk);
      expect(trusted(successor.pk), isTrue);
      append('member.add', a, {'user_id': b, 'role': 'admin',
        'signing_pk': TeamLog.toHex(admin.pk), 'encryption_pk': TeamLog.toHex(crypto.generateEncryptionKeypair().pk)}, successor.sk);
      append('member.remove', b, {'user_id': a}, admin.sk);
      encHex = TeamLog.toHex(crypto.generateEncryptionKeypair().pk);
      append('member.add', b, {'user_id': a, 'role': 'member',
        'signing_pk': TeamLog.toHex(replacement.pk), 'encryption_pk': encHex}, admin.sk);
      expect(trusted(replacement.pk), isFalse, reason: 'server can re-add our keys to its own genesis');
      expect(trusted(replacement.pk, state.genesisHash), isTrue);
      final unlinked = crypto.generateSigningKeypair();
      encHex = TeamLog.toHex(crypto.generateEncryptionKeypair().pk);
      append('member.keys', a, {'user_id': a, 'signing_pk': TeamLog.toHex(unlinked.pk),
        'encryption_pk': encHex, 'new_key_sig': TeamLog.toHex(crypto.signChallenge(
          TeamLog.newKeyMessage(state.headHash, a, TeamLog.toHex(unlinked.pk), encHex), unlinked.sk))}, replacement.sk);
      expect(trusted(unlinked.pk), isFalse, reason: 'rotation cannot repair an unlinked re-add');
      final vault = VaultService();
      final db = DatabaseService();
      await db.setSetting(teamLogRecordsSetting, jsonEncode(recs));
      await vault.unlock(kek: Uint8List(32), signingSecretKey: Uint8List.fromList(admin.sk),
          signingPublicKey: admin.pk, encryptionSecretKey: Uint8List.fromList(enc.sk),
          encryptionPublicKey: enc.pk, userId: b);
      try {
        final review = await vault.reviewTeamFounder();
        await expectLater(vault.confirmTeamFounder(review,
            crypto.computeFingerprint(unlinked.pk, TeamLog.fromHex(encHex))), throwsA(isA<TeamLogMismatch>()));
        expect(await readConfirmedTeamGenesis(b), isNull);
        await vault.confirmTeamFounder(review, crypto.computeFingerprint(founder.pk, enc.pk));
        expect(await readConfirmedTeamGenesis(b), state.genesisHash);
      } finally {
        vault.lock();
        await db.close();
      }
    } finally {
      await dir.delete(recursive: true);
    }
  });

  for (final failure in ['session', 'genesis', 'corrupt', 'rollback', 'foreign-pin', 'lock-before-write', 'lock-after-write', 'refresh']) {
    test('founder confirmation preserves continuity on $failure and allows retry', () async {
      final dir = await Directory.systemTemp.createTemp('sezam_founder_confirm_');
      await setUpPhone(dir.path);
      initPhoneCrypto();
      final vault = VaultService();
      final db = DatabaseService();
      final crypto = CryptoService();
      final signing = crypto.generateSigningKeypair();
      final encryption = crypto.generateEncryptionKeypair();
      final recs = records('basic');
      final body = (jsonDecode(recs.first['body'] as String) as Map)['data'] as Map;
      final fingerprint = crypto.computeFingerprint(TeamLog.fromHex(body['signing_pk'] as String),
          TeamLog.fromHex(body['encryption_pk'] as String));
      Future<void> unlock() => vault.unlock(kek: Uint8List(32),
          signingSecretKey: Uint8List.fromList(signing.sk), signingPublicKey: signing.pk,
          encryptionSecretKey: Uint8List.fromList(encryption.sk), encryptionPublicKey: encryption.pk, userId: b);
      try {
        await db.setSetting(teamLogRecordsSetting, jsonEncode(recs));
        await unlock();
        final review = await vault.reviewTeamFounder();
        final before = await db.getAllObjects();
        final checkpoint = await db.getSyncState('sync_checkpoint:$b');
        if (failure == 'session') { vault.lock(); await unlock(); }
        if (failure == 'corrupt') {
          await db.setSetting(teamLogRecordsSetting, jsonEncode([
            {...recs.first, 'sig': '00' * 64}, ...recs.skip(1)]));
        }
        if (failure == 'rollback') await db.setSetting(teamLogRecordsSetting, jsonEncode([recs.first]));
        if (failure == 'foreign-pin') await confirmTeamGenesis(b, 'ff' * 32);
        if (failure.startsWith('lock-') || failure == 'refresh') {
          final storage = await const FlutterSecureStorage().readAll();
          var reads = 0;
          var fired = false;
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
              const MethodChannel('plugins.it_nomads.com/flutter_secure_storage'), (call) async {
            final args = call.arguments as Map;
            final key = args['key'] as String?;
            if (call.method == 'read') {
              if (key == 'sezam_confirmed_team_genesis:$b' && ++reads == 2 && failure == 'lock-before-write') {
                vault.lock();
              }
              return storage[key];
            }
            if (call.method == 'write') {
              storage[key!] = args['value'] as String;
              if (!fired && key == 'sezam_confirmed_team_genesis:$b') {
                fired = true;
                if (failure == 'lock-after-write') vault.lock();
                if (failure == 'refresh') await db.setSetting(teamLogRecordsSetting, 'broken');
              }
              return null;
            }
            throw StateError('Unexpected secure-storage call: ${call.method}');
          });
        }
        final confirming = vault.confirmTeamFounder(
          failure == 'genesis' ? (userId: b, genesis: 'ff' * 32, generation: review.generation) : review,
          fingerprint);
        if (failure == 'refresh') {
          // INV-7: a copy damaged meanwhile is refused; the vault stays open.
          await confirming;
          expect(vault.isUnlocked, isTrue);
          expect(vault.teamLogRefusal?.cause, 'local_damaged');
        } else {
          await expectLater(confirming, throwsA(anything));
        }
        expect(await readConfirmedTeamGenesis(b), failure == 'foreign-pin' ? 'ff' * 32 :
            (failure == 'lock-after-write' || failure == 'refresh') ? review.genesis : isNull);
        expect(await db.getAllObjects(), before);
        expect(await db.getSyncState('sync_checkpoint:$b'), checkpoint);
        if (failure != 'foreign-pin') {
          await db.setSetting(teamLogRecordsSetting, jsonEncode(recs));
          if (!vault.isUnlocked) await unlock();
          await vault.confirmTeamFounder(await vault.reviewTeamFounder(), fingerprint);
          expect(await readConfirmedTeamGenesis(b), review.genesis);
          expect(vault.teamLogRefusal, isNull);
        }
      } finally {
        vault.lock();
        await db.close();
        await dir.delete(recursive: true);
      }
    });
  }

  test('invitation parser preserves external anchor and rejects ambiguity', () {
    final genesis = 'ab' * 32;
    expect(invitationDetails('code', 'https://sync.invalid'), (token: 'code', genesis: null));
    expect(invitationDetails('code#g=$genesis', 'https://sync.invalid'), (token: 'code', genesis: genesis));
    expect(invitationDetails('https://sync.invalid/?invite=a%26b#g=$genesis', 'https://sync.invalid/'),
        (token: 'a&b', genesis: genesis));
    for (final input in [
      'https://elsewhere.invalid/?invite=code#g=$genesis',
      'http://sync.invalid/?invite=code#g=$genesis',
      'https://sync.invalid/other?invite=code#g=$genesis',
      'https://user@sync.invalid/?invite=code#g=$genesis',
      'https://sync.invalid/?invite=a&invite=b#g=$genesis',
      'https://sync.invalid/?invite=#g=$genesis',
      'code#g=', 'code#g=bad', 'code#g=$genesis&g=$genesis',
      'code#other=$genesis', 'code#g=${genesis.toUpperCase()}',
    ]) {
      expect(() => invitationDetails(input, 'https://sync.invalid'), throwsA(anything), reason: input);
    }
  });

  setUpAll(() async {
    final sodium = await SodiumSumoInit.init2(
      () => DynamicLibrary.open(hostLibsodium()),
    );
    log = TeamLog(
      (sig, msg, pk) => sodium.crypto.sign.verifyDetached(
        message: msg,
        signature: sig,
        publicKey: pk,
      ),
    );
  });

  Map<String, dynamic> headOf(List<Map<String, dynamic>> recs) {
    final s = log.replay(recs);
    return {
      'genesis_hash': s.genesisHash,
      'seq': s.headSeq,
      'hash': s.headHash,
    };
  }

  Future<Object> sync(
    List<Map<String, dynamic>> served, {
    Map<String, dynamic>? head,
    LocalTeamLog? local,
    Map<String, dynamic>? pin,
    String? confirmedGenesis,
    List<int>? asked,
    Future<Map<String, dynamic>?> Function(List<Map<String, dynamic>> records)? restore,
  }) async {
    try {
      return (await syncTeamLog(
            log: log,
            head: head,
            local: local,
            pin: pin,
            confirmedGenesis: confirmedGenesis,
            fetchPage: (since) async {
              asked?.add(since);
              return served.skip(since + 1).take(2).toList();
            },
            restore: restore,
          )) ??
          'none';
    } on TeamLogMismatch catch (e) {
      return '$e';
    }
  }

  test('QR fragments are strict and cannot overwrite account trust', () async {
    final dir = await Directory.systemTemp.createTemp('sezam_qr_anchor_');
    await setUpPhone(dir.path);
    try {
      final genesis = headOf(records('basic'))['genesis_hash'] as String;
      expect(provisioningGenesis(''), isNull);
      expect(provisioningGenesis('g=$genesis'), genesis);
      for (final bad in ['g=', 'g=wrong', 'x=$genesis', 'g=$genesis&g=$genesis', 'g=$genesis&x=1']) {
        expect(() => provisioningGenesis(bad), throwsA(isA<TeamLogMismatch>()));
      }
      expect(await readConfirmedTeamGenesis(b), isNull);
      await confirmTeamGenesis(b, genesis);
      await confirmTeamGenesis(b, genesis);
      expect(await readConfirmedTeamGenesis(b), genesis);
      expect(await readConfirmedTeamGenesis(a), isNull);
      await expectLater(confirmTeamGenesis(b, 'ff' * 32), throwsA(isA<TeamLogMismatch>()));
      expect(await readConfirmedTeamGenesis(b), genesis);
      await const FlutterSecureStorage().write(key: 'sezam_confirmed_team_genesis:$b', value: '{');
      await expectLater(readConfirmedTeamGenesis(b), throwsA(isA<TeamLogMismatch>()));
      await expectLater(confirmTeamGenesis(b, genesis), throwsA(isA<TeamLogMismatch>()));
    } finally {
      await DatabaseService().close();
      await dir.delete(recursive: true);
    }
  });

  test('external genesis rejects missing or foreign head before fetching keys', () async {
    final recs = records('basic');
    final genesis = headOf(recs)['genesis_hash'] as String;
    final asked = <int>[];
    expect(await sync([], confirmedGenesis: genesis, asked: asked), contains('confirmed genesis'));
    expect(await sync(recs, head: headOf(recs), confirmedGenesis: 'ff' * 32, asked: asked), contains('confirmed genesis'));
    expect(asked, isEmpty);
    final good = await sync(recs, head: headOf(recs), confirmedGenesis: genesis) as LocalTeamLog;
    expect(good.team.genesisHash, genesis);
    final seen = records('remove_member_before_rekey');
    expect(await sync(recs, head: headOf(recs), pin: headOf(seen), confirmedGenesis: genesis), contains('went back'));
    final fork = records('downgrade_write_to_read');
    expect(await sync(fork, head: headOf(fork), pin: headOf(seen), confirmedGenesis: genesis), contains('differs at record'));
  });

  group('following the server\'s log', () {
    test('a fresh phone replays the whole log in pages', () async {
      final recs = records('basic');
      final asked = <int>[];
      final got =
          await sync(recs, head: headOf(recs), asked: asked) as LocalTeamLog;
      expect(got.team.headSeq, 5);
      expect(got.records.length, 6);
      expect(asked, [-1, 1, 3]);
      expect(teamLogPin(got.team), headOf(recs));
    });

    test('a log forked at the pinned record is refused', () async {
      final seen = records('remove_member_before_rekey');
      final forked = records('downgrade_write_to_read');
      final message = await sync(
        forked,
        head: headOf(forked),
        pin: headOf(seen),
      );
      expect(message, startsWith('TEAM LOG MISMATCH'));
      expect(message, contains('differs at record 6'));
    });

    test('a head with two admins is refused, a handover is followed', () async {
      // TL7 (review 1141a20): one admin per organisation in every client.
      final two = records('two_admins_at_the_head');
      expect(await sync(two, head: headOf(two)),
          contains('is refused at its head: more than one admin'));
      final handed = records('handover_keeps_the_former_admins_items');
      final got = await sync(handed, head: headOf(handed)) as LocalTeamLog;
      expect(got.team.headSeq, headOf(handed)['seq']);
    });

    test(
      'a shorter log, a missing one or another genesis is refused',
      () async {
        final seen = records('remove_member_before_rekey');
        final pin = headOf(seen);
        final basic = records('basic');
        expect(
          await sync(basic, head: headOf(basic), pin: pin),
          contains('went back (head 5 < 6)'),
        );
        expect(await sync(const [], pin: pin), contains('is gone'));
        expect(
          await sync(
            basic,
            head: {...headOf(basic), 'genesis_hash': 'ff' * 32},
            pin: pin,
          ),
          contains('another genesis'),
        );
      },
    );

    test('R9-E: a restored server gets the lost records back, a fork or refusal never', () async {
      final held = records('basic');
      final local = LocalTeamLog(held, log.replay(held));
      final genesis = headOf(held)['genesis_hash'] as String;
      for (final keep in [0, 3]) {
        var server = held.take(keep).toList();
        final posted = <int>[];
        final got = await sync(
          server,
          head: keep == 0 ? null : headOf(server),
          local: local,
          confirmedGenesis: genesis,
          restore: (part) async {
            posted.add(part.length);
            server = [...server, ...part];
            return headOf(server);
          },
        );
        expect(got, isA<LocalTeamLog>(), reason: 'keep $keep: $got');
        expect((got as LocalTeamLog).team.headSeq, 5);
        expect(posted, [6 - keep]);
        expect(server.map(TeamLog.recordHash), held.map(TeamLog.recordHash));
      }
      // The server's shorter log differs from the one held: never built on.
      final prefix = held.take(3).toList();
      final forked = {...headOf(prefix), 'hash': 'ab' * 32}; // another record at seq 2
      final posted = <int>[];
      Future<Map<String, dynamic>?> count(List<Map<String, dynamic>> part) async {
        posted.add(part.length);
        return null;
      }
      expect(await sync(prefix, head: forked, local: local, restore: count), contains('went back'));
      expect(await sync(prefix, head: {...headOf(prefix), 'genesis_hash': 'ff' * 32}, local: local, restore: count),
          contains('another genesis'));
      expect(posted, isEmpty);
      // A refused upload stays a mismatch.
      expect(
        await sync(held.take(3).toList(), head: headOf(held.take(3).toList()), local: local,
            restore: (part) async => throw Exception('400 refused')),
        contains('went back (head 2 < 5)'),
      );
    });

    test('a head the served records do not reach is refused', () async {
      final longer = records('remove_member_before_rekey');
      final served = records('basic');
      expect(
        await sync(served, head: headOf(longer)),
        contains('does not reach the head it announced'),
      );
    });

    test('a forged record does not replay', () async {
      final recs = records('basic');
      recs[3] = {...recs[3], 'sig': '00' * 64};
      expect(
        await sync(recs, head: headOf(records('basic'))),
        contains('does not replay'),
      );
    });

    test('without a log nothing changes', () async {
      expect(await sync(const []), 'none');
    });
  });

  group('what a pull applies in a team folder', () {
    test('the log decides who writes there, not envelopes or admin rows', () {
      final team = log.replay(records('basic'));
      final held = byId([
        ...base(),
        // The server says Dan is an admin (he signed an envelope) and gave Carol 'write'.
        row('ENV1', 'envelope', k1, d, null, {
          'target_user_id': d,
          'access_level': 'write',
        }),
        row('ENV2', 'envelope', k1, a, null, {
          'target_user_id': c,
          'access_level': 'write',
        }),
      ]);
      final pulled = [
        row('BOB_ITEM', 'entry', f1, b, k1),
        row('CAROL_ITEM', 'entry', f1, c, k1),
        row('DAN_ITEM', 'entry', f1, d, k1),
        row('OUTSIDE', 'entry', other, d, k9),
      ];
      expect(teamLogRefusedPulls(pulled, held, team, a), {
        'CAROL_ITEM',
        'DAN_ITEM',
      });
    });

    test(
      'an old or unknown key is refused, the author\'s own key with write access is not',
      () {
        final team = log.replay(records('remove_member_then_rekey'));
        final held = byId([
          ...base(),
          row(k2, 'dek', f1, a),
          row(own, 'dek', null, c),
        ]);
        final pulled = [
          row('OLD', 'entry', f1, a, k1),
          row('NEW', 'entry', f1, a, k2),
          row('ALIEN', 'entry', f1, a, k9),
          row('CAROL_OWN', 'entry', f1, c, own), // Carol only reads F1
        ];
        expect(teamLogRefusedPulls(pulled, held, team, a), {
          'OLD',
          'ALIEN',
          'CAROL_OWN',
        });
      },
    );

    test('a removal or move out needs write access where the item was', () {
      final team = log.replay(records('basic'));
      final held = byId([
        ...base(),
        row('ITEM', 'entry', f1, b, k1),
        row('ITEM2', 'entry', f1, b, k1),
      ]);
      List<Map<String, dynamic>> by(String who) => [
        row('ITEM', 'entry', f1, who, k1, {'is_deleted': 1}),
        row('ITEM2', 'entry', other, who, k9),
      ];
      expect(teamLogRefusedPulls(by(c), held, team, a), {'ITEM', 'ITEM2'});
      expect(teamLogRefusedPulls(by(d), held, team, a), {'ITEM', 'ITEM2'});
      expect(teamLogRefusedPulls(by(b), held, team, a), isEmpty);
    });
  });

  test('what was stored before is not shown when the log refuses it', () {
    final team = log.replay(records('basic'));
    final rows = [
      ...base(),
      row('ENV1', 'envelope', k1, a, null, {
        'target_user_id': c,
        'access_level': 'write',
      }),
      row('CAROL_ITEM', 'entry', f1, c, k1),
      row('DAN_DIR', 'node', f1, d, k1),
      row('BELOW_DAN', 'entry', 'DAN_DIR', b, k1),
      row('BOB_ITEM', 'entry', f1, b, k1),
    ];
    expect(unauthorizedWrites(rows, a, team: team), {
      'CAROL_ITEM',
      'DAN_DIR',
      'BELOW_DAN',
    });
    expect(
      unauthorizedWrites(rows, a),
      isEmpty,
    ); // before the log: Carol's write envelope
  });

  test('outside team folders the log names the admin, not signatures or access_level', () {
    // Review 1141a20 H5/H6: Dan (not in the log) signed an envelope, which
    // made him an admin by the old rule; the server says Carol may write in
    // OTHER (the admin's unshared folder) and re-signed a root under Dan.
    final team = log.replay(records('basic'));
    final rows = [
      ...base(),
      row('DAN_ENV', 'envelope', k9, d, null, {'target_user_id': c, 'access_level': 'write'}),
      row('DAN_OUT', 'entry', other, d, k9),
      row('CAROL_OUT', 'entry', other, c, k9),
      row('DAN_ROOT', 'node', null, d, k9),
      row('BELOW_DAN_ROOT', 'entry', 'DAN_ROOT', d, k9),
      row('ADMIN_OUT', 'entry', other, a, k9),
      row(own, 'dek', null, c),
      row('CAROL_HOME', 'node', root, c, own), // Carol's own tree stays hers
      row('CAROL_HOME_ITEM', 'entry', 'CAROL_HOME', c, own),
      row('CAROL_HOME_SUB', 'node', 'CAROL_HOME', c, own),
      row('CAROL_DEEP', 'entry', 'CAROL_HOME_SUB', c, own),
      row('SUB', 'node', other, a, k9),
      row('DAN_DEEP', 'entry', 'SUB', d, k9),
    ];
    expect(unauthorizedWrites(rows, b, team: team), {
      'DAN_OUT', 'CAROL_OUT', 'DAN_ROOT', 'BELOW_DAN_ROOT', 'DAN_DEEP',
    });
    expect(unauthorizedWrites(rows, b), isEmpty, reason: 'before the log: the old rules');
    expect(logAdmins(records('basic'), team), {a});
    final handover = log.replay(records('admin_handover'));
    final everAdmin = logAdmins(records('admin_handover'), handover);
    expect(everAdmin, containsAll(handover.members.keys.where((id) => TeamLog.isAdmin(handover, id))));
    expect(everAdmin.length, greaterThan(1), reason: 'the former admin is still an active member');
    final removed = log.replay(records('second_admin_removes_founder'));
    expect(logAdmins(records('second_admin_removes_founder'), removed), isNot(contains(a)));
    // An account the log made admin keeps what it wrote (a handover).
    expect(unauthorizedWrites(rows, b, team: team, teamAdmins: {a, d}), {'CAROL_OUT'});
  });

  test('logged envelopes need the current recipient and exact access', () {
    final team = log.replay(records('basic'));
    final pulled = [
      row('READ', 'envelope', k1, a, null, {'target_user_id': c, 'access_level': 'read'}),
      row('INFLATED', 'envelope', k1, a, null, {'target_user_id': c, 'access_level': 'write'}),
      row('ALIEN', 'envelope', k1, a, null, {'target_user_id': d, 'access_level': 'read'}),
      row('MEMBER_SIGNED', 'envelope', k1, b, null, {'target_user_id': c, 'access_level': 'read'}),
      row('DELETED', 'envelope', k1, a, null, {'target_user_id': c, 'access_level': 'write', 'is_deleted': 1}),
      row('LEGACY', 'envelope', k9, a, null, {'target_user_id': c, 'access_level': 'write'}),
    ];
    expect(teamLogRefusedPulls(pulled, byId(base()), team, a), {
      'INFLATED', 'ALIEN', 'MEMBER_SIGNED',
    });
    expect(teamLogRefusedPulls([pulled.first], byId(base()), team, c,
        ownEncryptionPk: 'ff' * 32), {'READ'});
    expect(teamLogRefusedPulls([pulled.first], byId(base()), team, c,
        ownEncryptionPk: team.members[c]!.encryptionPk), isEmpty);
    final removed = log.replay(records('remove_member_before_rekey'));
    expect(teamLogRefusedPulls([
      row('REMOVED', 'envelope', k1, a, null, {'target_user_id': b, 'access_level': 'write'}),
    ], byId(base()), removed, a), {'REMOVED'});
  });

  test('cached unsigned envelope cannot inflate logged read access', () {
    final objects = [
      ...base(),
      row('INFLATED', 'envelope', k1, a, null, {'target_user_id': c, 'access_level': 'write'}),
    ];
    expect(deriveFolderAccessLevels(objects, c, team: log.replay(records('basic')))[f1], 'read');
    expect(deriveFolderAccessLevels(objects, c)[f1], 'write');
    expect(deriveFolderAccessLevels([
      ...objects,
      row('REVOKED', 'envelope', k1, a, null, {'target_user_id': b, 'access_level': 'write'}),
    ], b, team: log.replay(records('remove_member_before_rekey'))), isEmpty);
  });

  test('cached folder bindings use the log, not unsigned DEK parents', () {
    final bindings = folderDekIdsFrom(
      dekRows: [row(k1, 'dek', other, a), row(k9, 'dek', f1, a)],
      heldDekIds: {k1, k9}, tier2DekIds: {},
      team: log.replay(records('basic')), userId: b,
    );
    expect(bindings[f1], k1);
    expect(bindings, isNot(contains(other)));
    for (final name in ['remove_member_before_rekey', 'remove_member_then_rekey']) {
      expect(folderDekIdsFrom(
        dekRows: [row(k1, 'dek', f1, a), row(k9, 'dek', other, b)],
        heldDekIds: {k1, k9}, tier2DekIds: {},
        team: log.replay(records(name)), userId: b,
      ), {other: k9});
    }
  });

  test('cached keys stop unlocking team data after removal, including restart', () async {
    final dir = await Directory.systemTemp.createTemp('sezam_team_cached_');
    await setUpPhone(dir.path);
    initPhoneCrypto();
    final crypto = CryptoService();
    final db = DatabaseService();
    final vault = VaultService();
    final signing = crypto.generateSigningKeypair();
    final kek = Uint8List.fromList(List.filled(32, 41));
    final dek = Uint8List.fromList(List.filled(32, 42));
    Future<void> unlock() => vault.unlock(
      kek: Uint8List.fromList(kek),
      signingSecretKey: Uint8List.fromList(signing.sk),
      signingPublicKey: Uint8List.fromList(signing.pk),
      userId: b,
    );
    Future<void> saveLog(String name) async {
      final recs = records(name);
      await db.setSetting(teamLogRecordsSetting, jsonEncode(recs));
      vault.teamLog = LocalTeamLog(recs, log.replay(recs));
    }
    try {
      await vault.init();
      await db.upsertObject(
        id: k1, objectType: 'dek', ownerId: b, version: 1, parentRef: f1,
        payload: crypto.wrapDEK(dek, k1, kek, own), queued: false,
      );
      await db.upsertObject(
        id: f1, objectType: 'node', ownerId: a, version: 1, parentRef: root,
        payload: crypto.encryptEnvelope({'name': 'shared'}, dek, k1, f1, 1, BlobKind.nodeMeta),
        queued: false,
      );
      await unlock();
      expect(vault.nodes[f1]?.name, 'shared', reason: 'a legacy vault with no log or pin still opens');
      vault.lock();
      await saveLog('basic');
      await unlock();
      expect(vault.nodes, isNot(contains(f1)), reason: 'observed log is not a trust anchor');
      await confirmTeamGenesis(b, vault.teamLog!.team.genesisHash);
      await vault.reloadData();
      expect(vault.nodes[f1]?.name, 'shared');
      final before = await db.getAllObjects();
      await saveLog('remove_member_before_rekey');
      await vault.reloadData();
      expect(vault.nodes, isNot(contains(f1)), reason: 'removed member must not reuse a cached team key');
      vault.lock();
      await unlock();
      expect(vault.nodes, isNot(contains(f1)), reason: 'restart must load the log before using cached keys');
      expect(await db.getAllObjects(), before, reason: 'ciphertexts are retained, not deleted');
    } finally {
      vault.lock();
      await db.close();
      await dir.delete(recursive: true);
    }
  });

  for (final damage in ['json', 'shape', 'signature', 'empty', 'missing', 'rollback', 'fork', 'checkpoint', 'checkpoint_ciphertext', 'checkpoint_account', 'confirmed_genesis', 'confirmed_account']) {
    for (final restart in [false, true]) {
      test('damaged cached log $damage refuses the team, not the ${restart ? 'unlock' : 'reload'}, before keys', () async {
        final dir = await Directory.systemTemp.createTemp('sezam_team_damage_');
        await setUpPhone(dir.path);
        initPhoneCrypto();
        final crypto = CryptoService();
        final db = DatabaseService();
        final vault = VaultService();
        final signing = crypto.generateSigningKeypair();
        final kek = Uint8List.fromList(List.filled(32, 41));
        final dek = Uint8List.fromList(List.filled(32, 42));
        final recs = records('remove_member_before_rekey');
        final goodLog = jsonEncode(recs);
        Future<void> unlock() => vault.unlock(
          kek: Uint8List.fromList(kek),
          signingSecretKey: Uint8List.fromList(signing.sk),
          signingPublicKey: Uint8List.fromList(signing.pk),
          userId: b,
        );
        try {
          await vault.init();
          await db.upsertObject(
            id: k1, objectType: 'dek', ownerId: b, version: 1, parentRef: f1,
            payload: crypto.wrapDEK(dek, k1, kek, own), queued: false,
          );
          await db.upsertObject(
            id: f1, objectType: 'node', ownerId: a, version: 1, parentRef: root,
            payload: crypto.encryptEnvelope({'name': 'shared'}, dek, k1, f1, 1, BlobKind.nodeMeta),
            queued: false,
          );
          await db.setSetting(teamLogRecordsSetting, goodLog);
          final nonce = Uint8List(crypto.aeadNonceBytes);
          final ciphertext = crypto.aeadEncrypt(
            plaintext: Uint8List.fromList(utf8.encode(jsonEncode({
              'last_sync_seq': 7, 'state_hash': '00' * 32, 'timestamp': 1,
              'team_log': headOf(recs),
            }))),
            additionalData: Uint8List.fromList(utf8.encode('sezam-sync-checkpoint-v1:$b')),
            nonce: nonce, key: kek,
          );
          final checkpoint = 'enc:v1:${base64Encode([...nonce, ...ciphertext])}';
          final sql = await db.database;
          await sql.rawInsert('INSERT INTO sync_state (key, value) VALUES (?, ?)', ['sync_checkpoint:$b', checkpoint]);
          await unlock();
          expect(vault.nodes, isNot(contains(f1)));
          final before = await db.getAllObjects();
          final broken = switch (damage) {
            'json' => '{',
            'shape' => '{"records":[]}',
            'signature' => jsonEncode([
              ...recs.take(recs.length - 1), {...recs.last, 'sig': '00' * 64},
            ]),
            'empty' => '[]',
            'rollback' => jsonEncode(records('basic')),
            'fork' => jsonEncode(records('downgrade_write_to_read')),
            _ => goodLog,
          };
          if (damage == 'missing') {
            await db.deleteSetting(teamLogRecordsSetting);
          } else {
            await db.setSetting(teamLogRecordsSetting, broken);
          }
          var savedCheckpoint = checkpoint;
          if (damage == 'checkpoint') {
            savedCheckpoint = 'enc:v1:broken';
          } else if (damage == 'checkpoint_ciphertext') {
            final tampered = Uint8List.fromList([...nonce, ...ciphertext]);
            tampered[tampered.length - 1] ^= 1;
            savedCheckpoint = 'enc:v1:${base64Encode(tampered)}';
          } else if (damage == 'checkpoint_account') {
            final foreign = crypto.aeadEncrypt(
              plaintext: Uint8List.fromList(utf8.encode(jsonEncode({
                'last_sync_seq': 7, 'state_hash': '00' * 32, 'timestamp': 1,
                'team_log': headOf(recs),
              }))),
              additionalData: Uint8List.fromList(utf8.encode('sezam-sync-checkpoint-v1:$a')),
              nonce: nonce, key: kek,
            );
            savedCheckpoint = 'enc:v1:${base64Encode([...nonce, ...foreign])}';
          }
          await sql.rawUpdate('UPDATE sync_state SET value = ? WHERE key = ?', [savedCheckpoint, 'sync_checkpoint:$b']);
          if (damage.startsWith('confirmed_')) {
            await const FlutterSecureStorage().write(
              key: 'sezam_confirmed_team_genesis:$b',
              value: jsonEncode({'user_id': damage == 'confirmed_account' ? a : b,
                'genesis_hash': damage == 'confirmed_genesis' ? 'ff' * 32 : headOf(recs)['genesis_hash']}),
            );
          }
          if (restart) vault.lock();
          // INV-7: the damaged copy refuses the team, never the unlock; no
          // team key opens from it (no downgrade to the rules before a log).
          await (restart ? unlock() : vault.reloadData());
          expect(vault.isUnlocked, isTrue);
          expect(vault.teamLogRefusal?.cause, 'local_damaged');
          expect(vault.teamLogRefusal!.offersForget, isFalse);
          expect(vault.teamLog, isNull);
          expect(vault.nodes, isNot(contains(f1)));
          expect(await db.getAllObjects(), before, reason: 'refusal retains ciphertext and dirty state');
          expect(await db.getSetting(teamLogRecordsSetting), damage == 'missing' ? null : broken);
          expect(await db.getSyncState('sync_checkpoint:$b'), savedCheckpoint);
          await const FlutterSecureStorage().delete(key: 'sezam_confirmed_team_genesis:$b');
          await db.setSetting(teamLogRecordsSetting, goodLog);
          await sql.rawUpdate('UPDATE sync_state SET value = ? WHERE key = ?', [checkpoint, 'sync_checkpoint:$b']);
          vault.lock();
          await unlock();
          expect(vault.isUnlocked, isTrue);
          expect(vault.teamLogRefusal, isNull);
          expect(vault.nodes, isNot(contains(f1)), reason: 'retry still honors removal');
          await db.setSetting(teamLogRecordsSetting, jsonEncode(records('remove_member_then_rekey')));
          await vault.reloadData();
          expect(vault.teamLog!.team.headSeq, greaterThan(headOf(recs)['seq'] as int));
          expect(vault.nodes, isNot(contains(f1)));
          vault.lock();
          await unlock();
          expect(vault.nodes, isNot(contains(f1)), reason: 'a valid continuation ahead of the checkpoint survives restart');
          expect(await db.getSyncState('sync_checkpoint:$b'), checkpoint);
        } finally {
          vault.lock();
          await db.close();
          await dir.delete(recursive: true);
        }
      });
    }
  }

  group('what the phone writes', () {
    String? attempt(
      String recordsName,
      String who,
      Map<String, dynamic> obj, [
      List<Map<String, dynamic>> extra = const [],
    ]) {
      final team = log.replay(records(recordsName));
      return teamLogWriteRefusal(
        team,
        who,
        obj,
        byId([
          ...base(),
          row(k2, 'dek', f1, a),
          row('ITEM', 'entry', f1, b, k1),
          ...extra,
        ]),
      );
    }

    test('write trust covers both sides of moves, private tier-2 keys and tombstones', () {
      final recs = records('basic');
      final team = log.replay(recs);
      final local = LocalTeamLog(recs, team);
      final held = byId([...base(), row(own, 'dek', null, b),
        row('ITEM', 'entry', f1, b, own)]);
      final writes = [
        row('NEW', 'entry', f1, b, k1),
        row('TIER2', 'entry', f1, b, own),
        row('ITEM', 'entry', other, b, own), // source only
        row('ITEM', 'entry', f1, b, own, {'is_deleted': 1}),
        row('OUT', 'entry', other, b, k1), // logged key, unlogged destination
        row(f1, 'node', other, b, k9), // the logged folder itself
        row(k1, 'dek', null, b),
        row('ENV', 'envelope', k1, b),
      ];
      for (final write in writes) {
        void attempt(String? pin, String who) => requireTrustedTeamWrites(local, pin, who,
            team.members[who]!.signingPk, team.members[who]!.encryptionPk, [write], held);
        expect(() => attempt(null, b), throwsA(isA<TeamLogRefused>()), reason: '${write['id']}');
        expect(() => attempt(team.genesisHash, b), returnsNormally);
        expect(() => attempt(null, a), returnsNormally, reason: 'own signed founder');
        expect(() => attempt('ff' * 32, a), throwsA(isA<TeamLogMismatch>()));
      }
      final personal = [row('PRIVATE', 'entry', other, b, own)];
      expect(() => requireTrustedTeamWrites(local, null, b, null, null, personal, held), returnsNormally);
      expect(() => requireTrustedTeamWrites(null, null, b, null, null, writes, held), returnsNormally);
      expect(() => requireTrustedTeamWrites(null, team.genesisHash, b, null, null, personal, held),
          throwsA(isA<TeamLogMismatch>()));
    });

    test('only with write access and the folder\'s current key', () {
      expect(attempt('basic', b, row('NEW', 'entry', f1, b, k1)), isNull);
      expect(
        attempt('basic', c, row('NEW', 'entry', f1, c, k1)),
        'team log gives no write access here',
      );
      expect(
        attempt('basic', d, row('NEW', 'entry', f1, d, k1)),
        'team log gives no write access here',
      );
      expect(
        attempt('basic', c, row('ITEM', 'entry', f1, c, k1, {'is_deleted': 1})),
        'team log gives no write access here',
      );
      expect(attempt('basic', c, row('OUT', 'entry', other, c, k9)), isNull);
      expect(
        attempt('remove_member_then_rekey', a, row('NEW', 'entry', f1, a, k1)),
        'sealed with an old key generation',
      );
      expect(
        attempt(
          'remove_member_before_rekey',
          a,
          row('NEW', 'entry', f1, a, k1),
        ),
        'folder waits for a re-key',
      );
    });

    test('a tier-2 item under its own new key needs write access', () {
      final bobs = [row(own, 'dek', null, b)];
      expect(attempt('basic', b, row('T2', 'entry', f1, b, own), bobs), isNull);
      final carols = [row(own, 'dek', null, c)];
      expect(
        attempt('basic', c, row('T2', 'entry', f1, c, own), carols),
        'team log gives no write access here',
      );
    });

    test('the folder\'s key is the log\'s current generation', () {
      final team = log.replay(records('remove_member_then_rekey'));
      final nodes = {
        root: const VaultNode(id: root, name: 'root', dekId: k9),
        f1: const VaultNode(id: f1, name: 'F1', parentRef: root, dekId: k2),
        'SUB': const VaultNode(
          id: 'SUB',
          name: 'sub',
          parentRef: f1,
          dekId: k2,
        ),
      };
      String pick(Set<String> held, {String? existing}) => resolveWriteDekId(
        parentRef: 'SUB',
        nodes: nodes,
        heldDekIds: held,
        rootDekId: k9,
        // A newer-looking key the server labels the folder's.
        folderDekIds: const {f1: '01JZZZZZZZZZZZZZZZZZZZZZZZ'},
        existingDekId: existing,
        existingParentRef: 'SUB',
        team: team,
      );
      expect(
        pick({k1, k2, k9, '01JZZZZZZZZZZZZZZZZZZZZZZZ'}, existing: k1),
        k2,
      );
      expect(() => pick({k1, k9}), throwsA(isA<TeamLogRefused>()));
    });
  });
}
