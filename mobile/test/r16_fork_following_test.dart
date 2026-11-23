// Review 18c300f R16-H1: a server keeps every record a device signed, also
// one it refused or one the device withdrew. On 18c300f a fork of this
// account's own records was followed whatever it held (a hand-over the admin
// had seen refused made Bob the admin; a dropped rotation named keys nobody
// holds), and a member's phone never followed a fork, also not once the
// admin's device had made the lost changes again: 'does not replay' for good.
//
// tests/vectors/team_log_fork.json says by hand what every client's
// forkRefusal answers; the phone gives the same answers, and its follower
// (syncTeamLog) takes them.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto_pkg;
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/team_log.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sodium/sodium_sumo.dart';

import 'support/real_server_phone.dart' show hostLibsodium;

void main() {
  final vectors = jsonDecode(File('../tests/vectors/team_log_fork.json').readAsStringSync())
      as Map<String, dynamic>;
  List<Map<String, dynamic>> recordsOf(Object? list) =>
      [for (final r in list as List) Map<String, dynamic>.from(r as Map)];
  final prefix = recordsOf(vectors['prefix']);
  final cases = {
    for (final c in vectors['cases'] as List) (c as Map)['name'] as String: c as Map<String, dynamic>,
  };
  late TeamLog log;

  setUpAll(() async {
    final sodium = await SodiumSumoInit.init2(() => DynamicLibrary.open(hostLibsodium()));
    log = TeamLog((sig, msg, pk) =>
        sodium.crypto.sign.verifyDetached(message: msg, signature: sig, publicKey: pk));
  });

  test('the phone core gives every answer', () {
    final got = <String, List<Object?>>{};
    final want = <String, List<Object?>>{};
    for (final c in cases.values) {
      final held = c['held_keys'] as List?;
      final (refusal, missing) = TeamLog.forkRefusal(
        recordsOf(c['lost']),
        recordsOf(c['theirs']),
        c['user_id'] as String?,
        held?.cast<String>(),
        {for (final h in c['withdrawn'] as List) h as String},
      );
      got[c['name'] as String] = [refusal, missing];
      final expect_ = c['expect'] as Map;
      want[c['name'] as String] = [expect_['refusal'], expect_['missing']];
    }
    expect(got, want);
  });

  Future<Object> follow(String name) async {
    final c = cases[name]!;
    final held = [...prefix, ...recordsOf(c['lost'])];
    final served = [...prefix, ...recordsOf(c['theirs'])];
    final state = log.replay(served);
    try {
      return (await syncTeamLog(
        log: log,
        head: {'genesis_hash': state.genesisHash, 'seq': state.headSeq, 'hash': state.headHash},
        local: LocalTeamLog(held, log.replay(held)),
        pin: null,
        ownUserId: c['user_id'] as String?,
        ownKeys: (c['held_keys'] as List?)?.cast<String>(),
        fetchPage: (since) async => served.skip(since + 1).take(2).toList(),
      ))!;
    } on TeamLogMismatch catch (e) {
      return '$e';
    }
  }

  test("the admin's phone never follows a hand-over or a rotation it did not lose", () async {
    expect(await follow('handover_the_server_kept'),
        contains('not followed: its record 3 changes a role this device did not lose'));
    expect(await follow('rotation_to_keys_nobody_holds'),
        contains('not followed: its record 3 names keys this device does not hold'));
    expect((await follow('handover_that_was_lost') as LocalTeamLog).team.headSeq, 5);
  });

  test("a member's phone follows once every change it saw is on the server's side", () async {
    expect(await follow('member_before_the_admin_made_it_again'),
        contains("record 3 this device saw is not on the server's side"));
    final followed = await follow('member_after_the_admin_made_it_again') as LocalTeamLog;
    expect(followed.records,
        [...prefix, ...recordsOf(cases['member_after_the_admin_made_it_again']!['theirs'])]);
  });

  // Review 18c300f R16-M5: on 18c300f a phone waited for its own lost changes
  // for good ('differs' at every pull, the team part refused).
  test('the phone core makes every lost change again', () {
    final got = <String, Object?>{};
    final want = <String, Object?>{};
    for (final c in cases.values) {
      final expect_ = c['expect'] as Map;
      if (!expect_.containsKey('remade')) continue;
      want[c['name'] as String] = expect_['remade'];
      final served = log.replay([...prefix, ...recordsOf(c['theirs'])]);
      final missing = (expect_['missing'] as List).cast<int>();
      try {
        got[c['name'] as String] = [
          for (final r in recordsOf(c['lost']))
            for (final body in [TeamLog.parseBody(r['body'], -1)])
              if (missing.contains(body['seq']))
                for (final data in [
                  TeamLog.resolveChange(served, body['type'] as String, Map<String, dynamic>.from(body['data'] as Map))
                ])
                  if (data != null) [body['type'], data],
        ];
      } on TeamLogError catch (e) {
        got[c['name'] as String] = e.code;
      }
    }
    expect(jsonDecode(jsonEncode(got)), want);
  });

  Future<(Object, List<Map<String, dynamic>>, List<List<Object?>>)> remake(String name,
      {bool refuse = false}) async {
    final c = cases[name]!;
    final sodium = await SodiumSumoInit.init2(() => DynamicLibrary.open(hostLibsodium()));
    final seed = crypto_pkg.sha256.convert(utf8.encode('sezam-team-log-vector:alice')).bytes;
    final alice = sodium.crypto.sign.seedKeyPair(SecureKey.fromList(sodium, Uint8List.fromList(seed)));
    final held = [...prefix, ...recordsOf(c['lost'])];
    final served = [...prefix, ...recordsOf(c['theirs'])];
    final state = log.replay(served);
    final posted = <Map<String, dynamic>>[];
    final setAside = <List<Object?>>[];
    final Object got;
    try {
      got = (await syncTeamLog(
        log: log,
        head: {'genesis_hash': state.genesisHash, 'seq': state.headSeq, 'hash': state.headHash},
        local: LocalTeamLog(held, log.replay(held)),
        pin: null,
        ownUserId: c['user_id'] as String?,
        ownKeys: (c['held_keys'] as List?)?.cast<String>(),
        fetchPage: (since) async => served.skip(since + 1).take(2).toList(),
        remake: TeamLogRemake(
          sign: (body) => TeamLog.signRecord(
              body, (m) => sodium.crypto.sign.detached(message: m, secretKey: alice.secretKey)),
          append: (records) async {
            posted.addAll(records);
            return refuse ? RemakeOutcome.refused : RemakeOutcome.taken;
          },
          setAside: (changes, reason) async {
            for (final change in changes) {
              setAside.add([change['type'], reason]);
            }
          },
        ),
      ))!;
    } on TeamLogMismatch catch (e) {
      return ('$e' as Object, posted, setAside);
    }
    return (got, posted, setAside);
  }

  test('the phone makes the changes it lost again on the server head', () async {
    final c = cases['own_fork_recovery_made_here']!;
    final (got, posted, setAside) = await remake('own_fork_recovery_made_here');
    final served = prefix.length + recordsOf(c['theirs']).length;
    expect((got as LocalTeamLog).team.headSeq, served + 1);
    expect(got.records.skip(served).toList(), posted);
    expect(jsonDecode(jsonEncode([
      for (final r in posted)
        for (final b in [TeamLog.parseBody(r['body'], -1)]) [b['type'], b['data'], b['author']],
    ])), [for (final r in (c['expect'] as Map)['remade'] as List) [...r as List, c['user_id']]]);
    expect(setAside, isEmpty);
  });

  test('the phone sets aside what the log or the server no longer takes', () async {
    final (moved, movedPosted, movedAside) = await remake('own_fork_folder_keyed_elsewhere');
    expect((moved as LocalTeamLog).records.length, prefix.length + 1);
    expect(movedPosted, isEmpty);
    expect(movedAside.single[0], 'folder.key');
    expect(movedAside.single[1], contains('folder_key_moved'));
    final (refused, offered, refusedAside) = await remake('own_fork_shorter', refuse: true);
    expect((refused as LocalTeamLog).records.length, prefix.length + 1);
    expect(refusedAside, [
      ['folder.key', 'the server refused them'],
      ['access.set', 'the server refused them'],
    ]);
    // R16-H1 for what the phone now sends: a server that kept what it
    // refused serves it on top of the log, and the phone does not take it.
    final kept = [...refused.records, ...offered];
    final keptState = log.replay(kept);
    final Object served;
    try {
      served = (await syncTeamLog(
        log: log,
        head: {'genesis_hash': keptState.genesisHash, 'seq': keptState.headSeq, 'hash': keptState.headHash},
        local: refused,
        pin: null,
        ownUserId: cases['own_fork_shorter']!['user_id'] as String,
        fetchPage: (since) async => kept.skip(since + 1).take(2).toList(),
        withdrawn: {for (final r in offered) TeamLog.recordHash(r)},
      ))!;
      fail('followed $served');
    } on TeamLogMismatch catch (e) {
      expect('$e', contains('which this phone withdrew'));
    }
  });
}
