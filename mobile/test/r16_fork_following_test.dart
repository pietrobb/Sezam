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

  test("the phone makes no change again: a fork missing its own lost change waits", () async {
    final got = await follow('own_fork_partly_again');
    expect(got, contains('differs at record 4'));
    expect(got, isNot(contains('not followed')));
  });
}
