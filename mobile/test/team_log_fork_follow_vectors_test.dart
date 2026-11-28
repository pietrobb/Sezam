// U7d (docs/CORE_UNIFICATION.md): tests/vectors/team_log_fork_follow.json,
// from the desktop's follow_fork before the move, as the phone's _followFork
// runs it: split, replay what is served (libsodium), take.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/team_log.dart';
import 'package:sodium/sodium_sumo.dart';

import 'support/real_server_phone.dart' show hostLibsodium;

void main() {
  final vectors =
      jsonDecode(
            File(
              '../tests/vectors/team_log_fork_follow.json',
            ).readAsStringSync(),
          )
          as Map<String, dynamic>;
  List<Map<String, dynamic>> recordsOf(Object? list) => [
    for (final r in list as List) Map<String, dynamic>.from(r as Map),
  ];
  late TeamLog log;

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

  Object? follow(Map c) {
    final local = recordsOf(c['local']);
    final served = recordsOf(c['served']);
    final held = (c['held_keys'] as List?)?.cast<String>();
    final split = TeamLog.forkSplit(
      local,
      served,
      [for (final p in c['pins'] as List) Map<String, Object?>.from(p as Map)],
      c['user_id'] as String?,
      held,
      {for (final h in c['withdrawn'] as List) h as String},
    );
    if (split['fork'] == null) return split;
    final fork = split['fork'] as int;
    final TeamState team;
    try {
      team = log.replay(served);
    } catch (_) {
      return {'stand': true};
    }
    final take = TeamLog.forkTake(
      team,
      Map<String, dynamic>.from(c['head'] as Map),
      local.sublist(fork),
      split['missing'] as List,
      c['user_id'] as String?,
      held,
      c['old_signing_pk'] as String?,
    );
    final plan = take['follow'];
    if (plan == null) return take;
    return {
      'follow': {'fork': fork, ...plan as Map},
    };
  }

  test('the phone gives each case', () {
    final cases = vectors['cases'] as List;
    expect(cases.length, greaterThanOrEqualTo(20));
    for (final c in cases) {
      final m = c as Map;
      expect(follow(m), m['expect'], reason: m['name']);
    }
  });

  test('which refusals look for a fork', () {
    expect(TeamLog.forkFollows('went_back'), isTrue);
    expect(TeamLog.forkFollows('differs'), isTrue);
    expect(TeamLog.forkFollows('does_not_replay'), isTrue);
    expect(TeamLog.forkFollows('short_of_head'), isFalse);
    expect(TeamLog.forkFollows(null), isFalse);
  });

  test('the phone keeps no rules of its own', () {
    final text = File(
      'lib/services/team_log_client.dart',
    ).readAsStringSync().replaceAll('\r\n', '\n');
    final start = text.indexOf('Future<LocalTeamLog?> _followFork(');
    final body = text.substring(start, text.indexOf('\n}\n', start));
    for (final copy in [
      'remadeKinds',
      'forkRefusal',
      'adminPolicyRefusal',
      'recordHash',
      'forkAbandoned',
    ]) {
      expect(body.contains(copy), isFalse, reason: copy);
    }
    expect(text.contains("'went_back', 'differs'"), isFalse);
  });
}
