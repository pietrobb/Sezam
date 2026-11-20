// INV-7 (docs/ROOT_CAUSE_PLAN.md, review 8bc70f7 H4/M2): the phone refuses the
// server's team log and offers "Zabudnúť pripnutý tímový denník" exactly as
// tests/vectors/team_log_mismatch.json says (tests/test_inv7_forget_offer.py
// runs the same cases on the desktop and the page): only where the team's log
// is lost for good, never for a server that lies.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/team_log.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sodium/sodium_sumo.dart';

import 'support/real_server_phone.dart' show hostLibsodium;

void main() {
  final vectors = jsonDecode(File('../tests/vectors/team_log_mismatch.json').readAsStringSync())
      as Map<String, dynamic>;
  final cases = [for (final c in vectors['cases'] as List) c as Map<String, dynamic>];
  late TeamLog log;

  setUpAll(() async {
    final sodium = await SodiumSumoInit.init2(() => DynamicLibrary.open(hostLibsodium()));
    log = TeamLog((sig, msg, pk) => sodium.crypto.sign.verifyDetached(message: msg, signature: sig, publicKey: pk));
  });

  List<Map<String, dynamic>> recordsOf(Object? list) =>
      [for (final r in (list as List? ?? const [])) Map<String, dynamic>.from(r as Map)];

  Future<Map<String, Object?>> follow(Map<String, dynamic> c) async {
    final device = c['device'] as Map<String, dynamic>;
    final server = c['server'] as Map<String, dynamic>;
    final served = recordsOf(server['records']);
    final held = device['records'] == null ? null : recordsOf(device['records']);
    final local = held == null ? null : LocalTeamLog(held, log.replay(held));
    final args = <Symbol, Object?>{
      #log: log,
      #head: server['head'] == null ? null : Map<String, dynamic>.from(server['head'] as Map),
      #local: local,
      #pin: local == null ? null : teamLogPin(local.team),
      #confirmedGenesis: device['confirmed_genesis'] as String?,
      #fetchPage: (int since) async =>
          served.where((r) => (jsonDecode(r['body'] as String) as Map)['seq'] as int > since).toList(),
      // A restore that lands is INV-2.
      #restore: (List<Map<String, dynamic>> _) async => throw Exception('refused'),
    };
    // Only a phone that left a log says so (a phone before review 8bc70f7 M2
    // had no way to: the case shows what it did instead).
    if ((device['forgotten_genesis'] as List).isNotEmpty) args[#leftEarlierLog] = true;
    try {
      Future<LocalTeamLog?> run() => Function.apply(syncTeamLog, const [], args) as Future<LocalTeamLog?>;
      LocalTeamLog? got;
      try {
        got = await run();
      } on NoSuchMethodError {
        if (args.remove(#leftEarlierLog) == null) rethrow;
        got = await run(); // the phone before M2: told nothing, it does what it did
      }
      return {'follows': got?.team.headSeq};
    } on TeamLogMismatch catch (e) {
      Object? cause;
      try {
        cause = (e as dynamic).cause;
      } on NoSuchMethodError {
        cause = null; // a phone before the one list names none
      }
      return {'refused': true, 'forget': '$e'.contains('Zabudnúť pripnutý tímový denník'), 'cause': cause};
    }
  }

  test('forgetting is offered exactly where the team log is lost for good', () async {
    final got = <String, Object?>{};
    final want = <String, Object?>{};
    for (final c in cases) {
      final name = c['name'] as String;
      final answer = await follow(c);
      got[name] = {...answer}..remove('cause');
      final expect = c['expect'] as Map<String, dynamic>;
      want[name] = expect.containsKey('follows')
          ? {'follows': expect['follows']}
          : {'refused': true, 'forget': expect['forget']};
    }
    expect(got, want);
  });

  // The list itself (teamLogMismatchForget): tests/test_inv7_forget_offer.py.
  test('the phone names the cause the oracle names', () async {
    for (final c in cases) {
      final refused = (c['expect'] as Map)['refused'];
      if (refused == null) continue;
      expect((await follow(c))['cause'], refused, reason: c['name'] as String);
    }
  });
}
