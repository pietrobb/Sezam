// Team log (lib/services/team_log.dart) against the shared decision vectors
// tests/vectors/team_log.json (TL2, goal #346): every scenario must give the
// Python reference's state, answers and error (code and record). Ed25519 runs
// on the host's libsodium, as in the real-server phone tests.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/team_log.dart';
import 'package:sodium/sodium_sumo.dart';

import 'support/real_server_phone.dart' show hostLibsodium;

Object? ask(TeamState s, String fn, List<dynamic> a) {
  switch (fn) {
    case 'may_write':
      return TeamLog.mayWrite(s, a[0] as String, a[1] as String);
    case 'key_recipients':
      return TeamLog.keyRecipients(s, a[0] as String);
    case 'current_key':
      return TeamLog.currentKey(s, a[0] as String);
    case 'key_generation':
      return TeamLog.keyGeneration(s, a[0] as String, a[1] as String);
    case 'is_team_folder':
      return TeamLog.isTeamFolder(s, a[0] as String);
    case 'is_stale':
      return TeamLog.isStale(s, a[0] as String);
    case 'may_seal':
      return TeamLog.maySeal(s, a[0] as String);
    case 'is_admin':
      return TeamLog.isAdmin(s, a[0] as String);
    case 'may_hold_key':
      return TeamLog.mayHoldKey(s, a[0] as String, a[1] as String);
    case 'envelope_valid':
      return TeamLog.envelopeValid(s, a[0] as String, a[1] as String,
          a[2] as String, a[3] as String?, a[4] as String);
    case 'item_refusal':
      return TeamLog.itemRefusal(s, a[0] as String, a[1] as String,
          a[2] as String?, a[3] as String?, a[4] as bool, a[5] as bool);
    case 'tombstone_refusal':
      return TeamLog.tombstoneRefusal(s, a[0] as String, a[1] as String?);
    case 'move_refusal':
      return TeamLog.moveRefusal(s, a[0] as String, a[1] as String?, a[2] as String?,
          a.length > 3 && a[3] as bool);
    case 'admin_policy_refusal':
      return TeamLog.adminPolicyRefusal(s);
  }
  throw StateError('unknown question $fn');
}

void main() {
  // SEZAM_TEAM_LOG_VECTORS: tests/test_team_log_differential.py's random logs.
  final path = Platform.environment['SEZAM_TEAM_LOG_VECTORS'] ??
      '../tests/vectors/team_log.json';
  final vectors =
      jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;
  late SodiumSumo sodium;
  late TeamLog log;

  setUpAll(() async {
    sodium = await SodiumSumoInit.init2(() => DynamicLibrary.open(hostLibsodium()));
    log = TeamLog((sig, msg, pk) => sodium.crypto.sign.verifyDetached(
        message: msg, signature: sig, publicKey: pk));
  });

  for (final s in (vectors['scenarios'] as List).cast<Map<String, dynamic>>()) {
    test(s['name'], () {
      final records = s['records'] as List;
      if (s.containsKey('error')) {
        final error = s['error'] as Map<String, dynamic>;
        try {
          log.replay(records);
          fail('replay accepted a log the reference refuses');
        } on TeamLogError catch (e) {
          expect({'seq': e.seq, 'code': e.code}, error);
        }
        return;
      }
      final state = log.replay(records);
      expect(state.toJson(), s['state']);
      for (final q in (s['questions'] as List).cast<Map<String, dynamic>>()) {
        expect(ask(state, q['fn'] as String, q['args'] as List), q['answer'],
            reason: '${q['fn']} ${q['args']}');
      }
    });
  }

  test('a record the phone signs replays like the reference', () {
    final seed = Uint8List.fromList(
        List.generate(32, (i) => i)); // any key; the reference check is below
    final kp = sodium.crypto.sign.seedKeyPair(SecureKey.fromList(sodium, seed));
    final pk = TeamLog.toHex(kp.publicKey);
    const uid = '01JM00000000000000000000F1';
    final body = TeamLog.nextBody(TeamState(), 'genesis', uid, {
      'org': '01JG000000000000000000000Z', 'user_id': uid,
      'signing_pk': pk, 'encryption_pk': 'ab' * 32,
    });
    final record = TeamLog.signRecord(body, (m) => sodium.crypto.sign
        .detached(message: m, secretKey: kp.secretKey));
    final state = log.replay([record]);
    expect(TeamLog.isAdmin(state, uid), isTrue);
    expect(state.genesisHash, state.headHash);
  });
}
