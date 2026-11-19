// Capability run 269: pre-anchor password states, driven by
// tests/test_pre_anchor_cross_client.py (same vectors as Python and JS).
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sodium/sodium_sumo.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'support/real_server_phone.dart' show hostLibsodium;

void main() {
  final crypto = CryptoService();
  final dir = Platform.environment['SEZAM_X3_DIR'];
  final cfg = dir == null
      ? null
      : jsonDecode(File('$dir/config.json').readAsStringSync()) as Map<String, dynamic>;

  setUpAll(() async {
    final sodium = await SodiumSumoInit.init2(
      () => DynamicLibrary.open(hostLibsodium()),
    );
    // Argon2id outputs computed by Python; an unexpected input fails loudly.
    final material = (cfg?['material'] as Map?)?.cast<String, String>() ?? {};
    crypto.initForTesting(
      sodium,
      argon2: (password, salt, timeCost, memoryCost, parallelism) async {
        final known = material['$password|${bytesToHex(salt)}'];
        if (known == null) throw StateError('no Argon2 vector for this input');
        return hexToBytes(known);
      },
    );
  });

  test('pre-anchor states match Python and JS', () async {
    if (cfg == null) return; // standalone run: no vectors
    final states = hexToBytes(cfg['states'] as String);
    for (final c in cfg['checks'] as List) {
      expect(
        await crypto.passwordReopensPreAnchor(c['password'] as String, states),
        c['reopens'],
        reason: c['password'] as String,
      );
    }
    for (final bad in cfg['bad'] as List) {
      expect(() => crypto.parsePreAnchor(hexToBytes(bad as String)), throwsFormatException);
    }
    expect(
      () => crypto.decodeAccountKeypair(hexToBytes(cfg['bad_bundle'] as String)),
      throwsFormatException,
    );
    final kek = hexToBytes(cfg['kek'] as String);
    final user = cfg['user'] as String;
    final opened = crypto.openAccountKeypair(hexToBytes(cfg['envelope'] as String), kek, user);
    expect(bytesToHex(opened.keypairData), cfg['raw']);
    expect(opened.confirmedGenesis, cfg['genesis']);
    expect(bytesToHex(opened.preAnchor!), cfg['states']);
    final params = cfg['params'] as Map;
    final first = crypto.addPreAnchor(
      null,
      hexToBytes(cfg['s0'] as String),
      params['time_cost'] as int,
      params['memory_cost'] as int,
      params['parallelism'] as int,
      hexToBytes(cfg['kek0'] as String),
    )!;
    final envelope = crypto.wrapAccountKeypair(
      hexToBytes(cfg['full'] as String),
      cfg['genesis'] as String,
      kek,
      cfg['kid'] as String,
      user,
      states,
    );
    File('$dir/emitted.json').writeAsStringSync(jsonEncode({
      'first': bytesToHex(first),
      'merged': bytesToHex(crypto.mergePreAnchor(states, first)!),
      'envelope': bytesToHex(envelope),
    }));
  });
}
