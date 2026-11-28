// tests/vectors/account_bundle.json on the phone (docs/CORE_UNIFICATION.md
// U6e): pre-anchor password states and the SZACCT account bundle are the
// core's; the KEK's check and a legacy bundle's public key are the phone's.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sodium/sodium_sumo.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'support/real_server_phone.dart' show hostLibsodium;

void main() {
  final crypto = CryptoService();
  final vectors =
      jsonDecode(
            File('../tests/vectors/account_bundle.json').readAsStringSync(),
          )
          as Map<String, dynamic>;
  List<Map<String, dynamic>> cases(String name) =>
      (vectors[name] as List).cast<Map<String, dynamic>>();
  Uint8List? bytes(Object? hex) =>
      hex == null || hex == '' ? null : hexToBytes(hex as String);
  String? hex(Uint8List? b) => b == null || b.isEmpty ? null : bytesToHex(b);

  /// {'ok': ...} or {'error': true}, as the vectors put it.
  Map<String, Object?> outcome(Object? Function() f) {
    try {
      return {'ok': f()};
    } on FormatException {
      return {'error': true};
    }
  }

  Map<String, Object?> want(Map<String, dynamic> c) =>
      c.containsKey('error') ? {'error': true} : {'ok': c['ok']};

  setUpAll(() async {
    final sodium = await SodiumSumoInit.init2(
      () => DynamicLibrary.open(hostLibsodium()),
    );
    crypto.initForTesting(
      sodium,
      argon2: (_, _, _, _, _) async => throw StateError('no Argon2 here'),
    );
  });

  test('pre-anchor states parse, merge and add as the vectors say', () {
    for (final c in cases('pre_anchor_parse')) {
      final out = outcome(
        () => [
          for (final e in crypto.parsePreAnchor(bytes(c['blob'])))
            {
              'salt': bytesToHex(e.salt),
              'time_cost': e.timeCost,
              'memory_cost': e.memoryCost,
              'parallelism': e.parallelism,
              'check': bytesToHex(e.check),
            },
        ],
      );
      expect(out, want(c), reason: c['blob'] as String);
    }
    for (final c in cases('pre_anchor_merge')) {
      final out = outcome(
        () => hex(crypto.mergePreAnchor(bytes(c['kept']), bytes(c['other']))),
      );
      expect(out, want(c), reason: '${c['kept']} + ${c['other']}');
    }
    for (final c in cases('pre_anchor_add')) {
      final out = outcome(
        () => hex(
          crypto.addPreAnchor(
            bytes(c['blob']),
            hexToBytes(c['salt'] as String),
            c['time_cost'] as int,
            c['memory_cost'] as int,
            c['parallelism'] as int,
            hexToBytes(c['kek'] as String),
          ),
        ),
      );
      expect(out, want(c), reason: c['salt'] as String);
    }
    final check = vectors['pre_anchor_check'] as Map<String, dynamic>;
    expect(
      bytesToHex(crypto.preAnchorCheck(hexToBytes(check['kek'] as String))),
      check['check'],
    );
  });

  test('account bundles decode and encode as the vectors say', () {
    for (final c in cases('bundle_decode')) {
      final out = outcome(() {
        final d = crypto.decodeAccountKeypair(
          hexToBytes(c['payload'] as String),
        );
        return {
          'keys': bytesToHex(d.keypairData),
          'confirmed_genesis': d.confirmedGenesis,
          'pre_anchor': hex(d.preAnchor),
        };
      });
      expect(out, want(c), reason: c['payload'] as String);
    }
    for (final c in cases('bundle_encode')) {
      final out = outcome(
        () => bytesToHex(
          crypto.encodeAccountKeypair(
            hexToBytes(c['keys'] as String),
            c['confirmed_genesis'] as String,
            bytes(c['pre_anchor']),
          ),
        ),
      );
      expect(out, want(c), reason: c['confirmed_genesis'] as String);
    }
  });
}
