// R9-B portable account bundle; Python also drives the 3-client exchange here.
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
  setUpAll(() async {
    final sodium = await SodiumSumoInit.init2(
      () => DynamicLibrary.open(hostLibsodium()),
    );
    crypto.initForTesting(
      sodium,
      argon2: (_, _, _, _, _) async => throw UnimplementedError(),
    );
  });

  test(
    'portable bundle authenticates keys and anchor without device state',
    () {
      final dir = Platform.environment['SEZAM_X3_DIR'];
      final shared = jsonDecode(
        File('../tests/vectors/cross_client.json').readAsStringSync(),
      )['keypair_wrap'];
      final full = hexToBytes(shared['keypair_hex'] as String);
      final raw = hexToBytes(shared['envelopes'][0]['payload_hex'] as String);
      final genesis = List.filled(32, 'ab').join();
      final payload = Uint8List.fromList([
        ...ascii.encode('SZACCT01'),
        ...raw,
        ...hexToBytes(genesis),
      ]);
      final kek = hexToBytes(shared['kek_hex'] as String);
      final kid = shared['kek_id'] as String;
      final user = shared['user_id'] as String;
      for (final keys in [raw, full]) {
        expect(crypto.encodeAccountKeypair(keys, genesis), payload);
      }
      for (final value in [
        '',
        List.filled(32, 'AB').join(),
        'ab',
        List.filled(64, 'g').join(),
      ]) {
        expect(
          () => crypto.encodeAccountKeypair(raw, value),
          throwsFormatException,
        );
      }
      for (final bad in [
        Uint8List(0),
        Uint8List(32),
        payload.sublist(0, 103),
        Uint8List.fromList([...payload, 0]),
        Uint8List.fromList([
          ...ascii.encode('SZACCT02'),
          ...payload.sublist(8),
        ]),
        Uint8List.fromList([
          ...full.sublist(0, 32),
          ...Uint8List(32),
          ...full.sublist(64),
        ]),
      ]) {
        expect(() => crypto.decodeAccountKeypair(bad), throwsFormatException);
      }
      for (final legacy in [raw, full]) {
        final opened = crypto.decodeAccountKeypair(legacy);
        expect(opened.keypairData, raw);
        expect(opened.confirmedGenesis, isNull);
      }
      final blob = crypto.wrapAccountKeypair(full, genesis, kek, kid, user);
      final decoded = crypto.openAccountKeypair(blob, kek, user);
      expect(decoded.keypairData, raw);
      expect(decoded.confirmedGenesis, genesis);
      final newKek = Uint8List(32);
      final rewrapped = crypto.wrapAccountKeypair(
        decoded.keypairData,
        decoded.confirmedGenesis!,
        newKek,
        kid,
        user,
      );
      expect(
        crypto.openAccountKeypair(rewrapped, newKek, user).confirmedGenesis,
        genesis,
      );
      expect(
        () => crypto.openAccountKeypair(blob, newKek, user),
        throwsA(anything),
      );
      expect(
        () =>
            crypto.openAccountKeypair(blob, kek, '01JACC0000000000000000000G'),
        throwsA(anything),
      );
      for (final offset in [0, 1, 2, blob.length - 1]) {
        final changed = Uint8List.fromList(blob)..[offset] ^= 1;
        expect(
          () => crypto.openAccountKeypair(changed, kek, user),
          throwsA(anything),
        );
      }
      if (dir == null) return;
      final cfg = jsonDecode(File('$dir/config.json').readAsStringSync());
      for (final c in cfg['cases']) {
        final plain = hexToBytes(c['payload'] as String);
        if (c['ok'] == false) {
          expect(
            () => crypto.decodeAccountKeypair(plain),
            throwsFormatException,
            reason: c['name'],
          );
        } else {
          final result = crypto.decodeAccountKeypair(plain);
          expect(bytesToHex(result.keypairData), cfg['raw'], reason: c['name']);
          expect(result.confirmedGenesis, c['genesis'], reason: c['name']);
        }
      }
      for (final c in cfg['envelopes']) {
        final envelope = hexToBytes(c['envelope'] as String);
        final uid = c['user'] as String? ?? user;
        if (c['ok'] == false) {
          expect(
            () => crypto.openAccountKeypair(envelope, kek, uid),
            throwsA(anything),
            reason: c['name'],
          );
        } else {
          final result = crypto.openAccountKeypair(envelope, kek, uid);
          expect(bytesToHex(result.keypairData), cfg['raw'], reason: c['name']);
          expect(result.confirmedGenesis, c['genesis'], reason: c['name']);
        }
      }
      File('$dir/emitted.json').writeAsStringSync(jsonEncode(bytesToHex(blob)));
    },
  );
}
