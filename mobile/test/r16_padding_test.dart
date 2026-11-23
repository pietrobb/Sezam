// Review 18c300f R16-L3: a padded blob tells only its size class. Padding
// stopped at 0xFFFF bytes (the u16 prefix), so a blob above 128 KiB told its
// exact length, and share links were sealed unpadded. tests/vectors/
// padding.json is the rule all three clients share (tests/test_r16_padding.py
// checks Python and the page).

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/share_service.dart';
import 'package:sodium/sodium_sumo.dart';

import 'support/real_server_phone.dart' show hostLibsodium, nodeArgon2id;

void main() {
  final vectors =
      jsonDecode(File('../tests/vectors/padding.json').readAsStringSync())
          as Map<String, dynamic>;
  final cases = (vectors['padded_size'] as List).cast<List>();
  final crypto = CryptoService();

  setUpAll(() async {
    final sodium = await SodiumSumoInit.init2(
      () => DynamicLibrary.open(hostLibsodium()),
    );
    crypto.initForTesting(sodium, argon2: nodeArgon2id);
  });

  test('the padded size is the shared one', () {
    for (final c in cases) {
      expect(paddedSize(c[0] as int), c[1], reason: 'n=${c[0]}');
    }
  });

  test('a large blob tells only its size class', () {
    for (final size in [70000, 131070, 150000, 300000, 1048575]) {
      final data = Uint8List(size)..fillRange(0, size, 7);
      final padded = crypto.padPlaintext(data);
      expect(padded.length % 0x10000, 0, reason: 'size=$size');
      expect(crypto.unpadPlaintext(padded), data);
    }
  });

  for (final secretLen in [10, 5000, 150000]) {
    test('a share link of a $secretLen-byte secret tells only its size class', () async {
      Uint8List? sealed;
      final service = ShareService.withClient(
        MockClient(
          (request) async => http.Response(
            jsonEncode({'status': 'ok', 'id': jsonDecode(request.body)['id']}),
            200,
          ),
        ),
        encrypt:
            ({
              required plaintext,
              required additionalData,
              required nonce,
              required key,
            }) {
              sealed = Uint8List.fromList(plaintext);
              return Uint8List.fromList([9, 8, 7]);
            },
      );
      final entry = <String, dynamic>{
        'name': 'bank',
        'fields': [
          {'key': 'password', 'value': 'x' * secretLen},
        ],
      };
      await service.createShareLink(
        entry: entry,
        serverUrl: 'https://sezam.example',
        token: 'jwt',
        maxViews: 1,
      );
      final size = sealed!.length;
      expect(
        size & (size - 1) == 0 || size % 0x10000 == 0,
        isTrue,
        reason: 'size=$size',
      );
      // What the share page and the phone read: JSON.parse / jsonDecode.
      expect(jsonDecode(utf8.decode(sealed!)), entry);
    });
  }
}
