// Idea #8: the phone answers a login challenge by signing
// 'sezam-auth-challenge-signature-v1' || challenge, and only a 40-byte
// challenge, so a malicious server cannot have the identity key sign bytes
// of its choosing (a sync object, an AI policy) as a "login".

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';

import 'support/real_server_phone.dart';

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  late Directory appDir;
  late List<Map<String, dynamic>> verifyBodies;
  late String challengeHex;
  late SyncService sync;
  late CryptoService crypto;
  var rotatedElsewhere = false;

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_auth_ctx_');
    await setUpPhone(appDir.path);
    verifyBodies = [];
    final client = MockClient((request) async {
      if (request.url.path == '/api/auth/challenge') {
        return http.Response(jsonEncode({'challenge': challengeHex}), 200);
      }
      verifyBodies.add(jsonDecode(request.body) as Map<String, dynamic>);
      if (rotatedElsewhere) {
        return http.Response(
          jsonEncode({'detail': 'Identity key rotated'}),
          409,
        );
      }
      return http.Response(jsonEncode({'token': 'jwt'}), 200);
    });
    http.runWithClient(() {
      sync = SyncService()..configure('https://sezam.test');
      crypto = CryptoService();
      initPhoneCrypto();
    }, () => client);
  });

  tearDownAll(() => appDir.delete(recursive: true));

  final context = utf8.encode('sezam-auth-challenge-signature-v1');

  test('signs context || challenge, never the bare challenge', () async {
    final keys = crypto.generateSigningKeypair();
    final challenge = Uint8List.fromList(List.generate(40, (i) => i * 3));
    challengeHex = _hex(challenge);
    await sync.authenticate(username: 'alice', signingSecretKey: keys.sk);

    final signature = Uint8List.fromList(
      List.generate(
        64,
        (i) => int.parse(
          (verifyBodies.single['signature'] as String).substring(
            i * 2,
            i * 2 + 2,
          ),
          radix: 16,
        ),
      ),
    );
    expect(
      crypto.verifyDetached(
        signature: signature,
        message: Uint8List.fromList([...context, ...challenge]),
        publicKey: keys.pk,
      ),
      isTrue,
    );
    expect(
      crypto.verifyDetached(
        signature: signature,
        message: challenge,
        publicKey: keys.pk,
      ),
      isFalse,
    );
  });

  test(
    'refuses to sign a server-chosen message that is no challenge',
    () async {
      final keys = crypto.generateSigningKeypair();
      for (final forged in [
        utf8.encode('sezam-ai-policy-v1') + List.filled(30, 1),
        List.filled(39, 0),
        List.filled(41, 0),
      ]) {
        verifyBodies.clear();
        challengeHex = _hex(forged);
        await expectLater(
          sync.authenticate(username: 'alice', signingSecretKey: keys.sk),
          throwsA(isA<ArgumentError>()),
        );
        expect(verifyBodies, isEmpty);
      }
    },
  );

  // Idea #11: a phone still holding the keypair another device rotated away
  // is told so (and adopts the new one with the password via the
  // KeyEpochStaleException prompt) instead of failing with a bare error.
  test(
    'a rotated identity asks for the takeover, not a failed login',
    () async {
      final keys = crypto.generateSigningKeypair();
      challengeHex = _hex(List.generate(40, (i) => i));
      rotatedElsewhere = true;
      try {
        await expectLater(
          sync.authenticate(username: 'alice', signingSecretKey: keys.sk),
          throwsA(isA<KeyEpochStaleException>()),
        );
      } finally {
        rotatedElsewhere = false;
      }
    },
  );
}
