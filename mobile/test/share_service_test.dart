import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/share_service.dart';

void main() {
  test(
    'mobile share matches the canonical server and crypto contract',
    () async {
      Map<String, dynamic>? requestBody;
      Uint8List? encryptedPlaintext;
      Uint8List? encryptedAad;
      Uint8List? encryptedNonce;
      Uint8List? encryptedKey;
      final shareKey = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
      final rawShareId = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final nonce = Uint8List.fromList(List<int>.filled(24, 7));
      var randomCall = 0;
      Uint8List randomBytes(int length) {
        final values = [shareKey, rawShareId, nonce];
        final value = values[randomCall++];
        expect(value, hasLength(length));
        return Uint8List.fromList(value);
      }

      final client = MockClient((request) async {
        expect(request.method, 'POST');
        expect(request.url.toString(), 'https://sezam.example/api/share');
        expect(request.headers['authorization'], 'Bearer jwt-token');
        requestBody = jsonDecode(request.body) as Map<String, dynamic>;
        return http.Response(
          jsonEncode({'status': 'ok', 'id': requestBody!['id']}),
          200,
        );
      });
      final service = ShareService.withClient(
        client,
        randomBytes: randomBytes,
        nonceBytes: 24,
        encrypt:
            ({
              required plaintext,
              required additionalData,
              required nonce,
              required key,
            }) {
              encryptedPlaintext = Uint8List.fromList(plaintext);
              encryptedAad = Uint8List.fromList(additionalData);
              encryptedNonce = Uint8List.fromList(nonce);
              encryptedKey = Uint8List.fromList(key);
              return Uint8List.fromList([9, 8, 7]);
            },
      );
      final entry = <String, dynamic>{
        'name': 'Example',
        'fields': [
          {'key': 'password', 'value': 'secret'},
        ],
      };
      final before = DateTime.now().millisecondsSinceEpoch;

      final result = await service.createShareLink(
        entry: entry,
        serverUrl: 'https://sezam.example/',
        token: 'jwt-token',
        maxViews: 3,
      );
      final after = DateTime.now().millisecondsSinceEpoch;

      expect(requestBody!.keys.toSet(), {
        'id',
        'encrypted_blob',
        'expires_at',
        'max_views',
        'notify_on_view',
      });
      expect(requestBody!['id'], result.shareId);
      expect(requestBody!['max_views'], 3);
      expect(requestBody!['notify_on_view'], isTrue);
      expect(result.expiryMinutes, 1440);
      expect(
        requestBody!['expires_at'],
        inInclusiveRange(before + 86400000, after + 86400000),
      );

      expect(_decodeBase64Url(result.shareId), orderedEquals(rawShareId));

      final uri = Uri.parse(result.shareUrl);
      expect(uri.path, '/s/${result.shareId}');
      expect(uri.fragment, isNot(contains('=')));
      expect(_decodeBase64Url(uri.fragment), orderedEquals(shareKey));

      expect(jsonDecode(utf8.decode(encryptedPlaintext!)), entry);
      expect(encryptedNonce, orderedEquals(nonce));
      expect(encryptedKey, orderedEquals(shareKey));
      expect(encryptedAad, orderedEquals([1, 1, 3, ...rawShareId, 0, 0, 0, 1]));

      final blob = base64Decode(requestBody!['encrypted_blob'] as String);
      expect(blob, orderedEquals([...nonce, 9, 8, 7]));
      final wrongId = Uint8List.fromList(rawShareId)..[0] ^= 1;
      expect(
        ShareService.buildShareAad(wrongId),
        isNot(orderedEquals(encryptedAad!)),
      );
    },
  );

  test('mobile Argon2id PIN policy matches the Python server vector', () async {
    final salt = Uint8List.fromList(List<int>.generate(16, (i) => i));
    const serverVector =
        r'$argon2id$v=19$m=65536,t=3,p=4$AAECAwQFBgcICQoLDA0ODw$djSch6+B5uFp5Q8uPevth/9gdZyR3W/IuTJoPO4yGGg';

    final result = await deriveSharePinHash(
      '2468',
      salt,
      hasher:
          ({
            required pin,
            required salt,
            required iterations,
            required memory,
            required parallelism,
            required length,
          }) async {
            expect(pin, '2468');
            expect(salt, orderedEquals(List<int>.generate(16, (i) => i)));
            expect(iterations, 3);
            expect(memory, 65536);
            expect(parallelism, 4);
            expect(length, 32);
            return serverVector;
          },
    );

    expect(result, serverVector);
  });

  test('mobile sends only a locally derived Argon2id PIN hash', () async {
    Map<String, dynamic>? requestBody;
    String? hashedPin;
    Uint8List? hashedSalt;
    final shareKey = Uint8List.fromList(List<int>.filled(32, 1));
    final rawShareId = Uint8List.fromList(List<int>.filled(32, 2));
    final nonce = Uint8List.fromList(List<int>.filled(24, 3));
    final salt = Uint8List.fromList(List<int>.generate(16, (i) => i));
    final values = [shareKey, rawShareId, nonce, salt];
    var randomCall = 0;
    const pinHash =
        r'$argon2id$v=19$m=65536,t=3,p=4$AAECAwQFBgcICQoLDA0ODw$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    final service = ShareService.withClient(
      MockClient((request) async {
        requestBody = jsonDecode(request.body) as Map<String, dynamic>;
        return http.Response(
          jsonEncode({'status': 'ok', 'id': requestBody!['id']}),
          200,
        );
      }),
      randomBytes: (length) {
        final value = values[randomCall++];
        expect(value, hasLength(length));
        return Uint8List.fromList(value);
      },
      nonceBytes: 24,
      pinHasher: (pin, pinSalt) async {
        hashedPin = pin;
        hashedSalt = Uint8List.fromList(pinSalt);
        return pinHash;
      },
      encrypt:
          ({
            required plaintext,
            required additionalData,
            required nonce,
            required key,
          }) => Uint8List.fromList([9]),
    );

    await service.createShareLink(
      entry: {'name': 'Protected'},
      serverUrl: 'https://sezam.example',
      token: 'jwt-token',
      maxViews: 10,
      pin: '2468',
      notifyOnView: false,
    );

    expect(hashedPin, '2468');
    expect(hashedSalt, orderedEquals(salt));
    expect(requestBody!['max_views'], 10);
    expect(requestBody!['notify_on_view'], isFalse);
    expect(requestBody!['pin_hash'], pinHash);
    expect(requestBody!.containsKey('pin'), isFalse);
    expect(requestBody.toString(), isNot(contains('2468')));
  });

  test(
    'mobile rejects unsupported views and invalid PINs before upload',
    () async {
      var requests = 0;
      final service = ShareService.withClient(
        MockClient((request) async {
          requests++;
          return http.Response('{}', 500);
        }),
      );
      final baseArgs = <String, dynamic>{'name': 'Example'};

      await expectLater(
        service.createShareLink(
          entry: baseArgs,
          serverUrl: 'https://sezam.example',
          token: 'jwt-token',
          maxViews: 5,
        ),
        throwsArgumentError,
      );
      await expectLater(
        service.createShareLink(
          entry: baseArgs,
          serverUrl: 'https://sezam.example',
          token: 'jwt-token',
          pin: '',
        ),
        throwsArgumentError,
      );
      await expectLater(
        service.createShareLink(
          entry: baseArgs,
          serverUrl: 'https://sezam.example',
          token: 'jwt-token',
          pin: List.filled(129, 'x').join(),
        ),
        throwsArgumentError,
      );
      expect(requests, 0);
    },
  );

  test(
    'mobile consumes the canonical encrypted_blob with share-ID AAD',
    () async {
      final rawShareId = Uint8List.fromList(
        List<int>.generate(32, (i) => 31 - i),
      );
      final shareId = base64UrlEncode(rawShareId).replaceAll('=', '');
      final shareKey = Uint8List.fromList(List<int>.filled(32, 4));
      final keyFragment = base64UrlEncode(shareKey).replaceAll('=', '');
      final nonce = Uint8List.fromList(List<int>.filled(24, 5));
      final ciphertext = Uint8List.fromList([6, 7, 8]);
      Uint8List? decryptedAad;

      final client = MockClient((request) async {
        expect(request.method, 'POST');
        expect(
          request.url.toString(),
          'https://sezam.example/api/share/$shareId',
        );
        expect(jsonDecode(request.body), <String, dynamic>{});
        return http.Response(
          jsonEncode({
            'encrypted_blob': base64Encode([...nonce, ...ciphertext]),
            'view_count': 1,
            'max_views': 1,
          }),
          200,
        );
      });
      final service = ShareService.withClient(
        client,
        nonceBytes: 24,
        decrypt:
            ({
              required ciphertext,
              required additionalData,
              required nonce,
              required key,
            }) {
              expect(ciphertext, orderedEquals([6, 7, 8]));
              expect(nonce, orderedEquals(List<int>.filled(24, 5)));
              expect(key, orderedEquals(shareKey));
              decryptedAad = Uint8List.fromList(additionalData);
              return Uint8List.fromList(
                utf8.encode(jsonEncode({'name': 'Example'})),
              );
            },
      );

      final entry = await service.consumeShareLink(
        shareUrl: 'https://sezam.example/s/$shareId#$keyFragment',
      );

      expect(entry, {'name': 'Example'});
      expect(decryptedAad, orderedEquals([1, 1, 3, ...rawShareId, 0, 0, 0, 1]));
    },
  );
}

Uint8List _decodeBase64Url(String value) {
  final padded = value.padRight((value.length + 3) ~/ 4 * 4, '=');
  return Uint8List.fromList(base64Url.decode(padded));
}
