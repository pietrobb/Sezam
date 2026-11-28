// AI broker S1e: the phone pulls the remote AI brake. It only ever publishes
// enabled=false, signs exactly the shared ai_policy message and picks an
// epoch above both the stored one and the current time.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/ai_brake_service.dart';

const userId = '01JACC0000000000000000000F';

void main() {
  test(
    'publishes a signed enabled=false policy above the stored epoch',
    () async {
      final requests = <http.Request>[];
      final signed = <Uint8List>[];
      final client = MockClient((request) async {
        requests.add(request);
        if (request.method == 'GET') {
          return http.Response(
            jsonEncode({
              'policy': {'user_id': userId, 'enabled': false, 'epoch': 5000},
            }),
            200,
          );
        }
        return http.Response(jsonEncode({'policy': {}}), 200);
      });
      final service = AiBrakeService.withClient(
        client,
        sign: (message) {
          signed.add(message);
          return Uint8List.fromList(List<int>.filled(64, 0xab));
        },
        nowMs: () => 4000, // a phone clock behind the stored epoch
      );

      final epoch = await service.pullBrake(
        serverUrl: 'https://sezam.example/',
        token: 'jwt',
        userId: userId,
      );

      expect(epoch, 5001);
      expect(requests.map((r) => '${r.method} ${r.url}'), [
        'GET https://sezam.example/api/ai-policy',
        'PUT https://sezam.example/api/ai-policy',
      ]);
      expect(
        requests.every((r) => r.headers['authorization'] == 'Bearer jwt'),
        isTrue,
      );
      final body = jsonDecode(requests.last.body) as Map<String, dynamic>;
      expect(body, {'enabled': false, 'epoch': 5001, 'signature': 'ab' * 64});
      expect(signed.single, AiBrakeService.policyMessage(userId, false, 5001));
    },
  );

  test(
    'uses the clock when no policy is stored and retries a lost race',
    () async {
      var puts = 0;
      var stored = 0;
      final client = MockClient((request) async {
        if (request.method == 'GET') {
          return http.Response(
            jsonEncode({
              'policy': stored == 0
                  ? null
                  : {'epoch': stored, 'enabled': false},
            }),
            200,
          );
        }
        puts++;
        final epoch = (jsonDecode(request.body) as Map)['epoch'] as int;
        if (puts == 1) {
          stored = epoch + 10; // another device published first
          return http.Response('{"detail":"Stale ai_policy epoch"}', 409);
        }
        return http.Response(jsonEncode({'policy': {}}), 200);
      });
      final service = AiBrakeService.withClient(
        client,
        sign: (_) => Uint8List(64),
        nowMs: () => 1762500000123,
      );

      final epoch = await service.pullBrake(
        serverUrl: 'https://sezam.example',
        token: 'jwt',
        userId: userId,
      );

      expect(puts, 2);
      expect(epoch, 1762500000123 + 11);
    },
  );

  test('a refused brake is an error, never a silent success', () async {
    final client = MockClient((request) async {
      if (request.method == 'GET') {
        return http.Response('{"policy": null}', 200);
      }
      return http.Response('{"detail":"invalid ai_policy signature"}', 400);
    });
    final service = AiBrakeService.withClient(
      client,
      sign: (_) => Uint8List(64),
    );

    expect(
      service.pullBrake(serverUrl: 'https://s', token: 't', userId: userId),
      throwsException,
    );
  });

  test('the message rejects a user id that is not 26 characters', () {
    expect(
      () => AiBrakeService.policyMessage('short', false, 1),
      throwsStateError,
    );
  });
}
