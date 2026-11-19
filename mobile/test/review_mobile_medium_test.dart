// Regressions for code review HEAD 2c7e809, medium mobile items M1-M5.
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/clipboard_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/timeout_client.dart';

void main() {
  group('M1 clipboard clear on Android 10+', () {
    test(
      'an unreadable clipboard (app without focus) is still cleared',
      () async {
        var clipboard = '';
        var clears = 0;
        final service = ClipboardService(
          readText: () async => null, // Android 10+ in the background
          writeText: (text) async => clipboard = text,
          clear: () async {
            clears++;
            clipboard = '';
          },
        );
        await service.copySensitive('secret', timeout: Duration.zero);
        await Future<void>.delayed(const Duration(milliseconds: 10));
        expect(clears, 1);
        expect(clipboard, isEmpty);
      },
    );

    test('a readable newer value is never cleared', () async {
      var clipboard = '';
      var clears = 0;
      final service = ClipboardService(
        readText: () async => clipboard,
        writeText: (text) async => clipboard = text,
        clear: () async => clears++,
      );
      await service.copySensitive('secret', timeout: Duration.zero);
      clipboard = 'copied in another app';
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(clears, 0);
      expect(clipboard, 'copied in another app');
    });

    test('a clear that came due in a frozen process runs on resume', () async {
      var now = DateTime(2026, 1, 1, 12);
      var clipboard = '';
      final service = ClipboardService(
        readText: () async => clipboard,
        writeText: (text) async => clipboard = text,
        now: () => now,
      );
      await service.copySensitive('secret', timeout: const Duration(hours: 1));

      await service.clearIfOverdue(); // resumed early: nothing to do yet
      expect(clipboard, 'secret');

      now = now.add(const Duration(hours: 2)); // timer never fired
      await service.clearIfOverdue();
      expect(clipboard, isEmpty);
    });

    test('Android marks the clip sensitive and clears without reading', () {
      final activity = File(
        'android/app/src/main/kotlin/sk/sezam/sezam_mobile/MainActivity.kt',
      ).readAsStringSync().replaceAll('\r\n', '\n');
      expect(activity, contains('"sk.sezam/clipboard"'));
      expect(activity, contains('ClipDescription.EXTRA_IS_SENSITIVE'));
      expect(activity, contains('clearPrimaryClip()'));
      final app = File(
        'lib/main.dart',
      ).readAsStringSync().replaceAll('\r\n', '\n');
      expect(app, contains('ClipboardService.shared.clearIfOverdue()'));
    });
  });

  test('M2 every libsodium SecureKey is disposed after use', () {
    final source = File(
      'lib/services/crypto_service.dart',
    ).readAsStringSync().replaceAll('\r\n', '\n');
    final helperStart = source.indexOf('T _withKey<T>(');
    expect(helperStart, greaterThan(0));
    final helperEnd = source.indexOf('\n  }\n', helperStart);
    final helper = source.substring(helperStart, helperEnd);
    expect(helper, contains('finally'));
    expect(helper, contains('secure.dispose()'));
    final outside = source.replaceRange(helperStart, helperEnd, '');
    expect(outside, isNot(contains('SecureKey.fromList(')));
  });

  test('M3 server Argon2 params are bounded on both sides', () {
    Map<String, dynamic> meta(int t, int m, int p) => {
      'argon2_params': {'time_cost': t, 'memory_cost': m, 'parallelism': p},
    };
    final ok = accountKdfParams(meta(3, 131072, 4));
    expect([ok.timeCost, ok.memoryCost, ok.parallelism], [3, 131072, 4]);
    for (final bad in [
      meta(1, 131072, 4),
      meta(21, 131072, 4),
      meta(3, 32768, 4),
      meta(3, 4194304, 4), // 4 GiB would OOM-kill the app
      meta(3, 131072, 0),
      meta(3, 131072, 64),
    ]) {
      expect(() => accountKdfParams(bad), throwsFormatException);
    }
  });

  group('M4 TOFU key change confirmation', () {
    final crypto = CryptoService();
    final oldSigning = Uint8List.fromList(List.filled(32, 1));
    final oldEncryption = Uint8List.fromList(List.filled(32, 2));
    final newSigning = Uint8List.fromList(List.filled(32, 3));
    final newEncryption = Uint8List.fromList(List.filled(32, 4));
    final oldFp = crypto.computeFingerprint(oldSigning, oldEncryption);
    final newFp = crypto.computeFingerprint(newSigning, newEncryption);
    final change = TofuKeyChangeException(
      userId: 'peer',
      oldFingerprint: oldFp,
      newFingerprint: newFp,
      signingPk: newSigning,
      encryptionPk: newEncryption,
    );
    Map<String, dynamic> pin() => {
      'user_id': 'peer',
      'signing_pk': oldSigning,
      'encryption_pk': oldEncryption,
      'fingerprint': oldFp,
      'first_seen': 1,
      'last_verified': 1,
    };

    test('re-pins exactly the verified key', () async {
      var stored = pin();
      await SyncService.confirmTofuKeyChange(
        change,
        newFp,
        loadKnownKey: (_) async => stored,
        saveKnownKey: (key) async => stored = key,
      );
      expect(stored['fingerprint'], newFp);
      expect(stored['signing_pk'], orderedEquals(newSigning));
      expect(stored['encryption_pk'], orderedEquals(newEncryption));
      expect(stored['first_seen'], 1);
    });

    test('rejects a different fingerprint or a pin that moved', () async {
      var writes = 0;
      await expectLater(
        SyncService.confirmTofuKeyChange(
          change,
          oldFp,
          loadKnownKey: (_) async => pin(),
          saveKnownKey: (_) async => writes++,
        ),
        throwsArgumentError,
      );
      await expectLater(
        SyncService.confirmTofuKeyChange(
          change,
          newFp,
          loadKnownKey: (_) async => {...pin(), 'fingerprint': 'other'},
          saveKnownKey: (_) async => writes++,
        ),
        throwsStateError,
      );
      final forged = TofuKeyChangeException(
        userId: 'peer',
        oldFingerprint: oldFp,
        newFingerprint: newFp,
        signingPk: oldSigning, // fingerprint does not belong to these keys
        encryptionPk: oldEncryption,
      );
      await expectLater(
        SyncService.confirmTofuKeyChange(
          forged,
          newFp,
          loadKnownKey: (_) async => pin(),
          saveKnownKey: (_) async => writes++,
        ),
        throwsArgumentError,
      );
      expect(writes, 0);
    });

    test('vault screen offers the confirmation and conflict resolution', () {
      final screen = File(
        'lib/screens/vault_screen.dart',
      ).readAsStringSync().replaceAll('\r\n', '\n');
      expect(screen, contains('on TofuKeyChangeException catch (change)'));
      expect(screen, contains('_sync.acceptTofuKeyChange(change'));
      expect(screen, contains("'Use server versions'"));
      expect(screen, contains('onPressed: verified ?'));
    });
  });

  group('M5 HTTP timeouts', () {
    test('no response headers -> TimeoutException', () async {
      final client = TimeoutClient(
        MockClient((_) => Completer<http.Response>().future),
        timeout: const Duration(milliseconds: 50),
      );
      await expectLater(
        client.get(Uri.parse('https://sezam.example/api/sync')),
        throwsA(isA<TimeoutException>()),
      );
    });

    test('a body that stalls -> TimeoutException', () async {
      final body = StreamController<List<int>>();
      body.add([1, 2, 3]); // then nothing more
      final client = TimeoutClient(
        MockClient.streaming(
          (_, _) async => http.StreamedResponse(body.stream, 200),
        ),
        timeout: const Duration(milliseconds: 50),
      );
      await expectLater(
        client.get(Uri.parse('https://sezam.example/api/sync')),
        throwsA(isA<TimeoutException>()),
      );
      await body.close();
    });

    test('a fast response passes through unchanged', () async {
      final client = TimeoutClient(
        MockClient(
          (_) async =>
              http.Response('{"ok":true}', 200, headers: {'etag': '"7"'}),
        ),
      );
      final response = await client.get(Uri.parse('https://sezam.example/'));
      expect(response.statusCode, 200);
      expect(response.body, '{"ok":true}');
      expect(response.headers['etag'], '"7"');
    });

    test('sync and share services use the timeout client', () {
      final sync = File(
        'lib/services/sync_service.dart',
      ).readAsStringSync().replaceAll('\r\n', '\n');
      expect(sync, contains('TimeoutClient(http.Client())'));
      expect(
        RegExp(r'(?<![\w.])http\.(get|post|put|delete)\(').hasMatch(sync),
        isFalse,
      );
      final share = File(
        'lib/services/share_service.dart',
      ).readAsStringSync().replaceAll('\r\n', '\n');
      expect(share, contains('TimeoutClient(http.Client())'));
    });
  });
}
