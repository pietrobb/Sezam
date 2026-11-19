import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/biometric_kek_store.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('KEK storage requires a fresh biometric auth on every read', () async {
    final calls = <MethodCall>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel('biometric_storage'),
            (call) async {
      calls.add(call);
      return true;
    });

    await openBiometricKekStorage();

    expect(calls, hasLength(1));
    expect(calls.single.method, 'init');
    final args = Map<String, dynamic>.from(calls.single.arguments as Map);
    expect(args['name'], biometricKekStorageName);
    final options = Map<String, dynamic>.from(args['options'] as Map);
    expect(options['authenticationRequired'], isTrue);
    expect(options['authenticationValidityDurationSeconds'], -1);
    expect(options['androidBiometricOnly'], isTrue);
    expect(options['darwinBiometricOnly'], isTrue);
  });

  test('AuthService never keeps the KEK in plain secure storage', () {
    final source =
        File('lib/services/auth_service.dart').readAsStringSync();
    // The only remaining use of the legacy key is deleting it.
    final legacyUses = RegExp(r'_secureStorage\.(\w+)\(key: _legacyKekKey')
        .allMatches(source)
        .map((m) => m.group(1))
        .toSet();
    expect(legacyUses, isNotEmpty);
    expect(legacyUses.difference({'delete', 'containsKey'}), isEmpty);
    expect(source.contains('local_auth'), isFalse);
    expect(source.contains('openBiometricKekStorage()).read()'), isTrue);
  });

  test('Android activity supports the biometric prompt and FLAG_SECURE', () {
    final activity = File(
      'android/app/src/main/kotlin/sk/sezam/sezam_mobile/MainActivity.kt',
    ).readAsStringSync();
    expect(activity, contains('FlutterFragmentActivity()'));
    expect(activity, contains('FLAG_SECURE'));
  });
}
