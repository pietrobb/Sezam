// Lockout review N3 (mobile): whitespace around the username. The connect
// screen trimmed, but the unlock path used the name stored by an older
// install as-is, so " alice" reached a different (or no) server account.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/auth_service.dart';

const _auth = 'lib/services/auth_service.dart';

void main() {
  test('surrounding whitespace is not part of the name', () {
    expect(normalizeUsername('  alice \t'), 'alice');
    expect(normalizeUsername('alice'), 'alice');
    expect(normalizeUsername('a lice'), 'a lice');
  });

  test('every public entry point normalizes the name first', () {
    final src = File(_auth).readAsStringSync().replaceAll('\r\n', '\n');
    for (final method in [
      'Future<AuthResult> unlockWithPassword({',
      'Future<AuthResult> provisionFromQR({',
      'Future<AuthResult> recoverFromServer({',
      'Future<ConnectResult> connectToServer({',
      'Future<ConnectResult> registerWithInvitation({',
      'Future<bool> pollForApproval({',
    ]) {
      final from = src.indexOf(method);
      expect(from, greaterThanOrEqualTo(0), reason: method);
      final bodyStart = src.indexOf('{\n', src.indexOf(')', from)) + 2;
      final firstLine = src.substring(bodyStart, src.indexOf('\n', bodyStart));
      expect(
        firstLine.trim(),
        'username = normalizeUsername(username);',
        reason: method,
      );
    }
  });
}
