// Lockout review M8 (mobile): the master password is normalized to NFC before
// the KDF, like on desktop and web; an existing password is also tried as
// typed and decomposed, for accounts created before the change.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/password_forms.dart';

const _auth = 'lib/services/auth_service.dart';
const _crypto = 'lib/services/crypto_service.dart';

const _nfc = 'Žltý kôň úpel ďábelské ódy';
// The same text with every accent as a combining mark.
const _nfd =
    'Z\u030Clty\u0301 ko\u0302n\u030C u\u0301pel d\u030Ca\u0301belske\u0301 o\u0301dy';

String _body(String file, String start, String end) {
  final src = File(file).readAsStringSync();
  final from = src.indexOf(start);
  expect(from, greaterThanOrEqualTo(0), reason: start);
  final to = src.indexOf(end, from + start.length);
  return src.substring(from, to < 0 ? src.length : to);
}

void main() {
  test('both forms of a password give the same KDF input', () {
    expect(_nfc, isNot(_nfd));
    expect(utf8.encode(canonicalPassword(_nfd)), utf8.encode(_nfc));
    expect(canonicalPassword(_nfc), _nfc);
  });

  test('an existing password is tried NFC first, then as typed and NFD', () {
    expect(passwordForms(_nfd), [_nfc, _nfd]);
    expect(passwordForms(_nfc), [_nfc, _nfd]);
    expect(passwordForms('plain-ascii-1'), ['plain-ascii-1']);
  });

  test('the KDF normalizes unless a legacy form is asked for', () {
    final derive = _body(_crypto, 'Future<Uint8List> deriveKEK(', '/// Derive');
    expect(derive, contains('exact ? password : canonicalPassword(password)'));
    final backup = _body(
      _crypto,
      'Future<Uint8List> deriveBackupKEK(',
      'Future<Uint8List> _deriveKEK(',
    );
    expect(backup, contains('exact ? password : canonicalPassword(password)'));
  });

  test('every check of an existing password tries its other forms', () {
    for (final (start, end, helper) in [
      (
        'Future<AuthResult> unlockWithPassword(',
        '// ── Offline Unlock',
        '_deriveExisting(',
      ),
      (
        'Future<AuthResult> unlockWithPassword(',
        '// ── Offline Unlock',
        '_recoverWithForms(',
      ),
      ('Future<AuthResult> unlockOffline(', 'Future<', '_deriveExisting('),
      ('Future<AuthResult> provisionFromQR(', 'Future<', '_deriveExisting('),
      ('importSezamKey({', '// ── Create Local Vault', '_deriveExisting('),
      (
        'Future<ConnectResult> _handleExistingServer(',
        'Future<',
        '_recoverWithForms(',
      ),
      (
        'Future<AuthResult> adoptPasswordChangedElsewhere(',
        'Future<void> _persistKeypairState',
        '_recoverWithForms(',
      ),
      ('Future<void> _uploadKeypairToServer(', 'Future<', '_deriveExisting('),
      (
        'Future<Uint8List?> _deriveLocalKek(',
        'Future<bool>',
        '_deriveExisting(',
      ),
    ]) {
      expect(_body(_auth, start, end), contains(helper), reason: start);
    }
  });

  test('only a 401 sends the proof of another form to the server', () {
    final recover = _body(
      _auth,
      'Future<({Uint8List derived, Map<String, dynamic> resp})> _recoverWithForms(',
      '/// KEK of [password] under the LOCAL salt',
    );
    expect(recover, contains('e.statusCode == 401 && i + 1 < forms.length'));
    expect(recover, contains('rethrow;'));
  });
}
