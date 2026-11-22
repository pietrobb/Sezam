// Goal #443: the phone reproduces the key voucher vectors of
// src/sezam/key_vouchers.py (tests/vectors/key_vouchers.json) byte for byte.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/key_vouchers.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;
  final v =
      jsonDecode(File('../tests/vectors/key_vouchers.json').readAsStringSync())
          as Map<String, dynamic>;

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_key_vouchers_');
    await setUpPhone(appDir.path);
    initPhoneCrypto();
  });

  tearDownAll(() => appDir.delete(recursive: true));

  test('voucher messages match the shared vectors', () {
    for (final m in (v['messages'] as List).cast<Map<String, dynamic>>()) {
      final message = keyVoucherMessage(
        m['user_id'] as String,
        hexToBytes(m['signing_pk'] as String),
        m['entries'],
      );
      expect(bytesToHex(message), m['message_hex']);
    }
  });

  test('malformed entries are refused', () {
    for (final e in v['malformed_entries'] as List) {
      expect(
        () => keyVoucherMessage(
          v['user_id'] as String,
          hexToBytes(v['current_signing_pk'] as String),
          [e],
        ),
        throwsFormatException,
        reason: '$e',
      );
    }
  });

  test('what the lists vouch for matches the shared vectors', () {
    for (final c in (v['cases'] as List).cast<Map<String, dynamic>>()) {
      final entry = c['entry'] as List;
      final vouched = vouchedEntries(
        v['user_id'] as String,
        hexToBytes(v['current_signing_pk'] as String),
        c['lists'],
      );
      expect(
        vouched.contains(
          keyVoucherKey(entry[0] as String, entry[1] as int, entry[2] as String),
        ),
        c['vouched'],
        reason: c['name'] as String,
      );
    }
  });
}
