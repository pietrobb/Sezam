// Review c02cc47 R17-L: the phone parses the voucher cases of
// tests/test_r17_l_voucher_parsers.py (written to SEZAM_X3_DIR/config.json)
// as the desktop and the web do.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/key_vouchers.dart';

import 'support/real_server_phone.dart';

void main() {
  final dir = Platform.environment['SEZAM_X3_DIR'];
  late Directory appDir;

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_voucher_parse_');
    await setUpPhone(appDir.path);
    initPhoneCrypto();
  });

  tearDownAll(() => appDir.delete(recursive: true));

  test(
    'the voucher cases parse as on the desktop and the web',
    () {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final pk = hexToBytes(cfg['signing_pk'] as String);
      for (final c in (cfg['cases'] as List).cast<Map<String, dynamic>>()) {
        final list = Map<String, dynamic>.from(c['list'] as Map);
        final repeat = c['repeat'] as int? ?? 1;
        list['entries'] = [
          for (var i = 0; i < repeat; i++) ...(list['entries'] as List),
        ];
        final entry = c['entry'] as List;
        final vouched = vouchedEntries(cfg['user_id'] as String, pk, [list]);
        expect(
          vouched.contains(
            keyVoucherKey(
              entry[0] as String,
              entry[1] as int,
              entry[2] as String,
            ),
          ),
          c['vouched'],
          reason: c['name'] as String,
        );
      }
    },
    skip: dir == null ? 'run by tests/test_r17_l_voucher_parsers.py' : false,
  );
}
