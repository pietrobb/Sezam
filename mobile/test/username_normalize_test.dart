// Review 688edcb N3: the phone sends the same account name as the server,
// desktop and web compute (tests/test_username_normalize_n3b.py VECTORS).
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/auth_service.dart';

void main() {
  test('normalizeUsername trims every client\'s whitespace and is NFC', () {
    const vectors = {
      ' alice\u00a0': 'alice',
      '\ufeffalice': 'alice',
      'alice\u200b': 'alice',
      'alice\x1c': 'alice',
      '\x85alice': 'alice',
      '\u3000alice\u202f': 'alice',
      'S\u030cimon': '\u0160imon',
      'a\u00a0b': 'a\u00a0b',
      ' \u00a0\ufeff ': '',
    };
    vectors.forEach((raw, expected) {
      expect(
        normalizeUsername(raw),
        expected,
        reason: raw.codeUnits.toString(),
      );
    });
  });
}
