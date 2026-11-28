// tests/vectors/password_forms.json: the master password stays with the
// phone (docs/CORE_UNIFICATION.md U6j), so its copy is checked against the
// desktop's forms here.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/password_forms.dart';

void main() {
  final vectors =
      jsonDecode(
            File('../tests/vectors/password_forms.json').readAsStringSync(),
          )
          as Map<String, dynamic>;
  final cases = (vectors['cases'] as List).cast<Map<String, dynamic>>();

  test('canonical form and forms to try are the desktop ones', () {
    for (final c in cases) {
      final password = c['password'] as String;
      expect(canonicalPassword(password), c['canonical'], reason: c['name']);
      expect(
        passwordForms(password),
        (c['forms'] as List).cast<String>(),
        reason: c['name'],
      );
    }
    expect(cases.length, greaterThanOrEqualTo(20));
  });
}
