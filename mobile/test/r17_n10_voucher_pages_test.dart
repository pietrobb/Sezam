// Review c02cc47 R17-N10: the server serves the voucher lists of a key in
// pages (`next` is the `after` of the next page, '' after the last). The phone
// read only the first page, so what a later list vouched for was withheld.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/sync_service.dart';

void main() {
  // SyncService() is one instance: its client is made once, so every test
  // swaps the handler behind it.
  late Map<String, Object?> Function(String after) serve;
  final asked = <String>[];
  late SyncService sync;

  setUpAll(() {
    final client = MockClient((request) async {
      final after = request.url.queryParameters['after'] ?? '';
      asked.add(after);
      return http.Response(jsonEncode(serve(after)), 200);
    });
    http.runWithClient(() {
      sync = SyncService()..configure('https://sezam.test');
    }, () => client);
    sync.setToken('jwt');
  });

  setUp(asked.clear);

  test('the phone reads every page of voucher lists', () async {
    final pages = {
      '': {
        'lists': ['first'],
        'next': 'A' * 26,
      },
      'A' * 26: {
        'lists': ['second'],
        'next': 'B' * 26,
      },
      'B' * 26: {
        'lists': ['third'],
        'next': '',
      },
    };
    serve = (after) => {'signing_pk': '00' * 32, ...pages[after]!};

    final lists = await sync.fetchKeyVoucherLists('U' * 26);

    expect(lists, ['first', 'second', 'third']);
    expect(asked, ['', 'A' * 26, 'B' * 26]);
  });

  test('a server that never ends the pages is read at most so far', () async {
    serve = (after) => {
      'lists': ['again'],
      'next': 'A' * 26,
    };

    await sync.fetchKeyVoucherLists('U' * 26);

    expect(asked.length, SyncService.keyVoucherMaxPages);
  });
}
