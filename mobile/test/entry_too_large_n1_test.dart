// Review d150605 N1: an entry over the server's 1 MiB limit was refused by
// VaultService (SyncObjectTooLargeException), but neither the new-entry nor
// the edit dialog caught it: Save did nothing visible and the user never
// learned the entry was not saved.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/sync_limits.dart';

String _between(String source, String start, String end) {
  final from = source.indexOf(start);
  expect(from, greaterThanOrEqualTo(0), reason: start);
  final to = source.indexOf(end, from);
  expect(to, greaterThan(from), reason: end);
  return source.substring(from, to);
}

void main() {
  test('the vault refuses an entry the server can never take', () {
    expect(
      () => requireSyncablePayload(List<int>.filled(maxObjectPayloadBytes + 1, 0)),
      throwsA(isA<SyncObjectTooLargeException>()),
    );
    expect(
      const SyncObjectTooLargeException(2 * 1024 * 1024).toString(),
      contains('Shorten the note'),
    );
  });

  test('the new-entry dialog tells the user and stays open', () {
    final screen = File('lib/screens/vault_screen.dart').readAsStringSync();
    final create = _between(screen, 'await _vault.createEntry(', 'Navigator.pop(ctx)');
    expect(create, contains('on SyncObjectTooLargeException catch (e)'));
    expect(create, contains('SnackBar(content: Text(e.toString()))'));
    expect(create, contains('return;'));
  });

  test('the edit dialog tells the user and stays open', () {
    final screen =
        File('lib/screens/entry_detail_screen.dart').readAsStringSync();
    final update = _between(
      screen,
      'await _vault.updateEntry(',
      'on StaleEntryEditException',
    );
    expect(update, contains('on SyncObjectTooLargeException catch (e)'));
    expect(update, contains('SnackBar(content: Text(e.toString()))'));
    expect(update, contains('return;'));
  });
}
