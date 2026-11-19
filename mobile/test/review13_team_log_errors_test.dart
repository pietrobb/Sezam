// Review c78fd19 (medium): the screens caught neither TeamLogRefused nor
// TeamLogMismatch. A write the team log refused left its dialog open behind an
// unhandled error, and the user was not told why nothing was saved.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/widgets/team_log_errors.dart';

void main() {
  Object? thrown;

  Future<bool?> press(WidgetTester tester, Future<void> Function() write) async {
    bool? saved;
    thrown = null;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => ElevatedButton(
              onPressed: () async {
                try {
                  saved = await runTeamLogWrite(context, write);
                } catch (e) {
                  thrown = e;
                }
              },
              child: const Text('Save'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('Save'));
    await tester.pumpAndSettle(const Duration(milliseconds: 100));
    return saved;
  }

  testWidgets('a refused write is reported and not taken as saved', (
    tester,
  ) async {
    final saved = await press(
      tester,
      () async => throw TeamLogRefused('sealed with an old key generation'),
    );
    expect(saved, isFalse);
    expect(find.byType(SnackBar), findsOneWidget);
    expect(
      find.textContaining('sealed with an old key generation'),
      findsOneWidget,
    );
    expect(find.textContaining('Nič sa neuložilo'), findsOneWidget);
  });

  testWidgets('a team log mismatch is reported and not taken as saved', (
    tester,
  ) async {
    final saved = await press(
      tester,
      () async => throw TeamLogMismatch('changed since the founder review'),
    );
    expect(saved, isFalse);
    expect(
      find.textContaining('changed since the founder review'),
      findsOneWidget,
    );
  });

  testWidgets('a write that succeeds shows nothing', (tester) async {
    expect(await press(tester, () async {}), isTrue);
    expect(find.byType(SnackBar), findsNothing);
  });

  testWidgets('any other error is left to the caller', (tester) async {
    expect(await press(tester, () async => throw StateError('other')), isNull);
    expect(thrown, isStateError);
    expect(find.byType(SnackBar), findsNothing);
  });

  test('the sync error text names both, and nothing else', () {
    expect(teamLogErrorText(TeamLogRefused('x')), contains('nedovolí'));
    expect(teamLogErrorText(TeamLogMismatch('y')), contains('y'));
    expect(teamLogErrorText(StateError('z')), isNull);
  });
}
