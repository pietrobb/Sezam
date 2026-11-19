// Review 8595ec1 (R10-F, medium): a failure before runApp showed a blank app.
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/main.dart';

void main() {
  testWidgets('a startup failure is shown, not a blank screen', (tester) async {
    final app = await startSezam(() async => throw StateError('database is locked'));
    await tester.pumpWidget(app);
    expect(find.text('Sezam sa nepodarilo spustit'), findsOneWidget);
    expect(find.textContaining('database is locked'), findsOneWidget);
  });

  testWidgets('a clean start opens the app', (tester) async {
    final app = await startSezam(() async => false);
    expect(app, isA<SezamApp>());
    expect((app as SezamApp).vaultExists, isFalse);
  });
}
