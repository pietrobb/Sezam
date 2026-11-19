import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/main.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  testWidgets('App launches with existing-vault unlock screen',
      (WidgetTester tester) async {
    SharedPreferences.setMockInitialValues({});

    await tester.pumpWidget(const SezamApp(vaultExists: true));
    await tester.pump(const Duration(seconds: 2));

    // Verify unlock screen is shown
    expect(find.text('Sezam'), findsWidgets);
    expect(find.text('Otvor sa'), findsOneWidget);
    expect(find.text('Odomknut vault'), findsOneWidget);
  });
}
