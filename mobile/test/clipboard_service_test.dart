import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/screens/entry_detail_screen.dart';
import 'package:sezam_mobile/services/clipboard_service.dart';

void main() {
  testWidgets('sensitive clipboard text is cleared after 15 seconds', (
    tester,
  ) async {
    var clipboardText = '';
    final service = ClipboardService(
      readText: () async => clipboardText,
      writeText: (text) async => clipboardText = text,
    );

    await service.copySensitive('https://sezam.example/share/id#secret');

    expect(clipboardText, contains('#secret'));
    await tester.pump(const Duration(seconds: 14));
    expect(clipboardText, contains('#secret'));
    await tester.pump(const Duration(seconds: 1));
    await tester.pump();
    expect(clipboardText, isEmpty);
  });

  testWidgets('auto-clear does not erase newer clipboard content', (
    tester,
  ) async {
    var clipboardText = '';
    final service = ClipboardService(
      readText: () async => clipboardText,
      writeText: (text) async => clipboardText = text,
    );

    await service.copySensitive('https://sezam.example/share/id#secret');
    clipboardText = 'new clipboard value';
    await tester.pump(const Duration(seconds: 15));
    await tester.pump();

    expect(clipboardText, 'new clipboard value');
  });

  testWidgets('scheduled clear survives entry detail disposal', (tester) async {
    var clipboardText = '';
    final service = ClipboardService(
      readText: () async => clipboardText,
      writeText: (text) async => clipboardText = text,
    );

    await service.copySensitive(
      'password-secret',
      timeout: const Duration(seconds: 1),
    );
    await tester.pumpWidget(
      MaterialApp(
        home: EntryDetailScreen(
          entryArgs: const {},
          clipboardService: service,
        ),
      ),
    );

    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 1));
    await tester.pump();

    expect(clipboardText, isEmpty);
  });
}
