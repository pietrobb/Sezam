import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/auto_lock.dart';

void main() {
  test('returning through inactive does not reset the leave time', () {
    final tracker = AutoLockTracker();
    final left = DateTime(2026, 11, 7, 10, 0);
    final back = left.add(const Duration(minutes: 6));

    // Leaving: resumed → inactive → hidden → paused.
    expect(tracker.onStateChange(AppLifecycleState.inactive, left), isTrue);
    expect(tracker.onStateChange(AppLifecycleState.hidden, left), isFalse);
    expect(tracker.onStateChange(AppLifecycleState.paused, left), isFalse);
    // Returning: paused → hidden → inactive → resumed.
    expect(tracker.onStateChange(AppLifecycleState.hidden, back), isFalse);
    expect(tracker.onStateChange(AppLifecycleState.inactive, back), isFalse);

    final leftAt = tracker.consumeOnResume();
    expect(leftAt, left);
    expect(AutoLockTracker.isExpired(leftAt!, back, 5), isTrue);
  });

  test('short interruption does not lock and resume clears the state', () {
    final tracker = AutoLockTracker();
    final left = DateTime(2026, 11, 7, 10, 0);
    tracker.onStateChange(AppLifecycleState.inactive, left);
    final leftAt = tracker.consumeOnResume()!;
    expect(
      AutoLockTracker.isExpired(
          leftAt, left.add(const Duration(seconds: 30)), 5),
      isFalse,
    );
    expect(tracker.leftAt, isNull);
    // The next background period starts fresh.
    final later = left.add(const Duration(hours: 1));
    expect(tracker.onStateChange(AppLifecycleState.paused, later), isTrue);
    expect(tracker.leftAt, later);
  });

  test('auto-lock 0 means disabled', () {
    final left = DateTime(2026, 11, 7);
    expect(
      AutoLockTracker.isExpired(left, left.add(const Duration(days: 1)), 0),
      isFalse,
    );
  });
}
