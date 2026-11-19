import 'package:flutter/widgets.dart';

/// Tracks when the user left the foreground for the auto-lock countdown.
///
/// Leaving passes inactive → (hidden) → paused and returning passes
/// paused → inactive → resumed. Only the FIRST non-resumed state marks the
/// moment the user left; later transitions (including inactive on the way
/// back) must not reset it, otherwise the elapsed time is always ~0.
class AutoLockTracker {
  DateTime? _leftAt;

  DateTime? get leftAt => _leftAt;

  /// Returns true when this transition starts a new background period.
  bool onStateChange(AppLifecycleState state, DateTime now) {
    if (state == AppLifecycleState.resumed) return false;
    if (_leftAt != null) return false;
    _leftAt = now;
    return true;
  }

  /// Consumes and returns the leave timestamp (null if the app never left).
  DateTime? consumeOnResume() {
    final leftAt = _leftAt;
    _leftAt = null;
    return leftAt;
  }

  static bool isExpired(DateTime leftAt, DateTime now, int minutes) {
    if (minutes <= 0) return false; // 0 = disabled
    return now.difference(leftAt) >= Duration(minutes: minutes);
  }
}
