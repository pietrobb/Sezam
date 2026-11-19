import 'dart:async';

import 'package:flutter/services.dart';

const _channel = MethodChannel('sk.sezam/clipboard');

class ClipboardService {
  ClipboardService({
    Future<String?> Function()? readText,
    Future<void> Function(String text)? writeText,
    Future<void> Function()? clear,
    DateTime Function()? now,
  }) : _readText = readText ?? _readClipboard,
       _writeText = writeText ?? _writeSensitiveClipboard,
       _clear =
           clear ?? (writeText != null ? () => writeText('') : _clearClipboard),
       _now = now ?? DateTime.now;

  /// App-wide instance, so a clear that came due while the app was in the
  /// background (timers do not run in a frozen process) can be finished on
  /// resume — see [clearIfOverdue].
  static final ClipboardService shared = ClipboardService();

  final Future<String?> Function() _readText;
  final Future<void> Function(String text) _writeText;
  final Future<void> Function() _clear;
  final DateTime Function() _now;

  Timer? _clearTimer;
  int _generation = 0;
  String? _pendingText;
  DateTime? _deadline;

  Future<void> copySensitive(
    String text, {
    Duration timeout = const Duration(seconds: 15),
  }) async {
    final generation = ++_generation;
    _clearTimer?.cancel();
    await _writeText(text);
    if (generation != _generation) return;

    _pendingText = text;
    _deadline = _now().add(timeout);
    _clearTimer = Timer(timeout, () => _clearIfStillOurs(generation));
  }

  /// Called when the app returns to the foreground.
  Future<void> clearIfOverdue() async {
    final deadline = _deadline;
    if (_pendingText == null || deadline == null) return;
    if (_now().isBefore(deadline)) return;
    await _clearIfStillOurs(_generation);
  }

  Future<void> _clearIfStillOurs(int generation) async {
    final text = _pendingText;
    if (generation != _generation || text == null) return;
    String? currentText;
    try {
      currentText = await _readText();
    } catch (_) {
      currentText = null;
    }
    if (generation != _generation) return;
    // Android 10+ returns no clipboard data to an app without focus, so a
    // null read cannot prove someone else replaced the secret. Clearing
    // blindly is the only way the timeout still works there; a readable
    // clipboard with different content is never touched.
    if (currentText != null && currentText.isNotEmpty && currentText != text) {
      _resetPending();
      return;
    }
    try {
      await _clear();
    } catch (_) {
      return; // Keep it pending; clearIfOverdue retries on resume.
    }
    if (generation == _generation) _resetPending();
  }

  void _resetPending() {
    _pendingText = null;
    _deadline = null;
    _clearTimer?.cancel();
    _clearTimer = null;
  }

  void cancelScheduledClear() {
    _generation++;
    _resetPending();
  }

  static Future<String?> _readClipboard() async {
    return (await Clipboard.getData(Clipboard.kTextPlain))?.text;
  }

  /// Marks the clip sensitive on Android (hidden from the Android 13+ copy
  /// preview and keyboard suggestions); plain clipboard elsewhere.
  static Future<void> _writeSensitiveClipboard(String text) async {
    try {
      await _channel.invokeMethod<void>('setSensitive', {'text': text});
    } on MissingPluginException {
      await Clipboard.setData(ClipboardData(text: text));
    }
  }

  static Future<void> _clearClipboard() async {
    try {
      await _channel.invokeMethod<void>('clear');
    } on MissingPluginException {
      await Clipboard.setData(const ClipboardData(text: ''));
    }
  }
}
