/// Saving and opening files outside the app sandbox (lockout review M4).
///
/// Android: the system document picker (Storage Access Framework), so the
/// user chooses Downloads, a cloud drive or a USB stick. Elsewhere the
/// platform has no such channel and the calls report it as unsupported.
library;

import 'dart:io';

import 'package:flutter/services.dart';

import 'unsent_changes.dart';

const _channel = MethodChannel('sk.sezam/files');

class DocumentService {
  const DocumentService();

  bool get isSupported => Platform.isAndroid;

  /// Ask the user where to save [bytes]. False when they cancelled.
  Future<bool> saveDocument(String fileName, Uint8List bytes) async {
    if (!isSupported) throw UnsupportedError('No document picker here');
    final saved = await _channel.invokeMethod<bool>('saveDocument', {
      'name': fileName,
      'mime': 'application/json',
      'bytes': bytes,
    });
    return saved == true;
  }

  /// Let the user pick a file; null when they cancelled.
  Future<Uint8List?> openDocument() async {
    if (!isSupported) throw UnsupportedError('No document picker here');
    return _channel.invokeMethod<Uint8List>('openDocument', {
      'mime': 'application/json',
      'max_bytes': maxUnsentExportBytes,
    });
  }
}
