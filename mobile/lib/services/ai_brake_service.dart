import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

/// Remote AI kill switch (AI broker TODO, section 1 phase 2).
///
/// The phone publishes a signed `ai_policy` `{enabled: false, epoch}` through
/// the sync server; every running `sezam mcp-serve` of the account polls it
/// (~30 s) and turns AI access off. The brokers verify the signature against
/// the owner's key in their own vault, so the server cannot forge it, and no
/// policy can turn AI access on again: that needs the master password on the
/// computer. This side therefore only ever sends `enabled: false`.
///
/// Signed message (shared with the desktop and the server, pinned in
/// tests/vectors/cross_client.json):
///   "sezam-ai-policy-v1" || user_id (26 B ASCII) || u8(enabled) || u64be(epoch)
class AiBrakeService {
  AiBrakeService.withClient(
    this._http, {
    required Uint8List Function(Uint8List message) sign,
    int Function()? nowMs,
  }) : _sign = sign,
       _nowMs = nowMs ?? (() => DateTime.now().millisecondsSinceEpoch);

  static const policyContext = 'sezam-ai-policy-v1';

  final http.Client _http;
  final Uint8List Function(Uint8List message) _sign;
  final int Function() _nowMs;

  static Uint8List policyMessage(String userId, bool enabled, int epoch) {
    final user = ascii.encode(userId);
    if (user.length != 26) {
      throw ArgumentError('userId must be a 26-character ULID');
    }
    if (epoch < 1) throw ArgumentError('epoch out of range');
    final context = ascii.encode(policyContext);
    final out = Uint8List(context.length + 26 + 1 + 8);
    out.setRange(0, context.length, context);
    out.setRange(context.length, context.length + 26, user);
    out[context.length + 26] = enabled ? 1 : 0;
    ByteData.sublistView(out).setUint64(context.length + 27, epoch, Endian.big);
    return out;
  }

  /// Turns AI access off on every computer of the account. Returns the
  /// published epoch: above the stored one and at least the current time in
  /// ms, so it stays newer than anything a computer has already applied.
  Future<int> pullBrake({
    required String serverUrl,
    required String token,
    required String userId,
  }) async {
    final base = serverUrl.replaceAll(RegExp(r'/+$'), '');
    final uri = Uri.parse('$base/api/ai-policy');
    final headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer $token',
    };
    // A rival brake from another device may win the epoch race once.
    for (var attempt = 0; attempt < 2; attempt++) {
      final current = await _http.get(uri, headers: headers);
      _check(current, 'read');
      final policy =
          (jsonDecode(current.body) as Map<String, dynamic>)['policy']
              as Map<String, dynamic>?;
      final stored = policy == null ? 0 : policy['epoch'] as int;
      final now = _nowMs();
      final epoch = now > stored ? now : stored + 1;
      final signature = _sign(policyMessage(userId, false, epoch));
      final response = await _http.put(
        uri,
        headers: headers,
        body: jsonEncode({
          'enabled': false,
          'epoch': epoch,
          'signature': _hex(signature),
        }),
      );
      if (response.statusCode == 409 && attempt == 0) continue;
      _check(response, 'publish');
      return epoch;
    }
    throw StateError('unreachable');
  }

  static void _check(http.Response response, String operation) {
    if (response.statusCode != 200) {
      throw Exception(
        'AI brake $operation failed: HTTP ${response.statusCode}',
      );
    }
  }

  static String _hex(Uint8List bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
