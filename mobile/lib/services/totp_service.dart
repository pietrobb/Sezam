/// Sezam TOTP Service — RFC 6238 time-based one-time password generator.
///
/// Generates 6-digit codes with 30-second time steps.
/// Compatible with Google Authenticator, Authy, etc.

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto_pkg;

class TotpService {
  static final TotpService _instance = TotpService._();
  factory TotpService() => _instance;
  TotpService._();

  /// Default TOTP parameters (RFC 6238).
  static const int defaultDigits = 6;
  static const int defaultPeriod = 30; // seconds
  static const int defaultT0 = 0; // Unix epoch

  /// Generate a TOTP code from a base32-encoded secret.
  ///
  /// [secret] is the base32-encoded shared secret.
  /// [timestamp] is Unix timestamp in seconds (defaults to now).
  /// [digits] is the number of digits (default 6).
  /// [period] is the time step in seconds (default 30).
  String generateCode(
    String secret, {
    int? timestamp,
    int digits = defaultDigits,
    int period = defaultPeriod,
  }) {
    final now = timestamp ?? (DateTime.now().millisecondsSinceEpoch ~/ 1000);
    final timeCounter = (now - defaultT0) ~/ period;
    final secretBytes = _base32Decode(secret);
    return _generateHOTP(secretBytes, timeCounter, digits);
  }

  /// Get remaining seconds until the next TOTP code change.
  int getRemainingSeconds({int period = defaultPeriod}) {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return period - ((now - defaultT0) % period);
  }

  /// Get the progress fraction (0.0 to 1.0) through the current period.
  double getProgress({int period = defaultPeriod}) {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final elapsed = (now - defaultT0) % period;
    return elapsed / period;
  }

  /// Generate HOTP (RFC 4226) — the core of TOTP.
  String _generateHOTP(Uint8List secret, int counter, int digits) {
    // Convert counter to 8-byte big-endian
    final counterBytes = Uint8List(8);
    final view = ByteData.sublistView(counterBytes);
    view.setInt64(0, counter, Endian.big);

    // HMAC-SHA1(secret, counter)
    final hmac = crypto_pkg.Hmac(crypto_pkg.sha1, secret);
    final hash = hmac.convert(counterBytes);
    final hashBytes = Uint8List.fromList(hash.bytes);

    // Dynamic truncation (RFC 4226 section 5.4)
    final offset = hashBytes[hashBytes.length - 1] & 0x0f;
    final binary = ((hashBytes[offset] & 0x7f) << 24) |
        ((hashBytes[offset + 1] & 0xff) << 16) |
        ((hashBytes[offset + 2] & 0xff) << 8) |
        (hashBytes[offset + 3] & 0xff);

    // Modulo 10^digits
    final otp = binary % _pow10(digits);
    return otp.toString().padLeft(digits, '0');
  }

  /// Power of 10.
  int _pow10(int n) {
    int result = 1;
    for (int i = 0; i < n; i++) {
      result *= 10;
    }
    return result;
  }

  /// Decode a base32 string to bytes (RFC 4648).
  Uint8List _base32Decode(String input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    final cleaned = input.toUpperCase().replaceAll(RegExp(r'[^A-Z2-7]'), '');

    final output = <int>[];
    int buffer = 0;
    int bitsLeft = 0;

    for (int i = 0; i < cleaned.length; i++) {
      final val = alphabet.indexOf(cleaned[i]);
      if (val < 0) continue;

      buffer = (buffer << 5) | val;
      bitsLeft += 5;

      if (bitsLeft >= 8) {
        bitsLeft -= 8;
        output.add((buffer >> bitsLeft) & 0xff);
      }
    }

    return Uint8List.fromList(output);
  }

  /// Encode bytes to base32 string (for display/export).
  String base32Encode(Uint8List input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    final buffer = StringBuffer();
    int bitsLeft = 0;
    int currentByte = 0;

    for (final byte in input) {
      currentByte = (currentByte << 8) | byte;
      bitsLeft += 8;

      while (bitsLeft >= 5) {
        bitsLeft -= 5;
        buffer.write(alphabet[(currentByte >> bitsLeft) & 0x1f]);
      }
    }

    if (bitsLeft > 0) {
      buffer.write(alphabet[(currentByte << (5 - bitsLeft)) & 0x1f]);
    }

    return buffer.toString();
  }

  /// Parse a TOTP URI (otpauth://totp/...).
  /// Returns {issuer, account, secret, digits, period, algorithm}.
  Map<String, dynamic>? parseTotpUri(String uri) {
    try {
      final parsed = Uri.parse(uri);
      if (parsed.scheme != 'otpauth' || parsed.host != 'totp') return null;

      final path = parsed.path.startsWith('/')
          ? parsed.path.substring(1)
          : parsed.path;
      final params = parsed.queryParameters;

      String issuer = params['issuer'] ?? '';
      String account = path;

      // Handle "Issuer:Account" format in path
      if (path.contains(':')) {
        final parts = path.split(':');
        if (issuer.isEmpty) issuer = parts[0];
        account = parts.length > 1 ? parts[1] : parts[0];
      }

      return {
        'issuer': Uri.decodeComponent(issuer),
        'account': Uri.decodeComponent(account),
        'secret': params['secret'] ?? '',
        'digits': int.tryParse(params['digits'] ?? '') ?? defaultDigits,
        'period': int.tryParse(params['period'] ?? '') ?? defaultPeriod,
        'algorithm': params['algorithm'] ?? 'SHA1',
      };
    } catch (_) {
      return null;
    }
  }
}
