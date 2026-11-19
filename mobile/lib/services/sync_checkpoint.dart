import 'dart:convert';
import 'dart:typed_data';

import 'crypto_service.dart';
import 'team_log_client.dart';

/// Decode the same authenticated checkpoint for sync and offline log replay.
Map<String, dynamic> decodeSyncCheckpoint(
  String raw,
  Uint8List kek,
  String userId,
) {
  if (!raw.startsWith('enc:v1:')) {
    throw const FormatException('Refusing plaintext or malformed sync checkpoint');
  }
  final crypto = CryptoService();
  final packed = base64Decode(raw.substring('enc:v1:'.length));
  final nonceLength = crypto.aeadNonceBytes;
  if (packed.length <= nonceLength) {
    throw const FormatException('Checkpoint ciphertext is truncated');
  }
  final plaintext = crypto.aeadDecrypt(
    ciphertext: Uint8List.fromList(packed.sublist(nonceLength)),
    additionalData: Uint8List.fromList(utf8.encode('sezam-sync-checkpoint-v1:$userId')),
    nonce: Uint8List.fromList(packed.sublist(0, nonceLength)),
    key: kek,
  );
  final checkpoint = jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
  final seq = checkpoint['last_sync_seq'];
  final stateHash = checkpoint['state_hash'];
  final timestamp = checkpoint['timestamp'];
  final commitToken = checkpoint['commit_token'];
  final commitTokenSeq = checkpoint['commit_token_seq'];
  if (seq is! int ||
      seq < 0 ||
      commitTokenSeq != null &&
          (commitTokenSeq is! int || commitTokenSeq < 0 || commitTokenSeq > seq) ||
      stateHash is! String ||
      !RegExp(r'^[0-9a-f]{64}$').hasMatch(stateHash) ||
      timestamp is! int ||
      commitToken != null &&
          (commitToken is! String || commitToken.isEmpty || commitToken.length > 64) ||
      checkpoint['team_log'] != null && !isTeamLogPin(checkpoint['team_log'])) {
    throw const FormatException('Checkpoint fields are invalid');
  }
  return checkpoint;
}
