import 'auth_service.dart';
import 'sync_service.dart';

/// The app's full resync (vault screen).
///
/// Review 7c10379 (mobile): a server restored from a backup taken before a
/// password change has the older key_epoch, and its full resync's pull asks
/// for the password the server has ([KeyEpochStaleException]). The app showed
/// "Full resync failed" and the next sync asked for the full resync again: a
/// dead end. The password is now asked for ([askPassword]), taken over
/// ([takeOver]) and the full resync runs again. Null when the user cancelled
/// or [takeOver] refused the password ([onRefused] gets its error).
Future<FullResyncResult?> fullResyncTakingPasswordOver({
  required Future<FullResyncResult> Function() fullResync,
  required Future<String?> Function() askPassword,
  required Future<AuthResult> Function(String password) takeOver,
  void Function(String error)? onRefused,
}) async {
  while (true) {
    try {
      return await fullResync();
    } on KeyEpochStaleException {
      final password = await askPassword();
      if (password == null || password.isEmpty) return null;
      final taken = await takeOver(password);
      if (!taken.success) {
        onRefused?.call(taken.error ?? 'Wrong password');
        return null;
      }
    }
  }
}
