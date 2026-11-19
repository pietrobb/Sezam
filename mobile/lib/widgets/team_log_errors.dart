import 'package:flutter/material.dart';

import '../services/team_log_client.dart';

/// Review c78fd19 (medium): what the user is told when the team log refuses a
/// change or the server's log does not match the one this phone trusts, or
/// null for any other error. The screens caught neither: a refused write left
/// its dialog open behind an unhandled error, and a sync showed only the last
/// words of the mismatch.
String? teamLogErrorText(Object error) {
  if (error is TeamLogRefused) {
    return 'Tímový denník túto zmenu nedovolí (${error.reason}). '
        'Nič sa neuložilo.';
  }
  if (error is TeamLogMismatch) {
    return 'Tímový denník na serveri nesedí s denníkom, ktorému tento telefón '
        'dôveruje: ${error.detail}. Tímové zmeny sú zastavené; over odtlačok '
        'zakladateľa s adminom.';
  }
  return null;
}

/// Runs a vault write started from a screen. A team-log refusal or mismatch is
/// shown in a SnackBar and returns false; any other error propagates.
Future<bool> runTeamLogWrite(
  BuildContext context,
  Future<void> Function() write,
) async {
  final messenger = ScaffoldMessenger.of(context);
  try {
    await write();
    return true;
  } on TeamLogRefused catch (e) {
    _show(messenger, e);
  } on TeamLogMismatch catch (e) {
    _show(messenger, e);
  }
  return false;
}

void _show(ScaffoldMessengerState messenger, Object error) {
  messenger.showSnackBar(
    SnackBar(
      content: Text(teamLogErrorText(error)!),
      duration: const Duration(seconds: 6),
    ),
  );
}
