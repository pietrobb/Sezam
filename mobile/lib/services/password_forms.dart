// Master password → KDF input (lockout review M8).
//
// The same visible password can arrive as different code points: an accented
// letter precomposed or as letter + combining mark, depending on keyboard,
// OS or paste. Desktop, web and mobile all derive the KEK from its Unicode
// NFC form, so it opens the account on every client.

import 'package:unorm_dart/unorm_dart.dart' as unorm;

/// The KDF input for a master password: its NFC form.
String canonicalPassword(String password) => unorm.nfc(password);

/// KDF inputs to try for an EXISTING password, canonical first.
///
/// An account or vault created before normalization derived from the
/// password exactly as typed; it may also have been typed decomposed. New
/// passwords use [canonicalPassword] only.
List<String> passwordForms(String password) {
  final forms = <String>[];
  for (final form in [
    canonicalPassword(password),
    password,
    unorm.nfd(password),
  ]) {
    if (!forms.contains(form)) forms.add(form);
  }
  return forms;
}
