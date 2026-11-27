// The phone follows the organisation's signed team log (TL5;
// docs/DESIGN_TEAM_LOG.md §4.3, §6), as the desktop and the browser do.
//
// Each pull brings the replayed log up to the server's announced head
// (GET /api/team-log?since, pages); the head this phone saw is part of the
// encrypted sync checkpoint, so a server whose log is gone, shorter, forked
// or of another genesis is refused (TEAM LOG MISMATCH). The records are kept
// in a setting and replayed (signatures checked) when the vault unlocks.

import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'write_authority.dart';
import 'team_log.dart';

const teamLogRecordsSetting = 'team_log_records';
const teamLogPages = 1000;
const forgetPinMinChars = 16;

// Independent of the replaceable vault DB and password/identity keys. This is
// device-local trust, not the portable encrypted account anchor.
const _trustStorage = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),
  iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
);

String _genesisHash(Object? value) {
  if (value is! String || !RegExp(r'^[0-9a-f]{64}$').hasMatch(value)) {
    throw TeamLogMismatch('has an invalid confirmed genesis');
  }
  return value;
}

String? provisioningGenesis(String fragment) {
  if (fragment.isEmpty) return null; // Legacy QR without a team log.
  final fields = Uri.splitQueryString(fragment);
  if (fields.length != 1 || !fields.containsKey('g') ||
      fragment.contains('&')) {
    throw TeamLogMismatch('has an invalid QR genesis fragment');
  }
  return _genesisHash(fields['g']);
}

({String token, String? genesis}) invitationDetails(String input, String serverUrl) {
  final uri = Uri.parse(input.trim());
  String token;
  if (uri.hasScheme) {
    final server = Uri.parse(serverUrl);
    if ((uri.scheme != 'http' && uri.scheme != 'https') ||
        uri.origin != server.origin || uri.userInfo.isNotEmpty ||
        uri.path.replaceFirst(RegExp(r'/$'), '') != server.path.replaceFirst(RegExp(r'/$'), '')) {
      throw const FormatException('Invitation belongs to another server');
    }
    final values = uri.queryParametersAll['invite'];
    if (values == null || values.length != 1) {
      throw const FormatException('Missing or ambiguous invitation token');
    }
    token = values.single;
  } else {
    if (uri.hasAuthority || uri.hasQuery) throw const FormatException('Invalid invitation');
    token = uri.path;
  }
  if (token.isEmpty || RegExp(r'\s').hasMatch(token)) {
    throw const FormatException('Invalid invitation token');
  }
  return (token: token, genesis: provisioningGenesis(uri.fragment));
}

// INV-7 (capability run 411): trust this phone keeps that cannot be read
// refuses the team (local_damaged), never the unlock, and is no password
// error; the founder confirmed again replaces it (confirmTeamFounder).
TeamLogMismatch _unreadableTrust(String what, Object error) => TeamLogMismatch(
      "anchor held on this phone cannot be read ($what: $error); confirming the team's founder "
      'again (Settings → Team trust) replaces it',
      'local_damaged',
    );

Future<String?> readConfirmedTeamGenesis(String userId) async {
  final raw = await _trustStorage.read(key: 'sezam_confirmed_team_genesis:$userId');
  if (raw == null) return null;
  try {
    final value = jsonDecode(raw) as Map<String, dynamic>;
    if (value['user_id'] != userId) throw const FormatException('another account');
    return _genesisHash(value['genesis_hash']);
  } catch (e) {
    throw _unreadableTrust('confirmed genesis', e);
  }
}

/// [replaceUnreadable]: the founder confirmed again on purpose replaces a pin
/// or a list of left genesis hashes that cannot be read.
Future<void> confirmTeamGenesis(String userId, String genesis,
    {void Function()? beforeWrite, bool replaceUnreadable = false}) async {
  _genesisHash(genesis);
  String? previous;
  try {
    previous = await readConfirmedTeamGenesis(userId);
  } on TeamLogMismatch {
    if (!replaceUnreadable) rethrow;
  }
  if (previous != null && previous != genesis) {
    throw TeamLogMismatch('conflicts with the confirmed genesis');
  }
  beforeWrite?.call();
  await _trustStorage.write(
    key: 'sezam_confirmed_team_genesis:$userId',
    value: jsonEncode({'user_id': userId, 'genesis_hash': genesis}),
  );
  // Confirmed again on purpose (invitation, QR, founder): no longer left.
  List<String>? forgotten;
  try {
    forgotten = await readForgottenTeamGenesis(userId);
  } on TeamLogMismatch {
    if (!replaceUnreadable) rethrow;
  }
  if (forgotten == null || forgotten.contains(genesis)) {
    await _writeForgottenTeamGenesis(userId, (forgotten ?? const []).where((g) => g != genesis));
  }
  if (replaceUnreadable) {
    try {
      await readAccountTeamGenesis(userId);
    } on TeamLogMismatch {
      // Noted again from the account keys at the next unlock.
      await _trustStorage.delete(key: _accountAnchorKey(userId));
    }
  }
}

// Review c78fd19 (medium): genesis hashes this phone left on purpose
// (SyncService.forgetTeamLogPin). The account bundle on the server may still
// name one; it is then not pinned again from there.
Future<List<String>> readForgottenTeamGenesis(String userId) async {
  final raw = await _trustStorage.read(key: 'sezam_forgotten_team_genesis:$userId');
  if (raw == null) return const [];
  try {
    final value = jsonDecode(raw) as Map<String, dynamic>;
    if (value['user_id'] != userId) throw const FormatException('another account');
    return [for (final g in value['genesis'] as List) _genesisHash(g)];
  } catch (e) {
    throw _unreadableTrust('genesis hashes this phone left', e);
  }
}

/// [readForgottenTeamGenesis], or null while it cannot be read.
Future<List<String>?> _readableForgottenTeamGenesis(String userId) async {
  try {
    return await readForgottenTeamGenesis(userId);
  } on TeamLogMismatch {
    return null;
  }
}

Future<void> _writeForgottenTeamGenesis(String userId, Iterable<String> genesis) async {
  final key = 'sezam_forgotten_team_genesis:$userId';
  final list = genesis.toSet().toList()..sort();
  if (list.isEmpty) {
    await _trustStorage.delete(key: key);
  } else {
    await _trustStorage.write(key: key, value: jsonEncode({'user_id': userId, 'genesis': list}));
  }
}

/// Leave [genesis]: remembered as left, the confirmed pin removed.
Future<void> forgetConfirmedTeamGenesis(String userId, Iterable<String> genesis) async {
  // An unreadable list is replaced, never in the way of leaving (run 411).
  await _writeForgottenTeamGenesis(userId, [...?await _readableForgottenTeamGenesis(userId), ...genesis]);
  await _trustStorage.delete(key: 'sezam_confirmed_team_genesis:$userId');
}

/// The genesis an account bundle names, unless this phone left that log.
Future<void> importAccountTeamGenesis(String userId, String genesis) async {
  // Capability run 412: a pin or list that cannot be read pins nothing and
  // never fails the unlock; the team is refused where it is used
  // (local_damaged) until the founder is confirmed again. A readable pin of
  // another log still refuses these keys before anything is written.
  final forgotten = await _readableForgottenTeamGenesis(userId);
  if (forgotten == null || forgotten.contains(genesis)) return;
  try {
    await readConfirmedTeamGenesis(userId);
  } on TeamLogMismatch {
    return;
  }
  await confirmTeamGenesis(userId, genesis);
}

// INV-7: the genesis the account keys name, noted at every unlock from the
// keys just opened (ACCOUNT_ANCHOR_META in team_log_local.py); absent while
// they name none or one this phone left.
String _accountAnchorKey(String userId) => 'sezam_account_team_anchor:$userId';

/// At unlock: note the genesis the account keys name ([genesis], null: none)
/// and pin it unless this phone pins another. Never refuses: a conflict is
/// refused where the team is used, as anchor_conflict (VaultService).
Future<void> recordAccountTeamGenesis(String userId, String? genesis) async {
  List<String>? forgotten = const [];
  if (genesis != null) {
    _genesisHash(genesis);
    // Capability run 411: unguarded, an unreadable list read "Wrong password".
    forgotten = await _readableForgottenTeamGenesis(userId);
    if (forgotten != null && forgotten.contains(genesis)) genesis = null;
  }
  if (genesis == null) {
    await _trustStorage.delete(key: _accountAnchorKey(userId));
    return;
  }
  await _trustStorage.write(
    key: _accountAnchorKey(userId),
    value: jsonEncode({'user_id': userId, 'genesis_hash': genesis}),
  );
  // An unreadable list may hold it: not pinned from the keys then (local_damaged).
  if (forgotten == null) return;
  String? confirmed;
  try {
    confirmed = await readConfirmedTeamGenesis(userId);
  } on TeamLogMismatch {
    return; // an unreadable pin is refused where the team is used (local_damaged)
  }
  if (confirmed == null) await confirmTeamGenesis(userId, genesis);
}

/// The genesis [recordAccountTeamGenesis] noted, unless this phone left it since.
Future<String?> readAccountTeamGenesis(String userId) async {
  final raw = await _trustStorage.read(key: _accountAnchorKey(userId));
  if (raw == null) return null;
  final String genesis;
  try {
    final value = jsonDecode(raw) as Map<String, dynamic>;
    if (value['user_id'] != userId) throw const FormatException('another account');
    genesis = _genesisHash(value['genesis_hash']);
  } catch (e) {
    throw _unreadableTrust('account anchor', e);
  }
  return (await readForgottenTeamGenesis(userId)).contains(genesis) ? null : genesis;
}

// Review c78fd19: the way out once the team's log is lost for good. INV-8:
// every offer is marked as a risk (RISK_MARKER in team_log_local.py).
const lostTeamLogHint = '. RISK: a hostile server can cause this on purpose (drop its log, serve a new genesis) '
    'so that this phone drops its pin. Only if your admin confirms out of band that the team\'s log '
    'is lost for good (another server, a reseed), '
    'Settings → "Zabudnúť pripnutý tímový denník" leaves it on this phone';

void requireConfirmedGenesis(String? confirmed, String? actual) {
  if (confirmed != null && confirmed != actual) {
    throw TeamLogMismatch('does not match the confirmed genesis');
  }
}

// INV-7 (docs/ROOT_CAUSE_PLAN.md): why this phone refuses the server's team
// log, and for which causes "Zabudnúť pripnutý tímový denník" is offered: only
// where the log is missing or a new one starts (another server, a reseed); a
// fork, a log going back or one that does not replay is a lying server, never
// forgotten. The same list as MISMATCH_CAUSES in team_log_local.py and
// TEAM_LOG_MISMATCH_FORGET in app.js (tests/vectors/team_log_mismatch.json).
const teamLogMismatchForget = <String, bool>{
  'confirmed_genesis': true, 'log_gone': true, 'other_genesis': true,
  'left_earlier_log': false, 'went_back': false, 'differs': false, 'does_not_replay': false,
  'short_of_head': false, 'head_genesis': false, 'refused_at_head': false,
  'local_damaged': false, 'anchor_conflict': true,
};

class TeamLogMismatch implements Exception {
  /// [cause] is a key of [teamLogMismatchForget] (none: this phone's own
  /// state, never offered); [offersForget] and the hint follow from it alone.
  TeamLogMismatch(this.detail, [this.cause]) {
    if (cause != null && !teamLogMismatchForget.containsKey(cause)) {
      throw ArgumentError.value(cause, 'cause', 'unknown team log mismatch cause');
    }
  }
  final String detail;
  final String? cause;

  bool get offersForget => cause != null && teamLogMismatchForget[cause]!;

  @override
  String toString() => "TEAM LOG MISMATCH: the server's team log $detail${offersForget ? lostTeamLogHint : ''}";
}

/// A change the log refuses: never queued, the server would refuse it for good.
class TeamLogRefused implements Exception {
  TeamLogRefused(this.reason);
  final String reason;

  @override
  String toString() => 'The team log does not allow this change ($reason)';
}

class LocalTeamLog {
  LocalTeamLog(this.records, this.team);
  final List<Map<String, dynamic>> records;
  final TeamState team;
}

// Only call with a signature-verified replay. A checkpoint is continuity,
// not independent authority for a server-chosen founder.
bool localTeamLogTrusted(LocalTeamLog? local, String? confirmedGenesis,
    String userId, String? signingPk, String? encryptionPk) {
  if (local == null || local.records.isEmpty) return false;
  if (confirmedGenesis != null) return local.team.genesisHash == confirmedGenesis;
  if (signingPk == null || encryptionPk == null) return false;
  final founder = teamFounderLineage(local);
  return founder.userId == userId && founder.keys.contains((signingPk, encryptionPk));
}

// Input must be a freshly signature-verified log, never a server key directory.
({String userId, List<(String, String)> keys}) teamFounderLineage(LocalTeamLog local) {
  final genesis = (jsonDecode(local.records.first['body'] as String) as Map)['data'] as Map;
  final userId = genesis['user_id'] as String;
  final known = <(String, String)>[(genesis['signing_pk'] as String, genesis['encryption_pk'] as String)];
  var linked = true;
  for (final record in local.records) {
    final body = jsonDecode(record['body'] as String) as Map;
    final data = body['data'] as Map;
    if (data['user_id'] != userId) continue;
    if (body['type'] == 'member.remove') {
      linked = false;
    } else if (body['type'] == 'member.add') {
      linked = known.contains((data['signing_pk'], data['encryption_pk']));
    } else if (body['type'] == 'member.keys' && linked) {
      known.add((data['signing_pk'] as String, data['encryption_pk'] as String));
    }
  }
  return (userId: userId, keys: known);
}

Map<String, Object?>? teamLogPin(TeamState? team) => team == null
    ? null
    : {
        'genesis_hash': team.genesisHash,
        'seq': team.headSeq,
        'hash': team.headHash,
      };

bool isTeamLogPin(Object? pin) =>
    pin is Map &&
    pin['genesis_hash'] is String &&
    pin['seq'] is int &&
    pin['hash'] is String;

/// The server's head after uploading what it lost onto its prefix of
/// [local]; [head] unchanged when it is no such prefix or refuses.
Future<Map<String, dynamic>?> _restoreTeamLog(
  Map<String, dynamic>? head,
  LocalTeamLog local,
  Map<String, dynamic>? pin,
  Future<Map<String, dynamic>?> Function(List<Map<String, dynamic>> records) restore,
) async {
  final localSeq = local.team.headSeq;
  final serverSeq = head == null ? -1 : head['seq'];
  if (serverSeq is! int || serverSeq >= localSeq) return head;
  final pinSeq = pin?['seq'];
  if (pinSeq is int && pinSeq > localSeq) return head;
  if (head != null &&
      (head['genesis_hash'] != local.team.genesisHash ||
          TeamLog.recordHash(local.records[serverSeq]) != head['hash'])) {
    return head;
  }
  try {
    var current = head;
    final bodies = [
      for (var seq = 0; seq < local.records.length; seq++) TeamLog.parseBody(local.records[seq]['body'], seq),
    ];
    // R17-L: a part ends nowhere inside a readmit (its share links).
    for (var start = serverSeq + 1, end = 0; start < local.records.length; start = end) {
      end = TeamLog.restorePartEnd(bodies, start, teamLogPages);
      current = await restore([
        for (final r in local.records.sublist(start, end)) {'body': r['body'], 'sig': r['sig']},
      ]);
    }
    return current;
  } catch (_) {
    return head; // refused (or 409): this pull stays a mismatch, the next compares again
  }
}

/// INV-7: this phone's cached copy of the team log ([raw], the stored records)
/// as it may be used: it replays, starts with [confirmed] (when set) and holds
/// every head in [pins]. The pins bind the log; the copy only caches it, as
/// the page keeps none and fetches it under its checkpoint pin each sign-in.
/// A copy that is missing or fails here is fetched again under the same pins
/// (SyncService.prepareInitialTeamLog), never trusted, never an end.
LocalTeamLog verifiedTeamLogCopy(
  String? raw,
  String? confirmed,
  List<Map<String, dynamic>> pins,
  Ed25519Verify verify,
) {
  if (raw == null) throw const FormatException('cached log is missing');
  final records = [
    for (final r in jsonDecode(raw) as List) Map<String, dynamic>.from(r as Map),
  ];
  if (records.isEmpty) throw const FormatException('cached log is empty');
  final team = TeamLog(verify).replay(records);
  requireConfirmedGenesis(confirmed, team.genesisHash);
  for (final pin in pins) {
    final seq = pin['seq'] as int;
    if (seq < 0 ||
        team.headSeq < seq ||
        team.genesisHash != pin['genesis_hash'] ||
        TeamLog.recordHash(records[seq]) != pin['hash']) {
      throw const FormatException('cached log differs from the saved head');
    }
  }
  return LocalTeamLog(records, team);
}

/// Bring [local] (this phone's copy, or null) up to [head] (the pull's
/// team_log_head). [pin] is the head an earlier pull saw. Null while the
/// organisation has no log. [fetchPage] returns the records after a seq.
Future<LocalTeamLog?> syncTeamLog({
  required TeamLog log,
  required Map<String, dynamic>? head,
  required LocalTeamLog? local,
  required Map<String, dynamic>? pin,
  String? confirmedGenesis,
  bool leftEarlierLog = false,
  String? ownUserId,
  List<String>? ownKeys,
  required Future<List<Map<String, dynamic>>> Function(int since) fetchPage,
  Future<Map<String, dynamic>?> Function(List<Map<String, dynamic>> records)? restore,
  TeamLogRemake? remake,
  Set<String> withdrawn = const {},
  Future<void> Function(List<String> hashes)? withdraw,
}) async {
  Never fail(String detail, String cause) => throw TeamLogMismatch(detail, cause);
  // Goal #440: a cause that offers to forget the pin only as far as the
  // records served bear it out, never on the unsigned head alone. No record
  // while the head says none is the log gone; a first record that is
  // [genesis] makes the head a lie; another genesis is the loss named.
  Future<Never> failAsServed(
      Map<String, dynamic>? shownHead, String? genesis, String detail, String cause) async {
    final served = await fetchPage(-1);
    if (served.isEmpty) {
      if (shownHead == null) fail(detail, cause);
      fail('does not reach the head it announced', 'short_of_head');
    }
    final String first;
    try {
      first = log.replay(served.take(1).toList()).genesisHash;
    } catch (e) {
      fail('does not replay: $e', 'does_not_replay');
    }
    if (first == genesis) {
      fail('head names another genesis than the records it serves', 'head_genesis');
    }
    if (cause == 'log_gone') {
      fail('starts with another genesis than this device saw', 'other_genesis');
    }
    fail(detail, cause);
  }

  if (restore != null && local != null) {
    // R9-E: a server restored from a backup lost records this phone
    // accepted. It puts them back onto a prefix of its copy; any other
    // server log (fork, another genesis, a refused upload) stays a
    // mismatch below.
    head = await _restoreTeamLog(head, local, pin, restore);
  }
  if (confirmedGenesis != null && confirmedGenesis != head?['genesis_hash']) {
    await failAsServed(head, confirmedGenesis, 'does not match the confirmed genesis', 'confirmed_genesis');
  }
  if (head == null) {
    if (local != null || pin != null) {
      await failAsServed(null, local?.team.genesisHash ?? pin?['genesis_hash'] as String?,
          'is gone (a server restored from a backup, or another server)', 'log_gone');
    }
    // Review 8bc70f7 M2: a phone that left a log does not fall back to the
    // rules from before any log because a server sends none.
    if (leftEarlierLog) {
      fail("is missing, and this phone left an earlier team log: it waits for the team's "
          'new log (the admin founds it) and its confirmed founder', 'left_earlier_log');
    }
    return null;
  }
  final pinned = local?.team.genesisHash ?? pin?['genesis_hash'] as String?;
  if (pinned != null && head['genesis_hash'] != pinned) {
    await failAsServed(head, pinned, 'starts with another genesis than this device saw', 'other_genesis');
  }
  try {
    return await _catchUpTeamLog(log, head, local, pin, fetchPage, withdrawn);
  } on TeamLogMismatch catch (e) {
    if (local == null ||
        ownUserId == null ||
        !const ['went_back', 'differs', 'does_not_replay'].contains(e.cause)) {
      rethrow;
    }
    final LocalTeamLog? followed;
    try {
      followed = await _followFork(log, head, local, pin, ownUserId, ownKeys, fetchPage, remake, withdrawn, withdraw);
    } on _ForkRefused catch (refused) {
      throw TeamLogMismatch(
          "${e.detail}; it forks from this phone's copy and is not followed: ${refused.reason}", e.cause);
    }
    if (followed == null) rethrow;
    return followed;
  }
}

/// Goal #442 (bg344 random run of TeamLogMachine): the server lost its log
/// and one device of this account put back a shorter copy, so it forks from
/// what this phone holds. Review 18c300f R16-H1: the server keeps what a
/// device of this account withdrew (a hand-over the server refused, a
/// dropped rotation), so a fork is followed only as far as
/// [TeamLog.forkRefusal] allows; a member's phone follows once every change
/// it saw is on the server's side (on 18c300f: 'does not replay' for good).
/// Null: the mismatch stands; [_ForkRefused]: it stands, and why.
Future<LocalTeamLog?> _followFork(
  TeamLog log,
  Map<String, dynamic> head,
  LocalTeamLog local,
  Map<String, dynamic>? pin,
  String? ownUserId,
  List<String>? ownKeys,
  Future<List<Map<String, dynamic>>> Function(int since) fetchPage,
  TeamLogRemake? remake,
  Set<String> withdrawn,
  Future<void> Function(List<String> hashes)? withdraw,
) async {
  final headSeq = head['seq'];
  if (headSeq is! int || headSeq < 0) return null;
  if (pin != null) {
    final pinSeq = pin['seq'];
    if (pinSeq is! int ||
        pinSeq < 0 ||
        pinSeq > local.team.headSeq ||
        TeamLog.recordHash(local.records[pinSeq]) != pin['hash']) {
      return null;
    }
  }
  final served = <Map<String, dynamic>>[];
  for (var page = 0; page < teamLogPages && served.length <= headSeq; page++) {
    final got = (await fetchPage(served.length - 1)).take(headSeq + 1 - served.length).toList();
    if (got.isEmpty) break;
    served.addAll(got);
  }
  var fork = 0;
  while (fork < served.length &&
      fork < local.records.length &&
      TeamLog.recordHash(served[fork]) == TeamLog.recordHash(local.records[fork])) {
    fork++;
  }
  if (fork == 0 || fork == served.length || fork == local.records.length) return null;
  final TeamState team;
  final List<int> missing;
  try {
    // [withdrawn]: what this phone sent and the server refused, and this
    // account's records a fork it followed went on without.
    final (refusal, lostOwn) = TeamLog.forkRefusal(
        local.records.sublist(fork), served.sublist(fork), ownUserId, ownKeys, withdrawn);
    if (refusal != null) throw _ForkRefused(refusal);
    missing = lostOwn;
    team = log.replay(served);
  } on _ForkRefused {
    rethrow;
  } catch (_) {
    return null;
  }
  if (team.headSeq != headSeq || team.headHash != head['hash'] || TeamLog.adminPolicyRefusal(team) != null) {
    return null;
  }
  // Capability finding 505 (desktop: _follow_fork): this account's records
  // left behind are withdrawn - a server serving them again later is not
  // followed (their changes went out again, or aside).
  final abandoned = TeamLog.forkAbandoned(local.records.sublist(fork), ownUserId);
  Future<LocalTeamLog> follow(LocalTeamLog followed) async {
    if (abandoned.isNotEmpty) {
      if (withdraw == null) throw StateError('a phone following a fork withdraws what it left behind');
      await withdraw(abandoned);
    }
    return followed;
  }

  if (missing.isEmpty) return follow(LocalTeamLog(served, team));
  if (ownUserId == null || remake == null) return null;
  final bodies = [
    for (final r in local.records.sublist(fork))
      if (missing.contains(TeamLog.parseBody(r['body'], -1)['seq'])) TeamLog.parseBody(r['body'], -1),
  ];
  // Review 18c300f R16-M5 (desktop: _follow_fork queues them again): this
  // account's lost changes go out again on the server's head; the phone made
  // them, or nobody else holds them, and on 18c300f it waited for good.
  if (bodies.any((body) => !TeamLog.remadeKinds.contains(body['type']))) return null;
  var after = team;
  final records = <Map<String, dynamic>>[];
  String? setAside;
  try {
    for (final body in bodies) {
      final data =
          TeamLog.resolveChange(after, body['type'] as String, Map<String, dynamic>.from(body['data'] as Map));
      if (data == null) continue;
      final record = remake.sign(TeamLog.nextBody(after, body['type'] as String, ownUserId, data));
      after = log.replay([record], after);
      records.add(record);
    }
  } on TeamLogError catch (e) {
    // As the desktop's queue: made together, set aside together.
    setAside = '$e';
  }
  if (setAside == null && records.isNotEmpty) {
    switch (await remake.append(records)) {
      case RemakeOutcome.taken:
        return follow(LocalTeamLog([...served, ...records], after));
      case RemakeOutcome.moved:
        return null; // another device appended meanwhile: the next pull compares again
      case RemakeOutcome.refused:
        setAside = 'the server refused them';
    }
  }
  if (setAside != null) await remake.setAside(bodies, setAside);
  return follow(LocalTeamLog(served, team));
}

/// What became of the records a phone made again (R16-M5).
enum RemakeOutcome { taken, moved, refused }

/// How a phone makes this account's lost team changes again (R16-M5):
/// [sign] signs a body with the account's key, [append] posts the records
/// onto the server's head, [setAside] reports the changes the log or the
/// server no longer takes (the desktop's 'sezam team-log queue').
class TeamLogRemake {
  TeamLogRemake({required this.sign, required this.append, required this.setAside});
  final Map<String, dynamic> Function(Map<String, Object?> body) sign;
  final Future<RemakeOutcome> Function(List<Map<String, dynamic>> records) append;
  final Future<void> Function(List<Map<String, dynamic>> changes, String reason) setAside;
}

class _ForkRefused implements Exception {
  _ForkRefused(this.reason);
  final String reason;
}

Future<LocalTeamLog> _catchUpTeamLog(
  TeamLog log,
  Map<String, dynamic> head,
  LocalTeamLog? local,
  Map<String, dynamic>? pin,
  Future<List<Map<String, dynamic>>> Function(int since) fetchPage,
  Set<String> withdrawn,
) async {
  Never fail(String detail, String cause) => throw TeamLogMismatch(detail, cause);
  final localSeq = local?.team.headSeq ?? -1;
  final pinSeq = pin?['seq'] as int? ?? -1;
  final seen = localSeq > pinSeq ? localSeq : pinSeq;
  final headSeq = head['seq'];
  if (headSeq is! int || headSeq < seen) {
    fail('went back (head $headSeq < $seen)', 'went_back');
  }
  if (local != null && headSeq == localSeq) {
    if (head['hash'] != local.team.headHash) {
      fail('differs at record $localSeq', 'differs');
    }
    return local;
  }
  var team = local?.team ?? TeamState();
  final records = [...?local?.records];
  for (var page = 0; page < teamLogPages && team.headSeq < headSeq; page++) {
    final got = await fetchPage(team.headSeq);
    if (got.isEmpty) break;
    // Appended after this pull's head: the next pull takes it.
    final batch = got.take(headSeq - team.headSeq).toList();
    try {
      team = log.replay(batch, team); // prev of the first = this phone's head
    } catch (e) {
      fail('does not replay: $e', 'does_not_replay');
    }
    final start = team.headSeq - batch.length + 1;
    if (pin != null &&
        pinSeq >= start &&
        pinSeq <= team.headSeq &&
        TeamLog.recordHash(batch[pinSeq - start]) != pin['hash']) {
      fail('differs at record $pinSeq', 'differs');
    }
    records.addAll(batch);
  }
  if (team.headSeq != headSeq || team.headHash != head['hash']) {
    fail('does not reach the head it announced', 'short_of_head');
  }
  if (team.genesisHash != head['genesis_hash']) {
    fail('genesis differs from the head it announced', 'head_genesis');
  }
  for (var seq = localSeq + 1; withdrawn.isNotEmpty && seq < records.length; seq++) {
    // R16-M5 (R16-H1 for what the phone now sends): the server kept a record it refused.
    if (withdrawn.contains(TeamLog.recordHash(records[seq]))) {
      fail('holds record $seq, which this phone withdrew (the server refused it)', 'differs');
    }
  }
  // TL7: the server refuses such an append; a head with it is not followed.
  final refusal = TeamLog.adminPolicyRefusal(team);
  if (refusal != null) fail('is refused at its head: $refusal', 'refused_at_head');
  return LocalTeamLog(records, team);
}

/// Ids among [pulled] (folders and items) the log refuses: judged in the
/// rows after the pull, a removal or move against what this device held
/// ([held]). A refused change is not applied; the copy held stays.
/// [reasons], when given, gets why each refused folder/item was refused.
Set<String> teamLogRefusedPulls(
  List<Map<String, dynamic>> pulled,
  Map<String, Map<String, dynamic>> held,
  TeamState team,
  String? ownUserId, {
  String? ownEncryptionPk,
  Map<String, String>? reasons,
}) {
  final after = {...held, for (final row in pulled) row['id'] as String: row};
  final ownKeys = ownKeySigners(after.values, ownUserId);
  return {
    for (final row in pulled)
      if (row['object_type'] == 'envelope' &&
          row['is_deleted'] != 1 &&
          team.dekIndex.containsKey(row['parent_ref']) &&
          !TeamLog.envelopeValid(
            team,
            row['signer_id'] as String? ?? '',
            row['target_user_id'] as String? ?? '',
            row['parent_ref'] as String,
            row['access_level'] as String?,
            row['target_user_id'] == ownUserId && ownEncryptionPk != null
                ? ownEncryptionPk
                : team.members[row['target_user_id']]?.encryptionPk ?? '',
          ))
        row['id'] as String,
    for (final row in pulled)
      if ((row['object_type'] == 'node' || row['object_type'] == 'entry') &&
          _noted(
                reasons,
                row['id'] as String,
                teamLogVerdict(
                  row,
                  after,
                  team,
                  ownKeys: ownKeys,
                  ownUserId: ownUserId,
                  sealing: false,
                  held: held[row['id']],
                  heldRows: held,
                ).refusal,
              ) !=
              null)
        row['id'] as String,
  };
}

String? _noted(Map<String, String>? reasons, String id, String? refusal) {
  if (refusal != null) reasons?[id] = refusal;
  return refusal;
}

/// The log's refusal of a write whose signer has no write access there.
const teamLogNoWriteAccess = 'team log gives no write access here';

/// Setting: pulled writes refused with [teamLogNoWriteAccess] (id -> the
/// object as served), judged again once the log gives their author write.
const teamLogNoWriteAccessSetting = 'team_log_writes_without_access';

/// Review 8595ec1 (R10-C): pulled folders/items the log refused only for
/// want of write access, kept as the server sent them ([refused]: id ->
/// object), that the log now lets their author write in the team folder
/// above them ([rows]: this phone's objects). Founding the log hid such
/// older items; given write access, they come back without a full resync.
List<Map<String, dynamic>> writesTheLogNowAllows(
  Map<String, dynamic> refused,
  Map<String, Map<String, dynamic>> rows,
  TeamState team,
) => [
  for (final obj in refused.values.whereType<Map>())
    if (_nowWritable(Map<String, dynamic>.from(obj), rows, team))
      Map<String, dynamic>.from(obj),
];

bool _nowWritable(
  Map<String, dynamic> obj,
  Map<String, Map<String, dynamic>> rows,
  TeamState team,
) {
  final id = obj['id'] as String?;
  final folder = id != null && TeamLog.isTeamFolder(team, id)
      ? id
      : teamFolderAbove(rows, team, obj['parent_ref'] as String?);
  final author =
      obj['signature_user_id'] as String? ?? obj['owner_id'] as String?;
  return folder != null &&
      author != null &&
      TeamLog.mayWrite(team, folder, author);
}

/// A write's source, destination and keys can all depend on the log, even
/// when a tier-2 key itself is private or a move leaves the team folder.
void requireTrustedTeamWrites(
  LocalTeamLog? local,
  String? confirmedGenesis,
  String userId,
  String? signingPk,
  String? encryptionPk,
  List<Map<String, dynamic>> writes,
  Map<String, Map<String, dynamic>> held,
) {
  requireConfirmedGenesis(confirmedGenesis, local?.team.genesisHash);
  if (local == null || localTeamLogTrusted(local, confirmedGenesis, userId, signingPk, encryptionPk)) return;
  final team = local.team;
  final after = {...held, for (final row in writes) row['id'] as String: row};
  bool touches(Map<String, dynamic> row, Map<String, Map<String, dynamic>> rows) =>
      TeamLog.isTeamFolder(team, row['id'] as String) ||
      teamFolderAbove(rows, team, row['parent_ref'] as String?) != null ||
      team.dekIndex.containsKey(row['id']) ||
      team.dekIndex.containsKey(row['parent_ref']) ||
      team.dekIndex.containsKey(sealingDekId(row));
  for (final row in writes) {
    final previous = held[row['id']];
    if (touches(row, after) || (previous != null && touches(previous, held))) {
      throw TeamLogRefused('the founder is not confirmed on this device');
    }
  }
}

/// Why the folder/item [row] this account is about to write may not leave
/// this device, or null (the server's push rule, sealing=true). [rows] is
/// the local state; [row] replaces its copy there.
String? teamLogWriteRefusal(
  TeamState team,
  String userId,
  Map<String, dynamic> row,
  Map<String, Map<String, dynamic>> rows,
) {
  final after = {...rows, row['id'] as String: row};
  return teamLogVerdict(
    row,
    after,
    team,
    ownKeys: ownKeySigners(after.values, userId),
    ownUserId: userId,
    sealing: true,
    held: rows[row['id']],
    heldRows: rows,
  ).refusal;
}
