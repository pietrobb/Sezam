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

Future<String?> readConfirmedTeamGenesis(String userId) async {
  final raw = await _trustStorage.read(key: 'sezam_confirmed_team_genesis:$userId');
  if (raw == null) return null;
  try {
    final value = jsonDecode(raw) as Map<String, dynamic>;
    if (value['user_id'] != userId) throw const FormatException('another account');
    return _genesisHash(value['genesis_hash']);
  } catch (e) {
    throw TeamLogMismatch('confirmed genesis cannot be read: $e');
  }
}

Future<void> confirmTeamGenesis(String userId, String genesis, {void Function()? beforeWrite}) async {
  _genesisHash(genesis);
  final previous = await readConfirmedTeamGenesis(userId);
  if (previous != null && previous != genesis) {
    throw TeamLogMismatch('conflicts with the confirmed genesis');
  }
  beforeWrite?.call();
  await _trustStorage.write(
    key: 'sezam_confirmed_team_genesis:$userId',
    value: jsonEncode({'user_id': userId, 'genesis_hash': genesis}),
  );
  // Confirmed again on purpose (invitation, QR, founder): no longer left.
  final forgotten = await readForgottenTeamGenesis(userId);
  if (forgotten.contains(genesis)) {
    await _writeForgottenTeamGenesis(userId, forgotten.where((g) => g != genesis));
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
    throw TeamLogMismatch('forgotten genesis cannot be read: $e');
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
  await _writeForgottenTeamGenesis(userId, [...await readForgottenTeamGenesis(userId), ...genesis]);
  await _trustStorage.delete(key: 'sezam_confirmed_team_genesis:$userId');
}

/// The genesis an account bundle names, unless this phone left that log.
Future<void> importAccountTeamGenesis(String userId, String genesis) async {
  if ((await readForgottenTeamGenesis(userId)).contains(genesis)) return;
  await confirmTeamGenesis(userId, genesis);
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
  'local_damaged': false, 'anchor_conflict': false,
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
    for (var start = serverSeq + 1; start < local.records.length; start += teamLogPages) {
      final end = start + teamLogPages < local.records.length ? start + teamLogPages : local.records.length;
      current = await restore([
        for (final r in local.records.sublist(start, end)) {'body': r['body'], 'sig': r['sig']},
      ]);
    }
    return current;
  } catch (_) {
    return head; // refused (or 409): this pull stays a mismatch, the next compares again
  }
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
  required Future<List<Map<String, dynamic>>> Function(int since) fetchPage,
  Future<Map<String, dynamic>?> Function(List<Map<String, dynamic>> records)? restore,
}) async {
  Never fail(String detail, String cause) => throw TeamLogMismatch(detail, cause);
  final localSeq = local?.team.headSeq ?? -1;
  if (restore != null && local != null) {
    // R9-E: a server restored from a backup lost records this phone
    // accepted. It puts them back onto a prefix of its copy; any other
    // server log (fork, another genesis, a refused upload) stays a
    // mismatch below.
    head = await _restoreTeamLog(head, local, pin, restore);
  }
  if (confirmedGenesis != null && confirmedGenesis != head?['genesis_hash']) {
    fail('does not match the confirmed genesis', 'confirmed_genesis');
  }
  if (head == null) {
    if (local != null || pin != null) {
      fail('is gone (a server restored from a backup, or another server)', 'log_gone');
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
    fail('starts with another genesis than this device saw', 'other_genesis');
  }
  final pinSeq = pin?['seq'] as int? ?? -1;
  final seen = localSeq > pinSeq ? localSeq : pinSeq;
  final headSeq = head['seq'];
  if (headSeq is! int || headSeq < seen)
    fail('went back (head $headSeq < $seen)', 'went_back');
  if (local != null && headSeq == localSeq) {
    if (head['hash'] != local.team.headHash)
      fail('differs at record $localSeq', 'differs');
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
