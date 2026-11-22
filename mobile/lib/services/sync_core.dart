// The shared sync core (core/, Rust): the sync decisions the desktop and the
// web make with the same crate (docs/SYNC_SINGLE_SOURCE.md 4b). Built and
// bundled by hook/build.dart; one JSON entry point, as in the other bindings.
import 'dart:convert';
import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'team_log.dart';

@Native<Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>(
  symbol: 'sezam_sync_core_call',
  assetId: 'package:sezam_mobile/services/sync_core.dart',
)
external Pointer<Utf8> _call(Pointer<Utf8> op, Pointer<Utf8> input);

@Native<Void Function(Pointer<Utf8>)>(
  symbol: 'sezam_sync_core_free',
  assetId: 'package:sezam_mobile/services/sync_core.dart',
)
external void _free(Pointer<Utf8> answer);

/// The verified team log as the core reads it (core/src/reseal.rs): each
/// folder's keys, oldest first, and the keys the log lets [userId] hold.
///
/// With [keys], only the folders that name one of them: the log names a key
/// in one folder only, and the core's answer about a key reads that folder
/// alone (review 8bc70f7 M8: each unsent write sent every folder of the team).
Map<String, Object?> syncCoreTeam(
  TeamState team,
  String userId, {
  Iterable<String>? keys,
}) {
  final folders = keys == null
      ? team.folders
      : {
          for (final folder in {
            for (final key in keys)
              if (team.dekIndex[key] != null) team.dekIndex[key]![0] as String,
          })
            if (team.folders[folder] != null) folder: team.folders[folder]!,
        };
  return {
    'folders': {
      for (final e in folders.entries)
        e.key: [for (final gen in e.value) gen[0]],
    },
    'may_hold': [
      for (final gens in folders.values)
        for (final gen in gens)
          if (TeamLog.mayHoldKey(team, userId, gen[0])) gen[0],
    ],
  };
}

/// Run one core operation; throws [StateError] on a refused input.
Object? syncCore(String op, Map<String, Object?> args) {
  final opPtr = op.toNativeUtf8();
  final inputPtr = jsonEncode(args).toNativeUtf8();
  try {
    final answer = _call(opPtr, inputPtr);
    final String text;
    try {
      text = answer.toDartString();
    } finally {
      _free(answer);
    }
    final out = jsonDecode(text) as Map<String, Object?>;
    if (out.containsKey('error')) {
      throw StateError('sync core $op: ${out['error']}');
    }
    return out['ok'];
  } finally {
    malloc.free(opPtr);
    malloc.free(inputPtr);
  }
}
