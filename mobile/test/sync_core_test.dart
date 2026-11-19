// The phone's binding of the shared sync core (core/ffi via hook/build.dart)
// answers as the crate does; tests/test_sync_core_web.py holds the desktop
// and web bindings to the same answers.
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/sync_core.dart';

void main() {
  test('the bundled core answers', () {
    expect(
      syncCore('next_cursor', {
        'last_seq': 0,
        'max_commit_seq': 7,
        'gc_floor_seq': 10,
        'head_commit_seq': 9,
      }),
      9,
    );
    expect(
      syncCore('decide_pulled', {
        'unsent': {
          'version': 4,
          'hash': 'b',
          'is_deleted': false,
          'base': {'version': 3, 'hash': 'a'},
        },
        'pulled': {
          'version': 3,
          'hash': 'a',
          'is_deleted': false,
          'own_earlier_push': false,
        },
      }),
      'keep_unsent',
    );
  });

  // Review c78fd19: the core rejects an older copy and tells equivocation;
  // a security field left out is refused, not read as false.
  test('older copies and equivocation; strict input', () {
    Map<String, Object?> held5() => {
      'version': 5,
      'hash': 'h5',
      'is_deleted': false,
      'queued': false,
    };
    expect(
      syncCore('against_held', {
        'gc_floor_seq': 0,
        'items': [
          {
            'held': held5(),
            'pulled': {'version': 4, 'hash': 'h4'},
          },
          {
            'held': held5(),
            'pulled': {'version': 5, 'hash': 'x'},
          },
          {
            'held': held5(),
            'pulled': {'version': 6, 'hash': 'h6'},
          },
        ],
      }),
      ['keep_held', 'equivocation', 'apply'],
    );
    expect(
      () => syncCore('gate', {
        'checkpoint': {'seq': 9},
        'reply': {'head_commit_seq': 4},
        'rollback_pending': false,
      }),
      throwsA(isA<StateError>()),
    );
  });

  // Capability review run 365: the same answers as
  // tests/test_sync_core_web.py::test_the_send_side_after_a_rekey.
  test(
    'a write queued under a replaced key goes out under the current one',
    () {
      const team = {
        'folders': {
          'F': ['g1', 'g2', 'g3'],
        },
        'may_hold': ['g3'],
      };
      expect(
        syncCore('reseal_targets', {
          'team': team,
          'held': ['g3'],
          'keys': ['g1', 'g2', 'g3', 'x'],
        }),
        [
          {'send': 'reseal', 'key': 'g3'},
          {'send': 'reseal', 'key': 'g3'},
          {'send': 'as_is'},
          {'send': 'as_is'},
        ],
      );
      // Review c78fd19: without the current key the write waits.
      final revoked = {...team, 'may_hold': <String>[]};
      expect(
        syncCore('reseal_targets', {
          'team': revoked,
          'held': ['g3'],
          'keys': ['g1'],
        }),
        [
          {'send': 'wait', 'key': 'g3'},
        ],
      );
      expect(
        syncCore('may_open_superseded', {'team': team, 'key': 'g1'}),
        true,
      );
      expect(
        syncCore('may_open_superseded', {'team': revoked, 'key': 'g1'}),
        false,
      );
    },
  );

  test('a refused input throws, nothing else is answered', () {
    expect(() => syncCore('no_such_operation', {}), throwsA(isA<StateError>()));
  });
}
