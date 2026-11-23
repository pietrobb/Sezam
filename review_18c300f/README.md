# Review 18c300f – deep state-machine failures (SEZAM_STATEFUL_EXAMPLES=300)

Replay: copy `zz_r9_replay.py` to the repo root of a checkout at 18c300f under a
non-`tests/` directory and run `python -m pytest zz_r9/zz_r9_replay.py`.
All six blobs replay deterministically (`replay_18c300f.log`).

| # | Machine | Failure |
|---|---------|---------|
| 0 | SyncMachine | m6 pull refused for good: object signed by the account's retired key, no voucher list names it (after rotation by C, stale device A takes the keys over and pushes) |
| 1 | SyncMachine | server lie in PullObject.parent_ref crashes pull with raw sqlite IntegrityError (FOREIGN KEY) |
| 2 | TeamLogMachine | server loses team log while B rotates identity; admin's restore refused ("gives … keys the account does not sign in with"); m8 stuck on TeamLogMismatch |
| 3 | TeamLogMachine | same root (A rotates, server loses log); members/admin stuck on TeamLogMismatch |
| 4 | TeamLogMachine | as 0 (m6 stuck on retired-key object). Its first assertion "full_resync: took … v2" is a harness false positive: B's own unpushed move already has local version 2 |
| 5 | TeamLogMachine | second_admin_revokes on an already-removed member: raw TeamLogError not_member |
