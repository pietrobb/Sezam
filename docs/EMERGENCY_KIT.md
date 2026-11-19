# Sezam emergency kit

What to keep, and how to test it once a quarter, so that losing your laptop, your server or your password does not cost you your vault.

Sezam is end-to-end encrypted: neither the server nor the authors know your password, and **without it or the Shamir shares nobody can unlock the data**. The emergency kit is therefore the only way back.

---

## 1. What to keep

| What | How you get it | What it is for | Where to keep it |
|------|----------------|----------------|------------------|
| **Master password** | at `sezam init` | opens the vault, the backup and the `.sezam-key` | in your head, and sealed on paper in a safe / with a notary |
| **Key fingerprint** | `Fingerprint:` in the output of `sezam init` | proves that a restored identity is yours | written down in the kit (it is not secret) |
| **Encrypted vault backup** | `sezam export <file> --format backup` | a full copy of `sezam.db` (all entries, keys, audit) | offline: a USB stick or disk in a safe, away from home/office |
| **`.sezam-key`** | `sezam export-key <file>` (also offered by `sezam init`) | backup of your identity (signing and encryption key) | on the same offline medium as the backup |
| **Shamir shares** | `sezam org-recovery-setup -t 3 -n 5` (on a vault that is not connected, the server registers it only at `sezam connect`; if connect prints a warning, repeat the setup with `--replace`) | reset of a forgotten master password, if at least `t` holders come together | each share with a different trusted person, never two in one place |

Notes:

- **The backup and the `.sezam-key` open with the password that was valid when they were created.** After changing the password (`sezam change-password`) create both again and destroy the old ones. If you change the password because it leaked, also destroy the snapshots from before the change (`<vault>/snapshots/`).
- Shares are shown **only once**. Copy them by hand or print them on an offline computer; do not photograph them with a phone and do not send them by e-mail.
- `sezam export --format csv|bitwarden` writes passwords as **plain text**. It does not belong in the emergency kit. If you really need it for a migration, keep it only on an encrypted medium and delete it right after use.
- None of the items in this table is on the server. The server is only sync, not a backup.

## 2. What Sezam does on its own

- **Automatic snapshots.** Before every risky operation (password change, KDF upgrade, org recovery, re-key, import, connecting to a server, full resync, reseed) a copy of the vault is saved to `<vault>/snapshots/`. The last 20 are kept. `sezam snapshot list` shows them and `sezam snapshot restore <name>` goes back (it asks for the password valid at the time of the snapshot). Details are in [TECHNICKA_DOKUMENTACIA.md §16.5](TECHNICKA_DOKUMENTACIA.md) (Slovak).
- Snapshots live **on the same disk** as the vault. They protect against a mistake in the vault, not against losing the device or having it stolen. That is what the offline backup is for.

## 3. What to do when…

**…sync is stuck or something is "waiting for the server":**
`sezam status` lists everything the vault is holding for the server: a server that went back to an older state (restored from a backup; sync stops until `sezam pull --full-resync`, and `sezam push` warns the same way), an unsent password change, a re-key after removing a member, the queue of removed members, conflicts and an unregistered recovery key. Each item shows the command that resolves it (`resolve`) and the command that drops it without a forgotten password (`drop`). Handle the items in the order they are listed.

**…the vault is broken or an operation went wrong** (e.g. a bad import):
`sezam snapshot list` → `sezam snapshot restore <name>`. From the backup on USB: `sezam restore <file>` (password valid at the time of the backup; the current state is kept as the snapshot `pre-restore`).

**…you lost your laptop and the server is running:**
on the new device run `sezam init --server <URL>` with the same user name and master password. The account is restored from the server and the data is downloaded.

**…you lost both the laptop and the server** (or never had a server):
copy the backup as `sezam.db` into an empty directory, set `SEZAM_VAULT=<directory>` and unlock it with the password valid at the time of the backup (`sezam unlock`, `sezam list`).

**…the server lost its database, but you have the vault (or a backup):**
on an empty server run `sezam server reseed [URL]`. The server gets back the same account (same `user_id`, keys and key epoch) and all your objects. The account's other devices then report a possible server rollback. Once you have checked that the reseed was yours, sync them with `sezam pull --full-resync`. Other team members join again with an invitation. Details are in [TECHNICKA_DOKUMENTACIA.md §16.6](TECHNICKA_DOKUMENTACIA.md) (Slovak).

**…you forgot your master password:**
get together with at least `t` share holders, run `sezam org-recovery` and paste each share (`<index>:<hex>`) into the prompt (it is not echoed); an empty line ends the input. Never pass shares as a command argument: they would stay in the shell history and the process list, and `sezam` does not accept them that way. Set a new password, then create a new backup, a new `.sezam-key` and, if needed, new shares. If the vault is connected to a server, the next `sezam push` gives the server the new password: the change is signed by the recovery key rebuilt from the shares, so neither the old password nor another admin is needed (a single admin is enough). This requires that the server has registered the recovery key (the setup or a later `sezam connect` reports "The server knows this … recovery"). A setup on a vault that is not connected waits for `sezam connect`; if the vault took over the key of an existing account when connecting, connect warns that the server does not know the recovery. The server does not know such shares: repeat `sezam org-recovery-setup --replace` while you still know the password. `sezam push` and unlocking in the desktop app warn the same way, for example for shares set up by an older version. A replacement that the server refuses changes nothing and the old shares stay valid. Otherwise, after recovery the server will need `sezam allow-key-reset` from another admin. The server keeps one org recovery: if another admin set it up, the setup does not replace it without `--replace-other-admin` (their shares would stop working), and that admin then allows recovery of your password with `sezam allow-key-reset`. A recovery set up on the web or another device is replaced by the setup only with `--replace`.

## 4. Quarterly test restore

Once a quarter (e.g. the first Monday of January, April, July and October) test the recovery on a **clean device**: a new user account, a virtual machine or a borrowed computer without your usual vault. It takes about 15 minutes.

1. **Is your backup current?** On your usual device run `sezam export <USB>/sezam-backup-<date>.db --format backup` and put it in the kit. If you changed the password since the last test, also run `sezam export-key` again.
2. **On the clean device** install Sezam and copy the backup as `sezam.db` into an empty directory. Set `SEZAM_VAULT` to that directory.
3. **Unlock** the backup (`sezam unlock`) with the password from the kit and check that `sezam list` shows your folders and that `sezam get` returns at least one password you know.
4. **Check the `.sezam-key`:** `sezam import-key <file> --path <another empty directory>` must accept the password and create a vault. Compare the printed `Fingerprint` with the one printed by `sezam init` that you wrote down in the kit.
5. **Reseed** (if you use a server): start an empty test server and try `sezam server reseed <test server URL>` on the copy of the vault from step 2. Do not use your production server for this.
6. **Shamir shares** (if you have them): ask the holders whether they still have their share and can find it. Do not have the share itself sent to you.
7. **Clean up:** on the clean device delete the directories from steps 2–5 and log out. Write the date and the result of the test into the kit.

If any step fails, fix it right away: with a new backup, a new `.sezam-key` or new shares (`sezam org-recovery-setup`).
