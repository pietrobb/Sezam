# Contributing to Sezam

Thank you for your interest. Sezam is alpha software and a password manager,
so changes are reviewed carefully. Small, focused pull requests with tests are
the easiest to accept.

## Before you start

- **Security problems:** do not open a public issue or pull request. Report
  them privately as described in [SECURITY.md](SECURITY.md).
- **Larger changes:** open an issue first and describe what you want to change
  and why. Changes to the vault format, the sync protocol, the team log or the
  cryptography must stay compatible across all three clients (desktop/CLI,
  web, mobile) and need a discussion before code.
- **Language:** code, comments, commit messages, issues and pull requests are
  in English. Most of the long-form documentation in `docs/` is in Slovak;
  translations are welcome.

## Development setup

```
git clone https://github.com/pietrobb/Sezam.git
cd Sezam
python -m pip install ./core/py   # the shared sync core (needs Rust)
python -m pip install -e ".[dev,import,gui]" pytest-qt
```

Mobile app: install Flutter (and Rust, for the shared sync core), then see
[mobile/README.md](mobile/README.md).

## Checks to run before a pull request

```
python -m ruff check
python -m pytest -q
cd mobile && flutter analyze && flutter test
```

Server tests that need real row locks run against MariaDB when
`SEZAM_TEST_MARIADB=user:password@host:port` is set. CI runs all of these on
every pull request.

## Pull requests

- One topic per pull request. Describe what changed and why.
- Every bug fix comes with a regression test that fails without the fix.
- Every new command, option or behavior comes with a test and, where users
  see it, an update of the documentation.
- Do not commit secrets, real vaults, server addresses or personal data, not
  even in tests. Use clearly fake values.

## Contributor License Agreement

Before your first pull request can be merged you need to sign the
[Contributor License Agreement](CLA.md). You keep the copyright to your work.
The agreement lets the project distribute your contribution under the AGPL
and also under other terms, for example in the Apple App Store.

Signing takes one step: comment on your pull request with exactly this
sentence:

```
I have read the CLA Document and I hereby sign the CLA
```

The CLA bot records your signature and you never have to sign again. The bot
only acts on these comments on a pull request; to see whether you have already
signed, comment `recheck`.

## License

By contributing you agree that your contributions are licensed under the
[GNU Affero General Public License v3.0](LICENSE) and under the terms of the
[Contributor License Agreement](CLA.md).
