#!/bin/bash
# The GitHub workflow's python and mobile jobs (.github/workflows/tests.yml), run
# locally on Linux when the hosted runners are unavailable (R10-A, goal #371).
# MariaDB: any reachable 10.11 server, e.g. the sezam-maria container.
# Usage: docker run --rm -v <repo>:/repo:ro -v sezam-ci-tools:/opt/tools \
#          -e SEZAM_TEST_MARIADB=root:sezamtest@host.docker.internal:33061 \
#          python:3.11 bash /repo/scripts/ci_linux_full.sh
set -eo pipefail
export DEBIAN_FRONTEND=noninteractive QT_QPA_PLATFORM=offscreen
export SEZAM_REQUIRE_MARIADB=1 SEZAM_REQUIRE_FLUTTER=1 CI=true
apt-get update -qq >/dev/null
apt-get install -y -qq xz-utils unzip libegl1 libgl1 libxkbcommon0 libfontconfig1 libdbus-1-3 \
  libsodium-dev libsqlite3-dev sudo openssh-client >/dev/null
mkdir -p /opt/tools
if [ ! -x /opt/tools/node/bin/node ]; then
  f=$(curl -fsSL https://nodejs.org/dist/latest-v24.x/SHASUMS256.txt | grep -oE 'node-v[0-9.]+-linux-x64\.tar\.xz' | head -n1)
  curl -fsSL "https://nodejs.org/dist/latest-v24.x/$f" | tar -xJ -C /opt/tools
  mv /opt/tools/node-v*-linux-x64 /opt/tools/node
fi
if [ ! -x /opt/tools/flutter/bin/flutter ]; then
  curl -fsSL https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.38.6-stable.tar.xz \
    | tar -xJ -C /opt/tools
fi
export PATH=/opt/tools/node/bin:/opt/tools/flutter/bin:$PATH
git config --global --add safe.directory '*'
mkdir -p /src
cd /repo
# Tracked files only, as a CI checkout: untracked local files (deploy scripts
# with the production address) would fail test_open_source_hygiene.
git ls-files -z --cached \
  | grep -zEv '^(\.worktrees|\.playwright-mcp|img|\.claude)/|\.exe$' \
  | while IFS= read -r -d '' f; do [ -e "$f" ] && cp --parents "$f" /src; done
cd /src && git init -q && git add -A >/dev/null && git -c user.email=ci@local -c user.name=ci commit -qm ci
node --version && flutter --version | head -n1
echo "== mobile job"
(cd mobile && flutter pub get >/dev/null && flutter analyze --no-fatal-infos && flutter test --reporter expanded 2>&1 | tail -n 40)
echo "== python job"
command -v cargo >/dev/null || { curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null; export PATH="$HOME/.cargo/bin:$PATH"; }
# The sync core from its source first: PyPI only holds an empty sezam-sync-core name reservation.
python -m pip install -q ./core/py 2>&1 | tail -n 3
python -m pip install -q -e ".[dev,import,gui]" pytest-qt==4.5.0 2>&1 | tail -n 3
python -m ruff check
git ls-files 'web/*.js' ':!:web/static/js/vendor/*' | xargs -n1 node --check
python -m pytest -q -p no:cacheprovider ${PYTEST_ARGS} 2>&1 | grep -E "^(FAILED|ERROR)|passed|failed|error" | tail -n 60
