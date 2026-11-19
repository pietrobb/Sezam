#!/bin/bash
# Root/sshd tests the gates skip, in a throwaway container (R9-I, goal #365).
# Usage: docker run --rm -v <repo>:/repo:ro python:3.11 bash /repo/scripts/ci_linux_sshd.sh
set -e
apt-get update -qq >/dev/null && apt-get install -y -qq openssh-server openssh-client sudo >/dev/null
mkdir -p /run/sshd
git config --global --add safe.directory /repo
mkdir -p /src
cd /repo
git ls-files -z --cached --others --exclude-standard \
  | grep -zEv '^(\.worktrees|\.playwright-mcp|img|\.claude)/|^mobile/|\.exe$' \
  | while IFS= read -r -d '' f; do [ -e "$f" ] && cp --parents "$f" /src; done
cd /src
command -v cargo >/dev/null || { curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null; export PATH="$HOME/.cargo/bin:$PATH"; }
# The sync core from its source first: the name sezam-sync-core is not ours on PyPI.
python -m pip install -q ./core/py 2>&1 | tail -n 3
python -m pip install -q -e ".[dev,import]" 2>&1 | tail -n 3
export SEZAM_TEST_HOST_SETUP=1 SEZAM_REQUIRE_HOST_SETUP=1
python -m pytest -q -rs -p no:cacheprovider \
  tests/test_review7_terminate_remote_openssh.py tests/test_ai_s3b_host_setup.py tests/test_ai_s3a_ssh_ca.py \
  2>&1 | grep -E "^(FAILED|ERROR|SKIPPED|E  )|passed|failed|error" | tail -n 40
