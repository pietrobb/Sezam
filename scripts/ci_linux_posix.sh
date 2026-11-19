#!/bin/bash
# The tests a Windows gate skips as POSIX-only, run on Linux (R9-I, goal #365).
# Usage: docker run --rm -v <repo>:/repo:ro python:3.11 bash /repo/scripts/ci_linux_posix.sh
set -e
apt-get update -qq >/dev/null && apt-get install -y -qq nodejs sudo openssh-client >/dev/null
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
python -m pytest -q -rs -p no:cacheprovider \
  tests/test_ai_p8_local_ipc.py tests/test_ai_s1b_control.py tests/test_ai_s4b_broker_service.py \
  tests/test_review6_vault_permissions.py tests/test_review_cli_mcp_medium.py tests/test_ai_s4a_hardening.py \
  tests/test_review_cli_ipc.py tests/test_review8_mcp_concurrent_clients.py tests/test_ai_s3b_host_setup.py \
  tests/test_ai_r2_snapshot_cli.py tests/test_review6_sudoers_escape.py tests/test_ai_s3a_ssh_ca.py \
  tests/test_review9_ai_brake_accept.py tests/test_review9_ai_dispatch_concurrency.py \
  2>&1 | grep -E "^(FAILED|ERROR|SKIPPED)|passed|failed|error" | tail -n 40
