#!/usr/bin/env bash
set -euo pipefail

# test/run_tests.sh - Run Bats tests
if ! command -v bats >/dev/null; then
  echo "bats not installed. Install with: sudo apt install bats"
  exit 1
fi
bats test/bats/

echo "All tests passed!"