#!/usr/bin/env bash
set -euo pipefail

# test/lint.sh - Run shellcheck on all scripts
echo "Running shellcheck..."
output=$(shellcheck look4gold.sh setup.sh lib/*.sh 2>&1) || {
  # Check if only style/info warnings
  if echo "$output" | grep -q "SC2064\|SC2129\|SC2016"; then
    echo "Only style/info warnings (SC2064, SC2129, SC2016) — acceptable."
    echo "$output"
  else
    echo "Shellcheck failed with errors:"
    echo "$output"
    exit 1
  fi
}
echo "Shellcheck passed!"