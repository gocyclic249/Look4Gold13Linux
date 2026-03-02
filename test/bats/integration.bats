#!/usr/bin/env bats
# test/bats/integration.bats - Integration tests

setup() {
  export SCRIPT_DIR="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  export CONFIG_DIR="${BATS_TMPDIR}/config"
  mkdir -p "$CONFIG_DIR"
  # Copy test fixtures
  cp "${SCRIPT_DIR}/test/fixtures/settings.conf" "$CONFIG_DIR/"
  cp "${SCRIPT_DIR}/test/fixtures/keywords.conf" "$CONFIG_DIR/"
  cp "${SCRIPT_DIR}/test/fixtures/dorks.conf" "$CONFIG_DIR/"
  # Mock APIs
  echo "BRAVE_API_KEY=fake" > "$CONFIG_DIR/apis.conf"
  echo "TAVILY_API_KEY=fake" >> "$CONFIG_DIR/apis.conf"
  echo "XAI_API_KEY=fake" >> "$CONFIG_DIR/apis.conf"
}

teardown() {
  rm -rf "$CONFIG_DIR"
}

@test "dry-run loads config without API calls" {
  # Run dry-run in subshell to avoid affecting globals
  run bash -c "cd '$SCRIPT_DIR' && ./look4gold.sh --dry-run --silent"
  [ "$status" -eq 0 ]
}