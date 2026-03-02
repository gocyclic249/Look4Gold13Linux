#!/usr/bin/env bats
# test/bats/common.bats - Tests for lib/common.sh functions

setup() {
  # Mock SCRIPT_DIR and CONFIG_DIR for tests
  export SCRIPT_DIR="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  export CONFIG_DIR="${BATS_TMPDIR}/config"
  mkdir -p "$CONFIG_DIR"
  source "${SCRIPT_DIR}/lib/common.sh"
}

teardown() {
  rm -rf "$CONFIG_DIR"
}

@test "check_deps succeeds when curl and jq available" {
  command -v curl >/dev/null || skip "curl not available"
  command -v jq >/dev/null || skip "jq not available"
  run check_deps
  [ "$status" -eq 0 ]
}

@test "load_keywords loads valid keywords" {
  echo "test1" > "$CONFIG_DIR/keywords.conf"
  echo "# comment" >> "$CONFIG_DIR/keywords.conf"
  echo "test2" >> "$CONFIG_DIR/keywords.conf"

  load_keywords
  [ "${#KEYWORDS[@]}" -eq 2 ]
  [ "${KEYWORDS[0]}" = "test1" ]
  [ "${KEYWORDS[1]}" = "test2" ]
}

@test "load_keywords fails on empty file" {
  cp test/fixtures/keywords-empty.conf "$CONFIG_DIR/keywords.conf"
  run load_keywords
  [ "$status" -eq 1 ]
}

@test "log_debug does not output when level too low" {
  _CURRENT_LOG_LEVEL=2  # WARN
  run log_debug "test"
  [ -z "$output" ]
}

@test "log_info outputs when level allows" {
  _CURRENT_LOG_LEVEL=1  # INFO
  run log_info "test message"
  [[ "$output" =~ "test message" ]]
}