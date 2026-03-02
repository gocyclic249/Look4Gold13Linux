#!/usr/bin/env bats
# test/bats/audit.bats - Tests for lib/audit.sh functions

setup() {
  export SCRIPT_DIR="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  export CONFIG_DIR="${BATS_TMPDIR}/config"
  mkdir -p "$CONFIG_DIR"
  source "${SCRIPT_DIR}/lib/common.sh"
  source "${SCRIPT_DIR}/lib/audit.sh"
  export AUDIT_OUTPUT_FILE="${BATS_TMPDIR}/audit.jsonl"
  touch "$AUDIT_OUTPUT_FILE"
}

teardown() {
  rm -rf "$CONFIG_DIR" "$AUDIT_OUTPUT_FILE"
}

@test "emit_audit_record creates valid JSON" {
  emit_audit_record "TEST_EVENT" "test_source" "test_keyword" "found" "low" "Test desc" '{"test": "data"}'
  run jq -e '.event_type == "TEST_EVENT"' "$AUDIT_OUTPUT_FILE"
  [ "$status" -eq 0 ]
}

@test "start_scan_record emits scan start" {
  start_scan_record 2
  run jq -e '.event_type == "SCAN_START"' "$AUDIT_OUTPUT_FILE"
  [ "$status" -eq 0 ]
}

@test "end_scan_record emits scan end" {
  end_scan_record
  run jq -e '.event_type == "SCAN_END"' "$AUDIT_OUTPUT_FILE"
  [ "$status" -eq 0 ]
}