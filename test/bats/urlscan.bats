#!/usr/bin/env bats
load helpers

setup() {
    load_common
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/audit.sh"
    export AUDIT_OUTPUT_FILE="$BATS_TEST_TMPDIR/out.jsonl"
    : > "$AUDIT_OUTPUT_FILE"
    _SCAN_ID="test-scan"; _FINDING_COUNT=0; _RECORD_COUNT=0
    export URLSCAN_API_KEY="x" DRY_RUN=false
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/urlscan.sh"
}

@test "emits CHECK_PHISH and raises severity on malicious verdict" {
    http_request() { printf '%s\n200' '{"results":[{"page":{"url":"https://acme-login.test/","domain":"acme-login.test"},"task":{"time":"2026-06-01T00:00:00Z"},"_id":"abc","verdicts":{"overall":{"malicious":true}}}]}'; }
    urlscan_search "acme" || true
    run jq -rs '.[0].event_type' "$AUDIT_OUTPUT_FILE"
    [ "$output" = "CHECK_PHISH" ]
    run jq -rs '.[0].severity' "$AUDIT_OUTPUT_FILE"
    [ "$output" = "medium" ]
}

@test "non-malicious result is low severity" {
    http_request() { printf '%s\n200' '{"results":[{"page":{"url":"https://acme.test/","domain":"acme.test"},"task":{"time":"t"},"_id":"z"}]}'; }
    urlscan_search "acme" || true
    run jq -rs '.[0].severity' "$AUDIT_OUTPUT_FILE"
    [ "$output" = "low" ]
}

@test "emits not_found on empty results" {
    http_request() { printf '%s\n200' '{"results":[]}'; }
    urlscan_search "acme" || true
    run jq -s '[.[] | select(.outcome=="not_found")] | length' "$AUDIT_OUTPUT_FILE"
    [ "$output" -eq 1 ]
}

@test "skips when key unset" {
    unset URLSCAN_API_KEY
    http_request() { printf '%s\n200' '{"results":[{"page":{"url":"x"}}]}'; }
    urlscan_search "acme" || true
    [ ! -s "$AUDIT_OUTPUT_FILE" ]
}
