#!/usr/bin/env bats
load helpers

setup() {
    load_common
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/audit.sh"
    export AUDIT_OUTPUT_FILE="$BATS_TEST_TMPDIR/out.jsonl"
    : > "$AUDIT_OUTPUT_FILE"
    _SCAN_ID="test-scan"; _FINDING_COUNT=0; _RECORD_COUNT=0
    export CRTSH_ENABLED=true DRY_RUN=false
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/crtsh.sh"
}

@test "emits one SEARCH_CERT record per unique domain" {
    http_request() { printf '%s\n200' '[{"name_value":"a.example.com\nexample.com","issuer_name":"CA","not_before":"2026-01-01","not_after":"2026-04-01","id":1},{"name_value":"a.example.com","issuer_name":"CA","not_before":"2026-02-01","not_after":"2026-05-01","id":2}]'; }
    crtsh_search "example" || true
    run jq -s '[.[] | select(.event_type=="SEARCH_CERT" and .outcome=="found")] | length' "$AUDIT_OUTPUT_FILE"
    [ "$output" -eq 2 ]
    run jq -rs '[.[] | select(.outcome=="found") | .details.domain] | sort | join(",")' "$AUDIT_OUTPUT_FILE"
    [ "$output" = "a.example.com,example.com" ]
    run jq -rs '[.[] | select(.outcome=="found") | select(.details.url != ("https://" + .details.domain))] | length' "$AUDIT_OUTPUT_FILE"
    [ "$output" -eq 0 ]
}

@test "emits not_found on empty array" {
    http_request() { printf '%s\n200' '[]'; }
    crtsh_search "example" || true
    run jq -s '[.[] | select(.outcome=="not_found")] | length' "$AUDIT_OUTPUT_FILE"
    [ "$output" -eq 1 ]
}

@test "skips when disabled" {
    export CRTSH_ENABLED=false
    http_request() { printf '%s\n200' '[{"name_value":"x.example.com"}]'; }
    crtsh_search "example" || true
    [ ! -s "$AUDIT_OUTPUT_FILE" ]
}

@test "skips when DRY_RUN=true" {
    export DRY_RUN=true
    http_request() { printf '%s\n200' '[{"name_value":"x.example.com"}]'; }
    crtsh_search "example" || true
    [ ! -s "$AUDIT_OUTPUT_FILE" ]
}
