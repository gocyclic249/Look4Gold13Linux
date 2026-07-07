#!/usr/bin/env bats
load helpers

setup() {
    load_common
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/audit.sh"
    export AUDIT_OUTPUT_FILE="$BATS_TEST_TMPDIR/out.jsonl"
    : > "$AUDIT_OUTPUT_FILE"
    _SCAN_ID="test-scan"; _FINDING_COUNT=0; _RECORD_COUNT=0
    export GITHUB_TOKEN="x" DRY_RUN=false
    unset GITHUB_ORGS
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/github.sh"
}

@test "emits a SEARCH_CODE record per item" {
    http_request() { printf '%s\n200' '{"total_count":1,"items":[{"repository":{"full_name":"acme/leak"},"path":"cfg/secrets.env","html_url":"https://github.com/acme/leak/blob/main/cfg/secrets.env","text_matches":[{"fragment":"API_KEY=abc"}]}]}'; }
    github_search "acme" || true
    run jq -s '[.[] | select(.event_type=="SEARCH_CODE" and .outcome=="found")] | length' "$AUDIT_OUTPUT_FILE"
    [ "$output" -eq 1 ]
    run jq -rs '.[0].details.html_url' "$AUDIT_OUTPUT_FILE"
    [ "$output" = "https://github.com/acme/leak/blob/main/cfg/secrets.env" ]
}

@test "runs an extra org-scoped pass when GITHUB_ORGS set" {
    export GITHUB_ORGS="acme-corp, acme-labs"
    _github_query() { echo "CALL:$3" >> "$BATS_TEST_TMPDIR/calls.log"; }
    github_search "acme" || true
    run cat "$BATS_TEST_TMPDIR/calls.log"
    [[ "$output" == *"CALL:broad"* ]]
    [[ "$output" == *"CALL:org_acme-corp"* ]]
    [[ "$output" == *"CALL:org_acme-labs"* ]]
}

@test "422 is treated as no results (no error record)" {
    http_request() { printf '%s\n422' '{"message":"Validation Failed"}'; }
    github_search "acme" || true
    run jq -s 'length' "$AUDIT_OUTPUT_FILE"
    [ "$output" -eq 0 ]
}

@test "skips when token unset" {
    unset GITHUB_TOKEN
    http_request() { printf '%s\n200' '{"items":[{"html_url":"x"}]}'; }
    github_search "acme" || true
    [ ! -s "$AUDIT_OUTPUT_FILE" ]
}
