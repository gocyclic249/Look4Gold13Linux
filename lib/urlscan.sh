#!/usr/bin/env bash
# lib/urlscan.sh — URLScan.io search source (brand / phishing page monitoring).
# Emits CHECK_PHISH records; standalone-semantics (rendered like OTX/NIST).

urlscan_search() {
    local keyword="$1"
    [[ -n "$keyword" ]] || { log_error "urlscan_search: keyword argument is required"; return 1; }

    if [[ -z "${URLSCAN_API_KEY:-}" ]]; then
        log_warn "URLSCAN_API_KEY not set, skipping URLScan.io search"
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would call URLScan.io for: $keyword"
        return 0
    fi

    local count="${SEARCH_RESULT_COUNT:-10}"
    local encoded
    encoded="$(url_encode "$keyword")"
    local url="https://urlscan.io/api/v1/search/?q=${encoded}&size=${count}"

    log_info "URLScan.io: querying '$keyword'"

    local -a _us_hdrs=(-H "API-Key: $URLSCAN_API_KEY" -H "Accept: application/json")
    local response http_code body
    response="$(http_request GET "$url" _us_hdrs)"
    http_code="$(echo "$response" | tail -n1)"
    body="$(echo "$response" | sed '$d')"

    if [[ "$http_code" -ne 200 ]]; then
        log_error "URLScan.io returned HTTP $http_code for '$keyword'"
        emit_audit_record "CHECK_PHISH" "urlscan" "$keyword" "error" "info" \
            "URLScan.io API error: HTTP $http_code" \
            "$(jq -nc --arg code "$http_code" '{http_code: $code}')"
        return 1
    fi

    local rcount
    # jq returns non-zero on invalid JSON; suppress stderr and default to 0 so
    # a malformed response falls through to the not_found path rather than aborting.
    rcount="$(echo "$body" | jq '.results | length' 2>/dev/null || echo 0)"

    if [[ "$rcount" -eq 0 ]]; then
        log_info "URLScan.io: no results for '$keyword'"
        emit_audit_record "CHECK_PHISH" "urlscan" "$keyword" "not_found" "info" \
            "No URLScan.io results for keyword" "null"
        return 0
    fi

    log_info "URLScan.io: $rcount result(s) for '$keyword'"

    local i page_url page_domain scan_time result_uuid malicious severity details
    for (( i=0; i<rcount; i++ )); do
        page_url="$(echo "$body" | jq -r ".results[$i].page.url // \"\"")"
        page_domain="$(echo "$body" | jq -r ".results[$i].page.domain // \"\"")"
        scan_time="$(echo "$body" | jq -r ".results[$i].task.time // \"\"")"
        result_uuid="$(echo "$body" | jq -r ".results[$i]._id // \"\"")"
        # verdicts.overall.malicious may be absent; suppress jq stderr for missing
        # keys and default to false so severity stays low when the field is omitted.
        malicious="$(echo "$body" | jq -r ".results[$i].verdicts.overall.malicious // false" 2>/dev/null || echo false)"
        severity="low"
        [[ "$malicious" == "true" ]] && severity="medium"
        details="$(jq -nc \
            --arg u "$page_url" --arg d "$page_domain" --arg t "$scan_time" \
            --arg id "$result_uuid" --argjson m "${malicious:-false}" \
            '{url: $u, page_domain: $d, scan_time: $t, result_uuid: $id, malicious: $m}')"
        emit_audit_record "CHECK_PHISH" "urlscan" "$keyword" "found" "$severity" \
            "URLScan result: ${page_url}" "$details"
    done
}
