#!/usr/bin/env bash
# lib/nist.sh — NIST NVD API module

# Performs a single NVD request. Args: url, use_key (true|false).
# Echoes the raw response: body followed by a final line holding the HTTP
# status code (caller splits with tail -n1 / sed '$d').
_nist_request() {
    local url="$1"
    local use_key="$2"

    local -a _nist_hdrs=()
    if [[ "$use_key" == "true" && -n "${NIST_API_KEY:-}" ]]; then
        _nist_hdrs=(-H "apiKey: $NIST_API_KEY")
    fi
    http_request GET "$url" _nist_hdrs
}

# Map a CVSS base score to a severity band using jq (no calculator dependency).
_nist_severity() {
    local score="$1"
    local s="${score:-0}"
    if [[ "$(jq -n --argjson s "$s" '$s >= 9.0')" == "true" ]]; then
        printf 'critical'
    elif [[ "$(jq -n --argjson s "$s" '$s >= 7.0')" == "true" ]]; then
        printf 'high'
    elif [[ "$(jq -n --argjson s "$s" '$s >= 4.0')" == "true" ]]; then
        printf 'medium'
    else
        printf 'low'
    fi
}

nist_search() {
    local keyword="$1"

    if [[ -z "${NIST_API_KEY:-}" ]]; then
        log_warn "NIST_API_KEY not set, skipping NIST NVD search"
        return 0
    fi

    local encoded_keyword
    encoded_keyword="$(url_encode "$keyword")"
    local days_back="${SEARCH_DAYS_BACK:-7}"

    log_info "NIST NVD: querying '$keyword' (last ${days_back} days)"

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would call NIST NVD API for: $keyword"
        return 0
    fi

    # NVD API accepts pubStartDate/pubEndDate in ISO 8601 format
    local pub_start pub_end
    pub_end="$(date -u '+%Y-%m-%dT%H:%M:%S.000')"
    pub_start="$(date -u -d "${days_back} days ago" '+%Y-%m-%dT%H:%M:%S.000')"

    local url response body http_code
    url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encoded_keyword}&pubStartDate=${pub_start}&pubEndDate=${pub_end}"

    response=$(_nist_request "$url" "true")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    # NVD returns 404 (not 401/403) when the apiKey is invalid, expired, or
    # not yet activated. Detect that specific case, warn clearly, and retry
    # once unauthenticated (works but is rate-limited to ~5 req/30s).
    if [[ "$http_code" -eq 404 && -n "${NIST_API_KEY:-}" ]]; then
        log_warn "NIST NVD returned HTTP 404 with an API key set — the key is likely invalid, expired, or not yet activated (NVD uses 404 for bad keys, not 401/403). Retrying unauthenticated (rate-limited)."
        response=$(_nist_request "$url" "false")
        http_code=$(echo "$response" | tail -n1)
        body=$(echo "$response" | sed '$d')
    fi

    if [[ "$http_code" -ne 200 ]]; then
        log_error "NIST NVD API returned HTTP $http_code for '$keyword'"
        emit_audit_record "CHECK_CVE" "nist_nvd" "$keyword" "error" "info" \
            "NIST NVD API error: HTTP $http_code" \
            "$(jq -nc --arg code "$http_code" '{http_code: $code}')"
        return 1
    fi

    local total_results
    total_results=$(echo "$body" | jq -r '.totalResults // 0' 2>/dev/null)

    if [[ "$total_results" -eq 0 ]]; then
        log_info "NIST NVD: no CVEs for '$keyword'"
        emit_audit_record "CHECK_CVE" "nist_nvd" "$keyword" "not_found" "info" \
            "No CVEs found for keyword" "null"
        return 0
    fi

    log_info "NIST NVD: $total_results CVE(s) for '$keyword'"

    # Process each vulnerability (up to the returned set)
    local vuln_count
    vuln_count=$(echo "$body" | jq '.vulnerabilities | length' 2>/dev/null)

    local i cve_id cve_desc severity base_score
    for (( i=0; i<vuln_count; i++ )); do
        cve_id=$(echo "$body" | jq -r ".vulnerabilities[$i].cve.id // \"\"" 2>/dev/null)
        cve_desc=$(echo "$body" | jq -r ".vulnerabilities[$i].cve.descriptions[0].value // \"\"" 2>/dev/null)

        # Try CVSS 3.1 first, then 3.0, then 2.0
        base_score=$(echo "$body" | jq -r "
            .vulnerabilities[$i].cve.metrics.cvssMetricV31[0].cvssData.baseScore //
            .vulnerabilities[$i].cve.metrics.cvssMetricV30[0].cvssData.baseScore //
            .vulnerabilities[$i].cve.metrics.cvssMetricV2[0].cvssData.baseScore //
            0" 2>/dev/null)

        # Map CVSS score to severity using jq
        severity="$(_nist_severity "$base_score")"

        local details
        details=$(jq -nc \
            --arg id "$cve_id" \
            --arg desc "$cve_desc" \
            --argjson score "$base_score" \
            '{cve_id: $id, cve_description: $desc, cvss_base_score: $score}')

        emit_audit_record "CHECK_CVE" "nist_nvd" "$keyword" "found" "$severity" \
            "CVE found: $cve_id (CVSS: $base_score)" "$details"
    done
}
