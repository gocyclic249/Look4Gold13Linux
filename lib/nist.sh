#!/usr/bin/env bash
# lib/nist.sh — NIST NVD API module

nist_search() {
    local keyword="$1"

    if [[ -z "${NIST_API_KEY:-}" ]]; then
        log_warn "NIST_API_KEY not set, skipping NIST NVD search"
        return 0
    fi

    local encoded_keyword
    encoded_keyword="$(url_encode "$keyword")"

    log_info "NIST NVD: querying '$keyword'"

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would call NIST NVD API for: $keyword"
        return 0
    fi

    local response http_code body
    response=$(curl -s -w "\n%{http_code}" \
        -H "apiKey: $NIST_API_KEY" \
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encoded_keyword}" \
        2>/dev/null)

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

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

        # Map CVSS score to severity
        if (( $(echo "$base_score >= 9.0" | bc -l 2>/dev/null || echo 0) )); then
            severity="critical"
        elif (( $(echo "$base_score >= 7.0" | bc -l 2>/dev/null || echo 0) )); then
            severity="high"
        elif (( $(echo "$base_score >= 4.0" | bc -l 2>/dev/null || echo 0) )); then
            severity="medium"
        else
            severity="low"
        fi

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
