#!/usr/bin/env bash
# lib/otx.sh — AlienVault OTX API module

otx_search() {
    local keyword="$1"

    if [[ -z "${OTX_API_KEY:-}" ]]; then
        log_warn "OTX_API_KEY not set, skipping OTX search"
        return 0
    fi

    local encoded_keyword
    encoded_keyword="$(url_encode "$keyword")"

    log_info "OTX: querying '$keyword'"

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would call OTX API for: $keyword"
        return 0
    fi

    local response http_code body
    response=$(curl -s -w "\n%{http_code}" \
        -H "X-OTX-API-KEY: $OTX_API_KEY" \
        "https://otx.alienvault.com/api/v1/search/pulses?q=${encoded_keyword}" \
        2>/dev/null)

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" -ne 200 ]]; then
        log_error "OTX API returned HTTP $http_code for '$keyword'"
        emit_audit_record "CHECK_THREAT" "otx" "$keyword" "error" "info" \
            "OTX API error: HTTP $http_code" \
            "$(jq -nc --arg code "$http_code" '{http_code: $code}')"
        return 1
    fi

    local pulse_count
    pulse_count=$(echo "$body" | jq '.results | length // 0' 2>/dev/null)

    if [[ "$pulse_count" -eq 0 ]]; then
        log_info "OTX: no pulses for '$keyword'"
        emit_audit_record "CHECK_THREAT" "otx" "$keyword" "not_found" "info" \
            "No threat intel pulses found for keyword" "null"
        return 0
    fi

    log_info "OTX: $pulse_count pulse(s) for '$keyword'"

    local i pulse_id name description tags indicator_count
    for (( i=0; i<pulse_count; i++ )); do
        pulse_id=$(echo "$body" | jq -r ".results[$i].id // \"\"" 2>/dev/null)
        name=$(echo "$body" | jq -r ".results[$i].name // \"\"" 2>/dev/null)
        description=$(echo "$body" | jq -r ".results[$i].description // \"\"" 2>/dev/null)
        tags=$(echo "$body" | jq -c ".results[$i].tags // []" 2>/dev/null)
        indicator_count=$(echo "$body" | jq -r ".results[$i].indicator_count // 0" 2>/dev/null)

        # Truncate long descriptions
        if [[ ${#description} -gt 500 ]]; then
            description="${description:0:500}..."
        fi

        local severity="medium"
        if (( indicator_count > 50 )); then
            severity="high"
        elif (( indicator_count > 10 )); then
            severity="medium"
        else
            severity="low"
        fi

        local details
        details=$(jq -nc \
            --arg id "$pulse_id" \
            --arg n "$name" \
            --arg d "$description" \
            --argjson t "$tags" \
            --argjson ic "$indicator_count" \
            '{pulse_id: $id, pulse_name: $n, pulse_description: $d, tags: $t, indicator_count: $ic}')

        emit_audit_record "CHECK_THREAT" "otx" "$keyword" "found" "$severity" \
            "Threat intel pulse: $name ($indicator_count indicators)" "$details"
    done
}
