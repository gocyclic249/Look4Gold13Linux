#!/usr/bin/env bash
# lib/tavily.sh — Tavily Search API module with security-focused dork queries
# Dork groups are loaded from .config/dorks.conf by load_dorks() in common.sh.

tavily_search() {
    local keyword="$1"

    if [[ -z "${TAVILY_API_KEY:-}" ]]; then
        log_warn "TAVILY_API_KEY not set, skipping Tavily Search"
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would call Tavily Search API for: $keyword"
        return 0
    fi

    local dork_mode="${DORK_MODE:-security}"

    if [[ "$dork_mode" == "raw" ]]; then
        _tavily_query "$keyword" "$keyword" "raw"
    else
        log_info "Tavily Search: running security dorks for '$keyword'"

        local group_idx=0
        for group in "${_DISCLOSURE_DORK_GROUPS[@]}"; do
            group_idx=$((group_idx + 1))
            local query="\"${keyword}\" (${group})"
            _tavily_query "$keyword" "$query" "disclosure_${group_idx}"
        done

        for group in "${_BREACH_DORK_GROUPS[@]}"; do
            group_idx=$((group_idx + 1))
            local query="\"${keyword}\" ${group}"
            _tavily_query "$keyword" "$query" "breach_${group_idx}"
        done
    fi
}

# Internal: execute a single Tavily Search API call
_tavily_query() {
    local keyword="$1"
    local query="$2"
    local dork_label="$3"
    local event_type="${4:-SEARCH_WEB}"
    local source_name="${5:-tavily_search}"

    local count="${SEARCH_RESULT_COUNT:-10}"
    local days_back="${SEARCH_DAYS_BACK:-7}"

    log_debug "Tavily Search: query='$query' (dork: $dork_label)"

    # Map SEARCH_DAYS_BACK to Tavily time_range parameter
    local time_range="week"
    if (( days_back <= 1 )); then
        time_range="day"
    elif (( days_back <= 7 )); then
        time_range="week"
    elif (( days_back <= 30 )); then
        time_range="month"
    else
        time_range="year"
    fi

    # Build request body
    local request_body
    request_body=$(jq -nc \
        --arg q "$query" \
        --argjson max "$count" \
        --arg depth "${TAVILY_SEARCH_DEPTH:-basic}" \
        --arg tr "$time_range" \
        '{
            query: $q,
            max_results: $max,
            search_depth: $depth,
            time_range: $tr,
            include_answer: false,
            include_raw_content: false
        }')

    local response http_code body
    response=$(echo "$request_body" | curl -s -w "\n%{http_code}" \
        -X POST \
        --proto =https \
        --max-time 30 --max-redirs 5 \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TAVILY_API_KEY" \
        -d @- \
        "https://api.tavily.com/search" \
        2>/dev/null)

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" -ne 200 ]]; then
        log_error "Tavily Search API returned HTTP $http_code for '$keyword' (dork: $dork_label)"
        emit_audit_record "$event_type" "$source_name" "$keyword" "error" "info" \
            "Tavily Search API error: HTTP $http_code (dork: $dork_label)" \
            "$(jq -nc --arg code "$http_code" --arg dork "$dork_label" '{http_code: $code, dork_group: $dork}')"
        return 1
    fi

    local result_count
    result_count=$(echo "$body" | jq -r '.results | length // 0' 2>/dev/null)

    if [[ "$result_count" -eq 0 ]]; then
        log_debug "Tavily Search: no results for '$keyword' (dork: $dork_label)"
        return 0
    fi

    log_info "Tavily Search: $result_count result(s) for '$keyword' (dork: $dork_label)"

    local i title url description score
    for (( i=0; i<result_count; i++ )); do
        title=$(echo "$body" | jq -r ".results[$i].title // \"\"" 2>/dev/null)
        url=$(echo "$body" | jq -r ".results[$i].url // \"\"" 2>/dev/null)
        description=$(echo "$body" | jq -r ".results[$i].content // \"\"" 2>/dev/null)
        score=$(echo "$body" | jq -r ".results[$i].score // 0" 2>/dev/null)

        local details
        details=$(jq -nc \
            --arg t "$title" \
            --arg u "$url" \
            --arg d "$description" \
            --arg dork "$dork_label" \
            --argjson idx "$i" \
            --argjson sc "$score" \
            '{title: $t, url: $u, description: $d, dork_group: $dork, result_index: $idx, relevance_score: $sc}')

        emit_audit_record "$event_type" "$source_name" "$keyword" "found" "low" \
            "Web result: $title" "$details"
    done
}
