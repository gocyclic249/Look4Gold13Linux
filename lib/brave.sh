#!/usr/bin/env bash
# lib/brave.sh — Brave Search API module

brave_search() {
    local keyword="$1"

    if [[ -z "${BRAVE_API_KEY:-}" ]]; then
        log_warn "BRAVE_API_KEY not set, skipping Brave Search"
        return 0
    fi

    local encoded_keyword
    encoded_keyword="$(url_encode "$keyword")"
    local count="${SEARCH_RESULT_COUNT:-10}"
    local days_back="${SEARCH_DAYS_BACK:-7}"

    log_info "Brave Search: querying '$keyword' (last ${days_back} days)"

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would call Brave Search API for: $keyword"
        return 0
    fi

    # Brave freshness parameter: pd=past day, pw=past week, pm=past month, py=past year
    # or custom range YYYY-MM-DDtoYYYY-MM-DD
    local from_date to_date freshness_param
    to_date="$(date -u '+%Y-%m-%d')"
    from_date="$(date -u -d "${days_back} days ago" '+%Y-%m-%d')"
    freshness_param="${from_date}to${to_date}"

    local response http_code body
    response=$(curl -s -w "\n%{http_code}" \
        -H "Accept: application/json" \
        -H "Accept-Encoding: gzip" \
        -H "X-Subscription-Token: $BRAVE_API_KEY" \
        "https://api.search.brave.com/res/v1/web/search?q=${encoded_keyword}&count=${count}&freshness=${freshness_param}" \
        --compressed 2>/dev/null)

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" -ne 200 ]]; then
        log_error "Brave Search API returned HTTP $http_code for '$keyword'"
        emit_audit_record "SEARCH_WEB" "brave_search" "$keyword" "error" "info" \
            "Brave Search API error: HTTP $http_code" \
            "$(jq -nc --arg code "$http_code" '{http_code: $code}')"
        return 1
    fi

    local result_count
    result_count=$(echo "$body" | jq -r '.web.results | length // 0' 2>/dev/null)

    if [[ "$result_count" -eq 0 ]]; then
        log_info "Brave Search: no results for '$keyword'"
        emit_audit_record "SEARCH_WEB" "brave_search" "$keyword" "not_found" "info" \
            "No web results found for keyword" "null"
        return 0
    fi

    log_info "Brave Search: $result_count result(s) for '$keyword'"

    local i title url description
    for (( i=0; i<result_count; i++ )); do
        title=$(echo "$body" | jq -r ".web.results[$i].title // \"\"" 2>/dev/null)
        url=$(echo "$body" | jq -r ".web.results[$i].url // \"\"" 2>/dev/null)
        description=$(echo "$body" | jq -r ".web.results[$i].description // \"\"" 2>/dev/null)

        local details
        details=$(jq -nc \
            --arg t "$title" \
            --arg u "$url" \
            --arg d "$description" \
            --argjson idx "$i" \
            '{title: $t, url: $u, description: $d, result_index: $idx}')

        emit_audit_record "SEARCH_WEB" "brave_search" "$keyword" "found" "low" \
            "Web result: $title" "$details"
    done
}
