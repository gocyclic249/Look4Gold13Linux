#!/usr/bin/env bash
# lib/tavily.sh — Tavily Search API module with security-focused dork queries
# Dork groups are loaded from .config/dorks.conf by load_dorks() in common.sh.

# Curated domain list for the precision pass. Used with Tavily's include_domains
# parameter (hard server-side filter) — the precision sibling to the dork-based
# broad-recall pass. Tuning this is intentional code change, not user config.
_PRECISION_DOMAINS=(
    github.com gist.github.com gitlab.com bitbucket.org codeberg.org sourcegraph.com
    pastebin.com paste.ee ghostbin.com dpaste.org rentry.co justpaste.it
    controlc.com privatebin.net 0bin.net hastebin.com ideone.com
    paste.debian.net dpaste.com pastes.io termbin.com paste2.org
    dropbox.com docs.google.com archive.org
    trello.com notion.site scribd.com slideshare.net
    reddit.com
    haveibeenpwned.com databreaches.net bleepingcomputer.com krebsonsecurity.com
)

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

    local results_json total_count
    results_json=$(echo "$body" | jq -c '[(.results // [])[] | {title: (.title // ""), url: (.url // ""), description: (.content // ""), score: (.score // 0)}]')
    total_count=$(echo "$results_json" | jq 'length')

    if [[ "$total_count" -eq 0 ]]; then
        log_debug "Tavily Search: no results for '$keyword' (dork: $dork_label)"
        return 0
    fi

    local allowed_hosts filtered_json result_count
    allowed_hosts=$(_extract_sites_from_dork_group "$query")
    filtered_json=$(_filter_results_by_sites "$results_json" "$allowed_hosts")
    result_count=$(echo "$filtered_json" | jq 'length')

    if [[ -n "$allowed_hosts" && "$result_count" -lt "$total_count" ]]; then
        log_debug "tavily: filtered site-scoped group '$dork_label': $total_count -> $result_count (allowed: $allowed_hosts)"
    fi

    if [[ "$result_count" -eq 0 ]]; then
        log_debug "Tavily Search: no on-site results for '$keyword' (dork: $dork_label)"
        return 0
    fi

    log_info "Tavily Search: $result_count result(s) for '$keyword' (dork: $dork_label)"

    local i title url description score
    for (( i=0; i<result_count; i++ )); do
        title=$(echo "$filtered_json" | jq -r ".[$i].title // \"\"" 2>/dev/null)
        url=$(echo "$filtered_json" | jq -r ".[$i].url // \"\"" 2>/dev/null)
        description=$(echo "$filtered_json" | jq -r ".[$i].description // \"\"" 2>/dev/null)
        score=$(echo "$filtered_json" | jq -r ".[$i].score // 0" 2>/dev/null)

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

# Precision pass: single Tavily call per keyword with include_domains set to
# the curated _PRECISION_DOMAINS list. No dork wrapping — the keyword itself
# is the query because include_domains is already scoping to trusted hosts.
tavily_precision_search() {
    local keyword="$1"

    if [[ -z "${TAVILY_API_KEY:-}" ]]; then
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would call Tavily precision search for: $keyword"
        return 0
    fi

    log_info "Tavily precision: include_domains pass for '$keyword'"
    _tavily_precision_query "$keyword"
}

_tavily_precision_query() {
    local keyword="$1"
    local event_type="SEARCH_WEB"
    local source_name="tavily_precision"
    local dork_label="precision_pass"

    local count="${SEARCH_RESULT_COUNT:-10}"
    local days_back="${SEARCH_DAYS_BACK:-7}"

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

    local domains_json
    domains_json=$(printf '%s\n' "${_PRECISION_DOMAINS[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')

    local request_body
    request_body=$(jq -nc \
        --arg q "$keyword" \
        --argjson max "$count" \
        --arg depth "${TAVILY_SEARCH_DEPTH:-basic}" \
        --arg tr "$time_range" \
        --argjson domains "$domains_json" \
        '{
            query: $q,
            max_results: $max,
            search_depth: $depth,
            time_range: $tr,
            include_answer: false,
            include_raw_content: false,
            include_domains: $domains
        }')

    log_debug "Tavily precision: query='$keyword' (include_domains: ${#_PRECISION_DOMAINS[@]} hosts)"

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
        log_error "Tavily precision API returned HTTP $http_code for '$keyword'"
        emit_audit_record "$event_type" "$source_name" "$keyword" "error" "info" \
            "Tavily precision API error: HTTP $http_code" \
            "$(jq -nc --arg code "$http_code" '{http_code: $code}')"
        return 1
    fi

    local results_json total_count
    results_json=$(echo "$body" | jq -c '[(.results // [])[] | {title: (.title // ""), url: (.url // ""), description: (.content // ""), score: (.score // 0)}]')
    total_count=$(echo "$results_json" | jq 'length')

    if [[ "$total_count" -eq 0 ]]; then
        log_debug "Tavily precision: no results for '$keyword'"
        return 0
    fi

    # Belt-and-suspenders: include_domains enforces server-side, but filter
    # again client-side in case Tavily ever returns an off-domain result.
    local allowed_hosts filtered_json result_count
    allowed_hosts="${_PRECISION_DOMAINS[*]}"
    filtered_json=$(_filter_results_by_sites "$results_json" "$allowed_hosts")
    result_count=$(echo "$filtered_json" | jq 'length')

    if [[ "$result_count" -lt "$total_count" ]]; then
        log_debug "tavily precision: filtered off-domain: $total_count -> $result_count"
    fi

    if [[ "$result_count" -eq 0 ]]; then
        return 0
    fi

    log_info "Tavily precision: $result_count result(s) for '$keyword'"

    local i title url description score
    for (( i=0; i<result_count; i++ )); do
        title=$(echo "$filtered_json" | jq -r ".[$i].title // \"\"" 2>/dev/null)
        url=$(echo "$filtered_json" | jq -r ".[$i].url // \"\"" 2>/dev/null)
        description=$(echo "$filtered_json" | jq -r ".[$i].description // \"\"" 2>/dev/null)
        score=$(echo "$filtered_json" | jq -r ".[$i].score // 0" 2>/dev/null)

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
