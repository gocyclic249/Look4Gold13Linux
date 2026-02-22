#!/usr/bin/env bash
# lib/brave.sh — Brave Search API module with security-focused dork queries

# Disclosure dork groups — sites where leaked content commonly appears
# Each group is a batch of OR'd site: operators to minimize API calls
_DISCLOSURE_DORK_GROUPS=(
    "site:pastebin.com OR site:github.com OR site:gist.github.com OR site:reddit.com"
    "site:dropbox.com/s/ OR site:docs.google.com OR site:archive.org OR site:paste.ee"
    "site:ghostbin.com OR site:dpaste.org OR site:rentry.co OR site:justpaste.it"
    "site:controlc.com OR site:privatebin.net OR site:0bin.net OR site:hastebin.com OR site:ideone.com"
    "github code exposed repository"
)

# Breach/threat dork groups — security news and intel sources
_BREACH_DORK_GROUPS=(
    "breach data leak compromised"
    "ransomware attack security incident"
    "credential stolen dark web"
    "site:haveibeenpwned.com OR site:databreaches.net OR site:bleepingcomputer.com OR site:krebsonsecurity.com"
    "breachforums breach leaked database"
)

brave_search() {
    local keyword="$1"

    if [[ -z "${BRAVE_API_KEY:-}" ]]; then
        log_warn "BRAVE_API_KEY not set, skipping Brave Search"
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would call Brave Search API for: $keyword"
        return 0
    fi

    local dork_mode="${BRAVE_DORK_MODE:-security}"

    if [[ "$dork_mode" == "raw" ]]; then
        _brave_query "$keyword" "$keyword" "raw"
    else
        log_info "Brave Search: running security dorks for '$keyword'"

        local group_idx=0
        for group in "${_DISCLOSURE_DORK_GROUPS[@]}"; do
            group_idx=$((group_idx + 1))
            local query="\"${keyword}\" (${group})"
            _brave_query "$keyword" "$query" "disclosure_${group_idx}"
        done

        for group in "${_BREACH_DORK_GROUPS[@]}"; do
            group_idx=$((group_idx + 1))
            local query="\"${keyword}\" ${group}"
            _brave_query "$keyword" "$query" "breach_${group_idx}"
        done
    fi
}

# Internal: execute a single Brave Search API call
_brave_query() {
    local keyword="$1"
    local query="$2"
    local dork_label="$3"

    local encoded_query
    encoded_query="$(url_encode "$query")"
    local count="${SEARCH_RESULT_COUNT:-10}"
    local days_back="${SEARCH_DAYS_BACK:-7}"

    log_debug "Brave Search: query='$query' (dork: $dork_label)"

    # Brave freshness parameter: custom range YYYY-MM-DDtoYYYY-MM-DD
    local from_date to_date freshness_param
    to_date="$(date -u '+%Y-%m-%d')"
    from_date="$(date -u -d "${days_back} days ago" '+%Y-%m-%d')"
    freshness_param="${from_date}to${to_date}"

    local response http_code body
    response=$(curl -s -w "\n%{http_code}" \
        -H "Accept: application/json" \
        -H "Accept-Encoding: gzip" \
        -H "X-Subscription-Token: $BRAVE_API_KEY" \
        "https://api.search.brave.com/res/v1/web/search?q=${encoded_query}&count=${count}&freshness=${freshness_param}" \
        --compressed 2>/dev/null)

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" -ne 200 ]]; then
        log_error "Brave Search API returned HTTP $http_code for '$keyword' (dork: $dork_label)"
        emit_audit_record "SEARCH_WEB" "brave_search" "$keyword" "error" "info" \
            "Brave Search API error: HTTP $http_code (dork: $dork_label)" \
            "$(jq -nc --arg code "$http_code" --arg dork "$dork_label" '{http_code: $code, dork_group: $dork}')"
        return 1
    fi

    local result_count
    result_count=$(echo "$body" | jq -r '.web.results | length // 0' 2>/dev/null)

    if [[ "$result_count" -eq 0 ]]; then
        log_debug "Brave Search: no results for '$keyword' (dork: $dork_label)"
        return 0
    fi

    log_info "Brave Search: $result_count result(s) for '$keyword' (dork: $dork_label)"

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
            --arg dork "$dork_label" \
            --argjson idx "$i" \
            '{title: $t, url: $u, description: $d, dork_group: $dork, result_index: $idx}')

        emit_audit_record "SEARCH_WEB" "brave_search" "$keyword" "found" "low" \
            "Web result: $title" "$details"
    done
}
