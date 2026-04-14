#!/usr/bin/env bash
# lib/cse_scrape.sh — Google Programmable Search Engine scraper
#
# The Google Custom Search JSON API was deprecated in late 2025. The
# Programmable Search Engine web widget at cse.google.com/cse?cx=<ID> is still
# available, so we dump its rendered DOM with headless chromium and parse the
# results with pup. Precision comes from the user's CSE "Sites to search"
# configuration — a curated list of high-value disclosure domains.

# Module-level cache for the resolved chromium binary so we don't search PATH
# on every keyword.
_CHROMIUM_BIN=""

# Resolve chromium binary once per scan. Returns 0 on success with $_CHROMIUM_BIN
# set; returns 1 on failure.
_cse_resolve_chromium() {
    if [[ -n "$_CHROMIUM_BIN" ]]; then
        return 0
    fi
    local candidate
    for candidate in chromium chromium-browser google-chrome; do
        if command -v "$candidate" &>/dev/null; then
            _CHROMIUM_BIN="$candidate"
            return 0
        fi
    done
    return 1
}

# Check runtime dependencies for the CSE scraper. Called once per scan at
# startup when ENABLE_CSE_SCRAPE=true. Aborts with a clear error rather than
# silently skipping so the opt-in user knows their configuration is broken.
cse_check_deps() {
    if [[ "${ENABLE_CSE_SCRAPE:-false}" != "true" ]]; then
        return 0
    fi

    local missing=()
    if ! _cse_resolve_chromium; then
        missing+=("chromium (install: sudo apt install chromium-browser  OR  snap install chromium)")
    fi
    if ! command -v pup &>/dev/null; then
        missing+=("pup (install: go install github.com/ericchiang/pup@latest  OR  download from https://github.com/ericchiang/pup/releases)")
    fi

    if (( ${#missing[@]} > 0 )); then
        log_error "CSE scraper enabled but required dependencies are missing:"
        local m
        for m in "${missing[@]}"; do
            log_error "  - $m"
        done
        log_error "Set ENABLE_CSE_SCRAPE=false in apis.conf to disable, or install the dependencies."
        return 1
    fi

    if [[ -z "${CSE_ID:-}" ]]; then
        log_error "CSE scraper enabled but CSE_ID is not set in apis.conf"
        log_error "Create a CSE at https://programmablesearchengine.google.com/ and paste its cx ID."
        return 1
    fi

    log_info "CSE scraper: chromium=$_CHROMIUM_BIN, pup=$(command -v pup), cx=$CSE_ID"
}

cse_scrape_search() {
    local keyword="$1"

    if [[ "${ENABLE_CSE_SCRAPE:-false}" != "true" ]]; then
        return 0
    fi

    if [[ -z "${CSE_ID:-}" ]]; then
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would run CSE scraper for: $keyword"
        return 0
    fi

    if ! _cse_resolve_chromium; then
        log_warn "CSE scraper: no chromium binary on PATH, skipping"
        return 0
    fi
    if ! command -v pup &>/dev/null; then
        log_warn "CSE scraper: pup not on PATH, skipping"
        return 0
    fi

    _cse_scrape_query "$keyword"

    # Rate limit between keywords. Google doesn't publish a CSE scraping rate
    # limit because scraping isn't officially supported, so stay polite.
    sleep 1
}

_cse_scrape_query() {
    local keyword="$1"
    local event_type="SEARCH_WEB"
    local source_name="google_cse_scrape"
    local dork_label="cse_scrape"

    local encoded
    encoded=$(url_encode "$keyword")
    local cse_url="https://cse.google.com/cse?cx=${CSE_ID}#gsc.tab=0&gsc.q=${encoded}&gsc.sort="

    log_debug "CSE scrape: query='$keyword' url='$cse_url'"

    local dump_file
    dump_file=$(_mktemp)

    # The --virtual-time-budget value gives the JS widget time to populate
    # results before chromium dumps the DOM. 8000ms was confirmed to produce
    # rendered results during development; tune if Google's widget gets slower.
    if ! "$_CHROMIUM_BIN" \
            --headless \
            --disable-gpu \
            --no-sandbox \
            --virtual-time-budget=8000 \
            --dump-dom "$cse_url" \
            > "$dump_file" 2>/dev/null; then
        log_warn "CSE scrape: chromium exited non-zero for '$keyword', skipping"
        return 0
    fi

    if [[ ! -s "$dump_file" ]]; then
        log_warn "CSE scrape: empty DOM dump for '$keyword'"
        return 0
    fi

    # Extract URLs via pup. Google's widget repeats each result anchor 2-3
    # times (visible + alt renderings), so dedupe by URL value in first-seen
    # order.
    local urls_file snippets_file
    urls_file=$(_mktemp)
    snippets_file=$(_mktemp)

    pup '.gsc-webResult.gsc-result a.gs-title attr{href}' < "$dump_file" 2>/dev/null \
        | awk 'NF && !seen[$0]++' \
        > "$urls_file"

    pup '.gsc-webResult.gsc-result .gs-snippet text{}' < "$dump_file" 2>/dev/null \
        > "$snippets_file"

    local url_count
    url_count=$(wc -l < "$urls_file")

    # Stale-selector detection: if the DOM contains result markers but pup
    # extracted zero URLs, the selector is probably out of date. Distinguish
    # this from a genuine "no results" response.
    if [[ "$url_count" -eq 0 ]]; then
        if grep -q 'gsc-webResult' "$dump_file"; then
            log_warn "CSE scrape: DOM contains result markers but pup extracted 0 URLs for '$keyword' — selectors may be stale"
        else
            log_debug "CSE scrape: no results for '$keyword'"
        fi
        return 0
    fi

    # Belt-and-suspenders: the CSE is server-side scoped to the user's curated
    # site list, but reuse the workstream-1 filter here too. We pass the
    # _PRECISION_DOMAINS list from tavily.sh as the allowlist since they're
    # the same curated set.
    local allowed_hosts
    allowed_hosts="${_PRECISION_DOMAINS[*]:-}"

    # Build a JSON array from urls + snippets (pair by line index).
    local results_json
    results_json=$(jq -sRc \
        --rawfile snippets "$snippets_file" \
        '
            split("\n")
            | map(select(length > 0))
            | . as $urls
            | ($snippets | split("\n")) as $snips
            | [range(0; $urls | length) as $i | {
                title: "",
                url: $urls[$i],
                description: ($snips[$i] // "")
              }]
        ' < "$urls_file")

    local total_count filtered_json result_count
    total_count=$(echo "$results_json" | jq 'length')

    if [[ -n "$allowed_hosts" ]]; then
        filtered_json=$(_filter_results_by_sites "$results_json" "$allowed_hosts")
    else
        filtered_json="$results_json"
    fi
    result_count=$(echo "$filtered_json" | jq 'length')

    if [[ -n "$allowed_hosts" && "$result_count" -lt "$total_count" ]]; then
        log_debug "cse scrape: filtered off-domain: $total_count -> $result_count"
    fi

    if [[ "$result_count" -eq 0 ]]; then
        return 0
    fi

    log_info "CSE scrape: $result_count result(s) for '$keyword'"

    local i title url description
    for (( i=0; i<result_count; i++ )); do
        title=$(echo "$filtered_json" | jq -r ".[$i].title // \"\"" 2>/dev/null)
        url=$(echo "$filtered_json" | jq -r ".[$i].url // \"\"" 2>/dev/null)
        description=$(echo "$filtered_json" | jq -r ".[$i].description // \"\"" 2>/dev/null)

        local details
        details=$(jq -nc \
            --arg t "$title" \
            --arg u "$url" \
            --arg d "$description" \
            --arg dork "$dork_label" \
            --argjson idx "$i" \
            '{title: $t, url: $u, description: $d, dork_group: $dork, result_index: $idx}')

        emit_audit_record "$event_type" "$source_name" "$keyword" "found" "low" \
            "CSE result: $url" "$details"
    done
}
