#!/usr/bin/env bash
# lib/fourchan.sh — 4chan Archive (FoolFuuka API) search module
# Searches public 4chan archives for keyword mentions on boards known
# for data leaks, credential dumps, and organizational exposure.
# No API key required — archives are free and public.

# Rate-limit tracking: last request epoch per archive host
declare -A _FOURCHAN_LAST_REQUEST

# Minimum seconds between requests to the same archive (5 req/min = 12s)
_FOURCHAN_RATE_LIMIT_SECS=12

fourchan_search() {
    local keyword="$1"

    if [[ "${FOURCHAN_ENABLED:-false}" != "true" ]]; then
        log_debug "4chan archive search disabled (FOURCHAN_ENABLED != true)"
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would search 4chan archives for: $keyword"
        return 0
    fi

    # FoolFuuka API requires keywords of at least 4 characters
    if [[ ${#keyword} -lt 4 ]]; then
        log_warn "4chan: keyword '$keyword' too short (min 4 chars for FoolFuuka API), skipping"
        return 0
    fi

    if [[ -z "${FOURCHAN_BOARDS:-}" ]]; then
        log_warn "4chan: FOURCHAN_BOARDS not configured, skipping"
        return 0
    fi

    local max_pages="${FOURCHAN_MAX_PAGES:-1}"

    # Compute date range from SEARCH_DAYS_BACK
    local now_epoch start_epoch
    now_epoch=$(date -u '+%s')
    start_epoch=$(( now_epoch - (${SEARCH_DAYS_BACK:-7} * 86400) ))

    log_info "4chan: searching archives for '$keyword' (last ${SEARCH_DAYS_BACK:-7} days, max $max_pages page(s))"

    # Parse FOURCHAN_BOARDS: comma-separated "board:archive_url" pairs
    local IFS=','
    local board_entries=($FOURCHAN_BOARDS)
    unset IFS

    local total_results=0
    for entry in "${board_entries[@]}"; do
        # Trim whitespace
        entry="$(echo "$entry" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -z "$entry" ]] && continue

        local board="${entry%%:*}"
        local archive_base="${entry#*:}"

        # Validate entry format
        if [[ -z "$board" || -z "$archive_base" || "$board" == "$entry" ]]; then
            log_warn "4chan: invalid board entry '$entry', expected 'board:https://archive.example.org'"
            continue
        fi

        local page
        for (( page=1; page<=max_pages; page++ )); do
            local count
            count=$(_fourchan_query "$keyword" "$board" "$archive_base" "$start_epoch" "$now_epoch" "$page")
            total_results=$(( total_results + count ))

            # Stop paging if we got fewer results than a full page (~25)
            if [[ "$count" -lt 25 ]]; then
                break
            fi
        done
    done

    log_info "4chan: $total_results result(s) for '$keyword'"
}

# Rate-limit: sleep if needed to maintain minimum gap between requests to the same archive
_fourchan_rate_limit() {
    local archive_key="$1"
    local now last elapsed wait_time

    now=$(date -u '+%s')
    last="${_FOURCHAN_LAST_REQUEST[$archive_key]:-0}"
    elapsed=$(( now - last ))

    if [[ "$elapsed" -lt "$_FOURCHAN_RATE_LIMIT_SECS" ]]; then
        wait_time=$(( _FOURCHAN_RATE_LIMIT_SECS - elapsed ))
        log_debug "4chan: rate-limiting $archive_key — sleeping ${wait_time}s"
        sleep "$wait_time"
    fi

    _FOURCHAN_LAST_REQUEST[$archive_key]=$(date -u '+%s')
}

# Execute one search against one archive/board, emit audit records, return result count
_fourchan_query() {
    local keyword="$1"
    local board="$2"
    local archive_base="$3"
    local start_epoch="$4"
    local end_epoch="$5"
    local page="$6"

    local encoded_keyword
    encoded_keyword="$(url_encode "$keyword")"

    # Extract hostname for rate-limit key
    local archive_host
    archive_host=$(echo "$archive_base" | sed 's|https\?://||;s|/.*||')

    _fourchan_rate_limit "$archive_host"

    local url="${archive_base}/_/api/chan/search/?text=${encoded_keyword}&boards=${board}&start=${start_epoch}&end=${end_epoch}&page=${page}"

    log_debug "4chan: GET /${board}/ from $archive_host (page $page)"

    local response http_code body
    response=$(curl -s -w "\n%{http_code}" \
        --max-time 30 \
        -H "User-Agent: Look4Gold13/1.0 (AU-13 OSINT Monitor)" \
        "$url" 2>/dev/null)

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    # Handle HTTP errors
    if [[ "$http_code" -eq 429 ]]; then
        # Rate limited — check Retry-After and retry once
        log_warn "4chan: HTTP 429 from $archive_host, retrying after 15s"
        sleep 15
        _FOURCHAN_LAST_REQUEST[$archive_host]=$(date -u '+%s')

        response=$(curl -s -w "\n%{http_code}" \
            --max-time 30 \
            -H "User-Agent: Look4Gold13/1.0 (AU-13 OSINT Monitor)" \
            "$url" 2>/dev/null)

        http_code=$(echo "$response" | tail -n1)
        body=$(echo "$response" | sed '$d')
    fi

    if [[ "$http_code" -ne 200 ]]; then
        log_warn "4chan: /${board}/ on $archive_host returned HTTP $http_code (may be Cloudflare-blocked)"
        emit_audit_record "SEARCH_CHAN" "fourchan_archive" "$keyword" "error" "info" \
            "4chan archive error: /${board}/ on $archive_host HTTP $http_code" \
            "$(jq -nc --arg code "$http_code" --arg b "$board" --arg a "$archive_host" \
                '{http_code: $code, board: $b, archive: $a}')"
        echo "0"
        return 0
    fi

    # FoolFuuka returns {"0": {"posts": [...]}} — flatten all posts
    local posts
    posts=$(echo "$body" | jq -c '[.[] | .posts[]?] // []' 2>/dev/null)

    if [[ -z "$posts" || "$posts" == "[]" || "$posts" == "null" ]]; then
        log_debug "4chan: no results for '$keyword' on /${board}/ (page $page)"
        if [[ "$page" -eq 1 ]]; then
            emit_audit_record "SEARCH_CHAN" "fourchan_archive" "$keyword" "not_found" "info" \
                "No 4chan posts found on /${board}/ ($archive_host)" \
                "$(jq -nc --arg b "$board" --arg a "$archive_host" '{board: $b, archive: $a}')"
        fi
        echo "0"
        return 0
    fi

    local post_count
    post_count=$(echo "$posts" | jq 'length' 2>/dev/null)
    log_info "4chan: $post_count post(s) on /${board}/ from $archive_host (page $page)"

    local i
    for (( i=0; i<post_count; i++ )); do
        local post_num thread_num timestamp_epoch poster_name thread_title comment

        post_num=$(echo "$posts" | jq -r ".[$i].num // \"\"" 2>/dev/null)
        thread_num=$(echo "$posts" | jq -r ".[$i].thread_num // .[$i].num // \"\"" 2>/dev/null)
        timestamp_epoch=$(echo "$posts" | jq -r ".[$i].timestamp // 0" 2>/dev/null)
        poster_name=$(echo "$posts" | jq -r ".[$i].name // \"Anonymous\"" 2>/dev/null)
        thread_title=$(echo "$posts" | jq -r ".[$i].title // \"\"" 2>/dev/null)
        comment=$(echo "$posts" | jq -r ".[$i].comment // \"\"" 2>/dev/null)

        # Strip HTML tags from comment and truncate
        comment=$(echo "$comment" | sed 's/<[^>]*>//g; s/&gt;/>/g; s/&lt;/</g; s/&amp;/\&/g; s/&quot;/"/g')
        if [[ ${#comment} -gt 500 ]]; then
            comment="${comment:0:500}..."
        fi

        local post_url="${archive_base}/${board}/thread/${thread_num}/#${post_num}"

        local details
        details=$(jq -nc \
            --arg pn "$post_num" \
            --arg tn "$thread_num" \
            --arg b "$board" \
            --arg a "$archive_host" \
            --arg url "$post_url" \
            --argjson ts "$timestamp_epoch" \
            --arg name "$poster_name" \
            --arg title "$thread_title" \
            --arg snippet "$comment" \
            '{
                post_num: ($pn | tonumber? // $pn),
                thread_num: ($tn | tonumber? // $tn),
                board: $b,
                archive: $a,
                url: $url,
                timestamp_epoch: $ts,
                poster_name: $name,
                thread_title: $title,
                comment_snippet: $snippet
            }')

        emit_audit_record "SEARCH_CHAN" "fourchan_archive" "$keyword" "found" "medium" \
            "4chan /${board}/: post #${post_num} in thread #${thread_num} on ${archive_host}" "$details"
    done

    echo "$post_count"
}
