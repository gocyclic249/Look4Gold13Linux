#!/usr/bin/env bash
# lib/github.sh — GitHub code search source.
# Searches public code file contents for a keyword (broad pass) and, when
# GITHUB_ORGS is set, adds one org-scoped pass per org. Emits SEARCH_CODE
# records; disclosure-semantics (feeds URL dedup + AI).
# Rate limit is ~10 req/min for code search — retry/backoff (http_request)
# handles secondary rate limits (403 w/ Retry-After, or 429).

github_search() {
    local keyword="$1"
    # Power-of-10 rule #5: assert required input before any side effects.
    [[ -n "$keyword" ]] || { log_error "github_search: keyword argument is required"; return 1; }

    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        log_warn "GITHUB_TOKEN not set, skipping GitHub code search"
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would call GitHub code search for: $keyword"
        return 0
    fi

    # Broad keyword pass (always).
    _github_query "$keyword" "\"${keyword}\"" "broad"

    # Optional org-scoped passes. GITHUB_ORGS is space/comma separated and
    # OPSEC-sensitive (lives only in gitignored apis.conf).
    if [[ -n "${GITHUB_ORGS:-}" ]]; then
        local -a orgs
        read -ra orgs <<< "${GITHUB_ORGS//,/ }"
        local org
        for org in "${orgs[@]}"; do
            [[ -z "$org" ]] && continue
            _github_query "$keyword" "\"${keyword}\" org:${org}" "org_${org}"
        done
    fi
}

# Internal: one GitHub code-search API call.
_github_query() {
    local keyword="$1"
    local query="$2"
    local label="$3"

    local count="${SEARCH_RESULT_COUNT:-10}"
    local encoded
    encoded="$(url_encode "$query")"
    local url="https://api.github.com/search/code?q=${encoded}&per_page=${count}"

    log_debug "GitHub code search: q='$query' (label: $label)"

    local -a _gh_hdrs=(
        -H "Authorization: Bearer $GITHUB_TOKEN"
        -H "Accept: application/vnd.github.text-match+json"
        -H "X-GitHub-Api-Version: 2022-11-28"
    )
    local response http_code body
    response="$(http_request GET "$url" _gh_hdrs)"
    http_code="$(echo "$response" | tail -n1)"
    body="$(echo "$response" | sed '$d')"

    # 422 = unprocessable query (e.g. too-broad term). Treat as no results.
    if [[ "$http_code" -eq 422 ]]; then
        log_debug "GitHub: unprocessable query for '$keyword' (label: $label)"
        return 0
    fi

    if [[ "$http_code" -ne 200 ]]; then
        log_error "GitHub code search returned HTTP $http_code for '$keyword' (label: $label)"
        emit_audit_record "SEARCH_CODE" "github_code" "$keyword" "error" "info" \
            "GitHub code search error: HTTP $http_code (label: $label)" \
            "$(jq -nc --arg code "$http_code" --arg l "$label" '{http_code: $code, query_label: $l}')"
        return 1
    fi

    # Rule #7: suppress jq stderr here because body may be empty or non-JSON
    # on transient API errors that still returned 200; || echo 0 provides a safe default.
    local items_count
    items_count="$(echo "$body" | jq '.items | length' 2>/dev/null || echo 0)"

    if [[ "$items_count" -eq 0 ]]; then
        log_info "GitHub: no code results for '$keyword' (label: $label)"
        return 0
    fi

    log_info "GitHub: $items_count code result(s) for '$keyword' (label: $label)"

    local i repo path html_url snippet details
    for (( i=0; i<items_count; i++ )); do
        repo="$(echo "$body" | jq -r ".items[$i].repository.full_name // \"\"")"
        path="$(echo "$body" | jq -r ".items[$i].path // \"\"")"
        html_url="$(echo "$body" | jq -r ".items[$i].html_url // \"\"")"
        # Rule #7: suppress jq stderr because text_matches may be absent when
        # the Accept header is not honoured or the field is not returned for this item.
        snippet="$(echo "$body" | jq -r ".items[$i].text_matches[0].fragment // \"\"" 2>/dev/null || echo "")"
        details="$(jq -nc \
            --arg r "$repo" --arg p "$path" --arg u "$html_url" \
            --arg s "$snippet" --arg l "$label" \
            '{repo: $r, path: $p, html_url: $u, snippet: $s, query_label: $l}')"
        emit_audit_record "SEARCH_CODE" "github_code" "$keyword" "found" "low" \
            "Code match: ${repo}/${path}" "$details"
    done
}
