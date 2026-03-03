#!/usr/bin/env bash
# lib/fourchan.sh — 4chan archive search via web search dorks
# Routes site:-scoped queries through Brave/Tavily instead of direct FoolFuuka
# API calls (which are largely Cloudflare-blocked). Search engines have already
# crawled and indexed these archive pages, so results come back reliably.
# Dork groups are loaded from .config/dorks.conf [chan] section by load_dorks().

fourchan_search() {
    local keyword="$1"

    if [[ "${FOURCHAN_ENABLED}" != "true" ]]; then
        log_debug "4chan archive search disabled (FOURCHAN_ENABLED != true)"
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would search 4chan archives (via web dorks) for: $keyword"
        return 0
    fi

    # Determine which web search API to use (Tavily preferred, Brave fallback)
    local search_fn=""
    if [[ -n "${TAVILY_API_KEY:-}" ]]; then
        search_fn="_tavily_query"
    elif [[ -n "${BRAVE_API_KEY:-}" ]]; then
        search_fn="_brave_query"
    else
        log_warn "4chan archives: no web search API available (need TAVILY_API_KEY or BRAVE_API_KEY)"
        return 0
    fi

    log_info "4chan: searching archives (via $search_fn) for '$keyword'"

    local group_idx=0
    for group in "${_CHAN_DORK_GROUPS[@]}"; do
        group_idx=$((group_idx + 1))
        local query="\"${keyword}\" (${group})"
        "$search_fn" "$keyword" "$query" "chan_dork_${group_idx}" "SEARCH_CHAN" "fourchan_dork"
    done
}
