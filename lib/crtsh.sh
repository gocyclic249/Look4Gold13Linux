#!/usr/bin/env bash
# lib/crtsh.sh — crt.sh Certificate Transparency source (no API key).
# Surfaces lookalike/phishing domains and shadow-IT certs mentioning a keyword.
# Emits SEARCH_CERT records; disclosure-semantics (feeds URL/domain dedup + AI).

crtsh_search() {
    local keyword="$1"

    if [[ "${CRTSH_ENABLED:-true}" != "true" ]]; then
        log_debug "crt.sh disabled (CRTSH_ENABLED != true)"
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would query crt.sh for: $keyword"
        return 0
    fi

    local max_results="${CRTSH_MAX_RESULTS:-100}"
    local encoded
    encoded="$(url_encode "%${keyword}%")"
    local url="https://crt.sh/?q=${encoded}&output=json"

    log_info "crt.sh: querying certificate transparency for '$keyword'"

    local -a _crt_hdrs=(-H "Accept: application/json")
    local response http_code body
    response="$(http_request GET "$url" _crt_hdrs)"
    http_code="$(echo "$response" | tail -n1)"
    body="$(echo "$response" | sed '$d')"

    if [[ "$http_code" -ne 200 ]]; then
        log_error "crt.sh returned HTTP $http_code for '$keyword'"
        emit_audit_record "SEARCH_CERT" "crtsh" "$keyword" "error" "info" \
            "crt.sh API error: HTTP $http_code" \
            "$(jq -nc --arg code "$http_code" '{http_code: $code}')"
        return 1
    fi

    # crt.sh intermittently returns a 502 HTML page under load; guard the parse.
    if ! echo "$body" | jq -e 'type == "array"' &>/dev/null; then
        log_warn "crt.sh: non-array response for '$keyword' (transient); skipping"
        return 1
    fi

    # One cert can list several domains in name_value (newline-separated). Flatten,
    # unique, cap. Keep the first cert's metadata per domain for context.
    local rows
    rows="$(echo "$body" | jq -c --argjson max "$max_results" '
        [ .[] as $c | ($c.name_value | split("\n")[])
          | select(length > 0)
          | { domain: ., issuer_name: ($c.issuer_name // ""),
              not_before: ($c.not_before // ""), not_after: ($c.not_after // ""),
              cert_id: ($c.id // 0) } ]
        | group_by(.domain) | map(.[0]) | .[0:$max]')"

    local count
    count="$(echo "$rows" | jq 'length')"

    if [[ "$count" -eq 0 ]]; then
        log_info "crt.sh: no certs for '$keyword'"
        emit_audit_record "SEARCH_CERT" "crtsh" "$keyword" "not_found" "info" \
            "No certificate transparency records for keyword" "null"
        return 0
    fi

    log_info "crt.sh: $count unique domain(s) for '$keyword'"

    local i domain details
    for (( i=0; i<count; i++ )); do
        domain="$(echo "$rows" | jq -r ".[$i].domain")"
        details="$(echo "$rows" | jq -c ".[$i] | . + {url: (\"https://\" + .domain)}")"
        emit_audit_record "SEARCH_CERT" "crtsh" "$keyword" "found" "low" \
            "Certificate domain: $domain" "$details"
    done
}
