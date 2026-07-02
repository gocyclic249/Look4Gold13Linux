# New OSINT Sources + HTTP Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three OSINT sources (crt.sh, GitHub code search, URLScan.io), route all API modules through one retry/backoff/throttle helper, and fix the `bc` CVSS severity bug in `lib/nist.sh`.

**Architecture:** A single `http_request()` helper in `lib/common.sh` becomes the choke point for every outbound API call, adding bounded retry, exponential backoff, `Retry-After` honoring, and a light throttle while preserving the existing `body\n<http_code>` return convention. Three new `lib/*.sh` modules follow the established source-module pattern (skip-if-key-unset, `emit_audit_record` per finding). crt.sh + GitHub feed URL/domain dedup + xAI like web results; URLScan flows to reports like OTX.

**Tech Stack:** Pure Bash 4+, `curl`, `jq`. Tests in `bats`. Lint via `shellcheck` + `bash -n`.

## Prerequisites

- `bats` must be installed to run the test steps (`sudo apt-get install -y bats`). `shellcheck` is already present. If `bats` cannot be installed, the test steps can be run by hand, but that defeats the TDD cycle — install it first.
- All work happens on branch `feature/osint-sources-and-resilience` (already created).
- Spec: `docs/superpowers/specs/2026-07-02-osint-sources-and-resilience-design.md`.

## Global Constraints

Every task's requirements implicitly include these (from the spec + repo conventions):

- `set -euo pipefail` in entry points; modules are sourced, not executed.
- snake_case functions, UPPER_CASE globals, 4-space indent; private helpers prefixed `_`.
- Use `log_*()` (never `echo`) for diagnostics inside modules.
- Use `_mktemp` (never bare `mktemp`) for temp files.
- Every `curl` call goes through `http_request` and therefore inherits `--proto =https`.
- Each source module skips gracefully (`return 0`) when its key/flag is unset, and honors `DRY_RUN`.
- Non-fatal API errors at call sites use `func || true`.
- No new hard runtime dependencies beyond `curl` + `jq`.
- Every loop has a provable ceiling or an explicit safety counter (Power-of-10 rule #2).
- `shellcheck` clean; the repo tolerates only SC2064/SC2129/SC2016. No blanket `2>/dev/null`/`SilentlyContinue` suppression of unclassified errors (rule #7).
- `GITHUB_ORGS` identifies the user's organization and is OPSEC-sensitive: it lives only in the gitignored, `chmod 600` `apis.conf`, never in a committed template value or example.
- New settings and their defaults: `RETRY_BACKOFF_BASE=1`, `HTTP_THROTTLE_SECONDS=0.2` (existing live-now settings: `RETRY_MAX_ATTEMPTS=3`, `API_TIMEOUT=30`).
- New event types: `SEARCH_CODE` (github), `SEARCH_CERT` (crt.sh), `CHECK_PHISH` (urlscan).

## File Structure

- Create `lib/crtsh.sh` — Certificate Transparency source (`crtsh_search`).
- Create `lib/github.sh` — GitHub code search source (`github_search`, `_github_query`).
- Create `lib/urlscan.sh` — URLScan.io source (`urlscan_search`).
- Create `test/bats/http_request.bats`, `test/bats/nist_severity.bats`, `test/bats/crtsh.bats`, `test/bats/github.bats`, `test/bats/urlscan.bats`, and shared `test/bats/helpers.bash`.
- Modify `lib/common.sh` — add `http_request`, `_hr_sleep`, `_hr_retry_after`; add GitHub/URLScan probes to `check_api_quotas`.
- Modify `lib/nist.sh` — replace `bc` with `jq`; route through `http_request`.
- Modify `lib/brave.sh`, `lib/tavily.sh`, `lib/otx.sh` — route through `http_request`.
- Modify `look4gold.sh` — source new modules, add calls, extend dedup `jq`.
- Modify `.config/settings.conf` + `.config/settings.conf.template` — new resilience settings.
- Modify `.config/apis.conf.template` — new keys + `GITHUB_ORGS` + `CRTSH_ENABLED`.
- Modify `setup.sh` — prompts + apis.conf writeout + validation probes.
- Modify `lib/report.sh` — render new event types in HTML "Source Findings".
- Modify `README.md` — source table, deps note, OPSEC note.

---

### Task 1: Shared `http_request()` helper + resilience settings

**Files:**
- Modify: `lib/common.sh` (add three functions near the other private helpers)
- Modify: `.config/settings.conf`, `.config/settings.conf.template`
- Create: `test/bats/helpers.bash`, `test/bats/http_request.bats`

**Interfaces:**
- Produces: `http_request <METHOD> <URL> <CURL_ARGS_ARRAY_NAME> [<BODY>]` — echoes response body then a final line with the HTTP status code (`000` on network failure / exhausted retries). Retries `429`, `5xx`, `000`, and `403`-with-`Retry-After`; honors integer `Retry-After` on `429`.
- Produces: `_hr_sleep <seconds>` (no-op on `0`/empty), `_hr_retry_after <header_file>` (echoes integer seconds or nothing).
- Consumes (from repo): `_mktemp`, `log_debug` (both in `common.sh`).

- [ ] **Step 1: Add the settings (both files).**

Append to `.config/settings.conf` AND `.config/settings.conf.template`:

```bash

# --- HTTP resilience (applies to every API module via http_request) ---
# Base seconds for exponential retry backoff: delay = base * 2^(attempt-1), capped at 60s.
RETRY_BACKOFF_BASE=1
# Small delay after each API call to smooth request bursts (fractional seconds OK).
HTTP_THROTTLE_SECONDS=0.2
```

(`RETRY_MAX_ATTEMPTS=3` and `API_TIMEOUT=30` already exist in both files and become live in this task.)

- [ ] **Step 2: Write the shared test helper.**

Create `test/bats/helpers.bash`:

```bash
# Shared bats helpers for Look4Gold13 module tests.
REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

# Source common.sh, then neutralize side-effecting helpers for hermetic tests.
load_common() {
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/common.sh"
    log_debug()  { :; }
    log_info()   { :; }
    log_warn()   { :; }
    log_error()  { :; }
    # Header temp files go to the bats-managed tmp dir.
    _mktemp() { mktemp "$BATS_TEST_TMPDIR/hr.XXXXXX"; }
}

# Install a scripted `curl` stub on PATH. Args: space-separated status codes.
# The nth curl invocation returns "body-<code>\n<code>". If STUB_RETRY_AFTER
# is set and the code is 429, writes "Retry-After: <val>" to the -D header file.
install_curl_stub() {
    export STUB_SEQ="$*"
    export STUB_COUNT_FILE="$BATS_TEST_TMPDIR/curl.count"
    : > "$STUB_COUNT_FILE"
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    cat > "$BATS_TEST_TMPDIR/bin/curl" <<'STUB'
#!/usr/bin/env bash
n=$(( $(cat "$STUB_COUNT_FILE" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STUB_COUNT_FILE"
hdr=""; prev=""
for a in "$@"; do [[ "$prev" == "-D" ]] && hdr="$a"; prev="$a"; done
read -ra seq <<< "${STUB_SEQ:-200}"
code="${seq[$((n-1))]:-${seq[${#seq[@]}-1]}}"
if [[ -n "${STUB_RETRY_AFTER:-}" && "$code" == "429" && -n "$hdr" ]]; then
    printf 'Retry-After: %s\r\n' "$STUB_RETRY_AFTER" > "$hdr"
fi
printf 'body-%s\n%s' "$code" "$code"
STUB
    chmod +x "$BATS_TEST_TMPDIR/bin/curl"
    PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

curl_call_count() { cat "$STUB_COUNT_FILE" 2>/dev/null || echo 0; }
```

- [ ] **Step 3: Write the failing tests.**

Create `test/bats/http_request.bats`:

```bash
#!/usr/bin/env bats
load helpers

setup() {
    load_common
    export RETRY_MAX_ATTEMPTS=3 API_TIMEOUT=5 RETRY_BACKOFF_BASE=0 HTTP_THROTTLE_SECONDS=0
}

@test "returns body+code and calls curl once on 200" {
    install_curl_stub 200
    local -a h=(-H "X-Test: 1")
    run http_request GET "https://example.test/" h
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | tail -n1)" = "200" ]
    [ "$(curl_call_count)" -eq 1 ]
}

@test "retries once on 429 then succeeds" {
    install_curl_stub 429 200
    local -a h=(-H "X-Test: 1")
    run http_request GET "https://example.test/" h
    [ "$(printf '%s' "$output" | tail -n1)" = "200" ]
    [ "$(curl_call_count)" -eq 2 ]
}

@test "retries 5xx up to RETRY_MAX_ATTEMPTS then returns last response" {
    install_curl_stub 500 500 500 500
    local -a h=(-H "X-Test: 1")
    run http_request GET "https://example.test/" h
    [ "$(printf '%s' "$output" | tail -n1)" = "500" ]
    [ "$(curl_call_count)" -eq 3 ]
}

@test "does not retry a non-429 4xx" {
    install_curl_stub 404 200
    local -a h=(-H "X-Test: 1")
    run http_request GET "https://example.test/" h
    [ "$(printf '%s' "$output" | tail -n1)" = "404" ]
    [ "$(curl_call_count)" -eq 1 ]
}

@test "honors integer Retry-After on 429" {
    export STUB_RETRY_AFTER=0
    install_curl_stub 429 200
    local -a h=(-H "X-Test: 1")
    run http_request GET "https://example.test/" h
    [ "$(printf '%s' "$output" | tail -n1)" = "200" ]
    [ "$(curl_call_count)" -eq 2 ]
}

@test "POST forwards a body" {
    install_curl_stub 200
    local -a h=(-H "Content-Type: application/json")
    run http_request POST "https://example.test/" h '{"q":"x"}'
    [ "$(printf '%s' "$output" | tail -n1)" = "200" ]
}
```

- [ ] **Step 4: Run tests to verify they fail.**

Run: `bats test/bats/http_request.bats`
Expected: FAIL — `http_request: command not found` (function not yet defined).

- [ ] **Step 5: Implement the helper.**

In `lib/common.sh`, add near the other private helpers (e.g. after `_mktemp`):

```bash
# --- HTTP request helper: bounded retry, backoff, throttle -----------------
# Usage: http_request METHOD URL CURL_ARGS_ARRAY_NAME [BODY]
#   CURL_ARGS_ARRAY_NAME is the *name* of a bash array of per-call curl args
#   (auth headers, Accept, --compressed, ...). BODY, if given, is sent via -d.
# Echoes: response body, then a final line with the HTTP status code (same
# convention as the old inline curl blocks). "000" on network failure or
# exhausted retries. Retries 429/5xx/000 (and 403 with Retry-After) up to
# RETRY_MAX_ATTEMPTS with exponential backoff (RETRY_BACKOFF_BASE * 2^(n-1),
# capped 60s); an integer Retry-After header overrides the computed backoff.
http_request() {
    local method="$1"
    local url="$2"
    local -n _hr_args="$3"
    local body="${4:-}"

    local max_attempts="${RETRY_MAX_ATTEMPTS:-3}"
    local timeout="${API_TIMEOUT:-30}"
    local backoff_base="${RETRY_BACKOFF_BASE:-1}"
    local throttle="${HTTP_THROTTLE_SECONDS:-0.2}"

    # Guard against a misconfigured attempt count (rule #2: bounded loop).
    local ceiling=20
    (( max_attempts > ceiling )) && max_attempts=$ceiling
    (( max_attempts < 1 )) && max_attempts=1

    local attempt=1 response http_code hdr_file retry_after delay retryable
    while (( attempt <= max_attempts )); do
        hdr_file="$(_mktemp)"
        local -a cmd=(curl -s -w $'\n%{http_code}'
            --proto =https --max-time "$timeout" --max-redirs 5
            -X "$method" -D "$hdr_file" "${_hr_args[@]}")
        [[ -n "$body" ]] && cmd+=(-d "$body")
        cmd+=("$url")

        response="$("${cmd[@]}" 2>/dev/null)" || response=$'\n000'
        http_code="$(printf '%s' "$response" | tail -n1)"
        retry_after="$(_hr_retry_after "$hdr_file")"
        rm -f "$hdr_file"

        retryable=false
        case "$http_code" in
            000|429)      retryable=true ;;
            5[0-9][0-9])  retryable=true ;;
            403)          [[ -n "$retry_after" ]] && retryable=true ;;
        esac

        if [[ "$retryable" == "false" ]] || (( attempt >= max_attempts )); then
            _hr_sleep "$throttle"
            printf '%s' "$response"
            return 0
        fi

        if [[ -n "$retry_after" ]]; then
            delay="$retry_after"
        else
            delay=$(( backoff_base * (2 ** (attempt - 1)) ))
        fi
        (( delay > 60 )) && delay=60
        log_debug "http_request: HTTP $http_code (attempt $attempt/$max_attempts) — retry in ${delay}s: $url"
        _hr_sleep "$delay"
        attempt=$(( attempt + 1 ))
    done
}

# sleep wrapper so tests can neutralize delays (0/empty is a no-op).
_hr_sleep() {
    local secs="$1"
    [[ -z "$secs" || "$secs" == "0" ]] && return 0
    sleep "$secs" 2>/dev/null || true
}

# Echo an integer Retry-After value (seconds form) from a curl header dump.
# HTTP-date forms are ignored (only the seconds form is honored).
_hr_retry_after() {
    local hdr_file="$1"
    [[ -f "$hdr_file" ]] || return 0
    local val
    val="$(grep -i '^[[:space:]]*retry-after:' "$hdr_file" 2>/dev/null \
        | tail -n1 | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//')"
    [[ "$val" =~ ^[0-9]+$ ]] && printf '%s' "$val"
    return 0
}
```

- [ ] **Step 6: Run tests to verify they pass.**

Run: `bats test/bats/http_request.bats`
Expected: PASS (6 tests).

- [ ] **Step 7: Lint.**

Run: `bash -n lib/common.sh && shellcheck -e SC2064,SC2129,SC2016 lib/common.sh`
Expected: no errors. (`local -n` nameref requires Bash 4.3+, which the project already targets.)

- [ ] **Step 8: Commit.**

```bash
git add lib/common.sh .config/settings.conf .config/settings.conf.template test/bats/helpers.bash test/bats/http_request.bats
git commit -m "feat(http): shared http_request helper with retry/backoff/throttle"
```

---

### Task 2: Fix the `bc` CVSS severity bug in `lib/nist.sh`

**Files:**
- Modify: `lib/nist.sh:101-110` (severity mapping)
- Create: `test/bats/nist_severity.bats`

**Interfaces:**
- Produces: `_nist_severity <cvss_score>` — echoes `critical|high|medium|low` using `jq` (no `bc`).

- [ ] **Step 1: Write the failing test.**

Create `test/bats/nist_severity.bats`:

```bash
#!/usr/bin/env bats
load helpers

setup() {
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/nist.sh"
}

@test "9.8 maps to critical" { [ "$(_nist_severity 9.8)" = "critical" ]; }
@test "9.0 maps to critical" { [ "$(_nist_severity 9.0)" = "critical" ]; }
@test "7.5 maps to high"     { [ "$(_nist_severity 7.5)" = "high" ]; }
@test "4.0 maps to medium"   { [ "$(_nist_severity 4.0)" = "medium" ]; }
@test "3.9 maps to low"      { [ "$(_nist_severity 3.9)" = "low" ]; }
@test "0 maps to low"        { [ "$(_nist_severity 0)" = "low" ]; }
```

- [ ] **Step 2: Run test to verify it fails.**

Run: `bats test/bats/nist_severity.bats`
Expected: FAIL — `_nist_severity: command not found`.

- [ ] **Step 3: Add the helper and use it.**

In `lib/nist.sh`, add above `nist_search()`:

```bash
# Map a CVSS base score to a severity band using jq (no bc dependency).
_nist_severity() {
    local score="$1"
    local s="${score:-0}"
    if [[ "$(jq -n --argjson s "$s" '$s >= 9.0')" == "true" ]]; then
        printf 'critical'
    elif [[ "$(jq -n --argjson s "$s" '$s >= 7.0')" == "true" ]]; then
        printf 'high'
    elif [[ "$(jq -n --argjson s "$s" '$s >= 4.0')" == "true" ]]; then
        printf 'medium'
    else
        printf 'low'
    fi
}
```

Then replace the `bc`-based block (`lib/nist.sh:101-110`):

```bash
        # Map CVSS score to severity
        if (( $(echo "$base_score >= 9.0" | bc -l 2>/dev/null || echo 0) )); then
            severity="critical"
        elif (( $(echo "$base_score >= 7.0" | bc -l 2>/dev/null || echo 0) )); then
            severity="high"
        elif (( $(echo "$base_score >= 4.0" | bc -l 2>/dev/null || echo 0) )); then
            severity="medium"
        else
            severity="low"
        fi
```

with:

```bash
        # Map CVSS score to severity (jq, not bc)
        severity="$(_nist_severity "$base_score")"
```

- [ ] **Step 4: Run test to verify it passes.**

Run: `bats test/bats/nist_severity.bats`
Expected: PASS (6 tests). Confirm `bc` is gone: `! grep -q 'bc ' lib/nist.sh`.

- [ ] **Step 5: Lint.**

Run: `bash -n lib/nist.sh && shellcheck -e SC2064,SC2129,SC2016 lib/nist.sh`
Expected: no errors.

- [ ] **Step 6: Commit.**

```bash
git add lib/nist.sh test/bats/nist_severity.bats
git commit -m "fix(nist): replace bc CVSS mapping with jq (removes undeclared dep + silent low-severity bug)"
```

---

### Task 3: Route existing modules through `http_request`

**Files:**
- Modify: `lib/otx.sh:22-28`, `lib/nist.sh:16-21` (`_nist_request`), `lib/brave.sh:62-69`, `lib/tavily.sh:96-104` and `lib/tavily.sh:226-234`

**Interfaces:**
- Consumes: `http_request` (Task 1).

This is a mechanical refactor: replace each inline `curl -s -w "\n%{http_code}" ...` block with a local header array + `http_request` call. The `http_code`/`body` split lines directly below each block stay unchanged.

- [ ] **Step 1: Retrofit `lib/otx.sh`.** Replace the `response=$(curl ...)` block (lines ~22-28) with:

```bash
    local -a _otx_hdrs=(-H "X-OTX-API-KEY: $OTX_API_KEY")
    local response http_code body
    response=$(http_request GET "https://otx.alienvault.com/api/v1/search/pulses?q=${encoded_keyword}" _otx_hdrs)
```

- [ ] **Step 2: Retrofit `lib/nist.sh` `_nist_request`.** Replace its body (lines ~11-21) with:

```bash
    local -a _nist_hdrs=()
    if [[ "$use_key" == "true" && -n "${NIST_API_KEY:-}" ]]; then
        _nist_hdrs=(-H "apiKey: $NIST_API_KEY")
    fi
    http_request GET "$url" _nist_hdrs
```

- [ ] **Step 3: Retrofit `lib/brave.sh` `_brave_query`.** Replace the `response=$(curl ...)` block (lines ~62-69) with:

```bash
    local -a _brave_hdrs=(
        -H "Accept: application/json"
        -H "Accept-Encoding: gzip"
        -H "X-Subscription-Token: $BRAVE_API_KEY"
        --compressed
    )
    local response http_code body
    response=$(http_request GET "https://api.search.brave.com/res/v1/web/search?q=${encoded_query}&count=${count}&freshness=${freshness_param}" _brave_hdrs)
```

- [ ] **Step 4: Retrofit `lib/tavily.sh`** in BOTH `_tavily_query` (lines ~96-104) and `_tavily_precision_query` (lines ~226-234). Replace each `response=$(echo "$request_body" | curl ... -d @- ...)` block with:

```bash
    local -a _tavily_hdrs=(
        -H "Content-Type: application/json"
        -H "Authorization: Bearer $TAVILY_API_KEY"
    )
    local response http_code body
    response=$(http_request POST "https://api.tavily.com/search" _tavily_hdrs "$request_body")
```

- [ ] **Step 5: Verify behavior is unchanged via a dry run.**

Run: `bash -n lib/otx.sh lib/nist.sh lib/brave.sh lib/tavily.sh && bash look4gold.sh --dry-run --verbose`
Expected: clean syntax; dry run completes and prints the scan summary with no errors (dry run makes no API calls, but confirms the modules still source and parse).

- [ ] **Step 6: Re-run prior tests to confirm no regression.**

Run: `bats test/bats/nist_severity.bats test/bats/http_request.bats`
Expected: PASS.

- [ ] **Step 7: Lint.**

Run: `shellcheck -e SC2064,SC2129,SC2016 lib/otx.sh lib/nist.sh lib/brave.sh lib/tavily.sh`
Expected: no errors.

- [ ] **Step 8: Commit.**

```bash
git add lib/otx.sh lib/nist.sh lib/brave.sh lib/tavily.sh
git commit -m "refactor(http): route brave/tavily/nist/otx through http_request for retry/throttle"
```

---

### Task 4: crt.sh Certificate Transparency module

**Files:**
- Create: `lib/crtsh.sh`
- Create: `test/bats/crtsh.bats`

**Interfaces:**
- Produces: `crtsh_search <keyword>`. Emits `SEARCH_CERT`/`crtsh` records; `details` = `{ domain, url, issuer_name, not_before, not_after, cert_id }`.
- Consumes: `http_request`, `url_encode`, `emit_audit_record`, `log_*`.

- [ ] **Step 1: Write the failing test.**

Create `test/bats/crtsh.bats`:

```bash
#!/usr/bin/env bats
load helpers

setup() {
    load_common
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/audit.sh"
    export AUDIT_OUTPUT_FILE="$BATS_TEST_TMPDIR/out.jsonl"
    : > "$AUDIT_OUTPUT_FILE"
    _SCAN_ID="test-scan"; _FINDING_COUNT=0; _RECORD_COUNT=0
    export CRTSH_ENABLED=true DRY_RUN=false
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/crtsh.sh"
}

@test "emits one SEARCH_CERT record per unique domain" {
    http_request() { printf '%s\n200' '[{"name_value":"a.example.com\nexample.com","issuer_name":"CA","not_before":"2026-01-01","not_after":"2026-04-01","id":1},{"name_value":"a.example.com","issuer_name":"CA","not_before":"2026-02-01","not_after":"2026-05-01","id":2}]'; }
    crtsh_search "example" || true
    run jq -s '[.[] | select(.event_type=="SEARCH_CERT" and .outcome=="found")] | length' "$AUDIT_OUTPUT_FILE"
    [ "$output" -eq 2 ]
    run jq -rs '[.[] | select(.outcome=="found") | .details.domain] | sort | join(",")' "$AUDIT_OUTPUT_FILE"
    [ "$output" = "a.example.com,example.com" ]
}

@test "emits not_found on empty array" {
    http_request() { printf '%s\n200' '[]'; }
    crtsh_search "example" || true
    run jq -s '[.[] | select(.outcome=="not_found")] | length' "$AUDIT_OUTPUT_FILE"
    [ "$output" -eq 1 ]
}

@test "skips when disabled" {
    export CRTSH_ENABLED=false
    http_request() { printf '%s\n200' '[{"name_value":"x.example.com"}]'; }
    crtsh_search "example" || true
    [ ! -s "$AUDIT_OUTPUT_FILE" ]
}
```

- [ ] **Step 2: Run test to verify it fails.**

Run: `bats test/bats/crtsh.bats`
Expected: FAIL — `crtsh_search: command not found`.

- [ ] **Step 3: Implement `lib/crtsh.sh`.**

```bash
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
        details="$(echo "$rows" | jq -c ".[$i] + {url: (\"https://\" + .domain)}")"
        emit_audit_record "SEARCH_CERT" "crtsh" "$keyword" "found" "low" \
            "Certificate domain: $domain" "$details"
    done
}
```

- [ ] **Step 4: Run test to verify it passes.**

Run: `bats test/bats/crtsh.bats`
Expected: PASS (3 tests).

- [ ] **Step 5: Lint.**

Run: `bash -n lib/crtsh.sh && shellcheck -e SC2064,SC2129,SC2016 lib/crtsh.sh`
Expected: no errors.

- [ ] **Step 6: Commit.**

```bash
git add lib/crtsh.sh test/bats/crtsh.bats
git commit -m "feat(crtsh): add Certificate Transparency source (SEARCH_CERT)"
```

---

### Task 5: GitHub code search module

**Files:**
- Create: `lib/github.sh`
- Create: `test/bats/github.bats`

**Interfaces:**
- Produces: `github_search <keyword>` and `_github_query <keyword> <query> <label>`. Emits `SEARCH_CODE`/`github_code` records; `details` = `{ repo, path, html_url, snippet, query_label }`.
- Consumes: `http_request`, `url_encode`, `emit_audit_record`, `log_*`, `GITHUB_TOKEN`, `GITHUB_ORGS`.

- [ ] **Step 1: Write the failing test.**

Create `test/bats/github.bats`:

```bash
#!/usr/bin/env bats
load helpers

setup() {
    load_common
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/audit.sh"
    export AUDIT_OUTPUT_FILE="$BATS_TEST_TMPDIR/out.jsonl"
    : > "$AUDIT_OUTPUT_FILE"
    _SCAN_ID="test-scan"; _FINDING_COUNT=0; _RECORD_COUNT=0
    export GITHUB_TOKEN="x" DRY_RUN=false
    unset GITHUB_ORGS
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/github.sh"
}

@test "emits a SEARCH_CODE record per item" {
    http_request() { printf '%s\n200' '{"total_count":1,"items":[{"repository":{"full_name":"acme/leak"},"path":"cfg/secrets.env","html_url":"https://github.com/acme/leak/blob/main/cfg/secrets.env","text_matches":[{"fragment":"API_KEY=abc"}]}]}'; }
    github_search "acme" || true
    run jq -s '[.[] | select(.event_type=="SEARCH_CODE" and .outcome=="found")] | length' "$AUDIT_OUTPUT_FILE"
    [ "$output" -eq 1 ]
    run jq -rs '.[0].details.html_url' "$AUDIT_OUTPUT_FILE"
    [ "$output" = "https://github.com/acme/leak/blob/main/cfg/secrets.env" ]
}

@test "runs an extra org-scoped pass when GITHUB_ORGS set" {
    export GITHUB_ORGS="acme-corp, acme-labs"
    _github_query() { echo "CALL:$3" >> "$BATS_TEST_TMPDIR/calls.log"; }
    github_search "acme" || true
    run cat "$BATS_TEST_TMPDIR/calls.log"
    [[ "$output" == *"CALL:broad"* ]]
    [[ "$output" == *"CALL:org_acme-corp"* ]]
    [[ "$output" == *"CALL:org_acme-labs"* ]]
}

@test "422 is treated as no results (no error record)" {
    http_request() { printf '%s\n422' '{"message":"Validation Failed"}'; }
    github_search "acme" || true
    run jq -s 'length' "$AUDIT_OUTPUT_FILE"
    [ "$output" -eq 0 ]
}

@test "skips when token unset" {
    unset GITHUB_TOKEN
    http_request() { printf '%s\n200' '{"items":[{"html_url":"x"}]}'; }
    github_search "acme" || true
    [ ! -s "$AUDIT_OUTPUT_FILE" ]
}
```

- [ ] **Step 2: Run test to verify it fails.**

Run: `bats test/bats/github.bats`
Expected: FAIL — `github_search: command not found`.

- [ ] **Step 3: Implement `lib/github.sh`.**

```bash
#!/usr/bin/env bash
# lib/github.sh — GitHub code search source.
# Searches public code file contents for a keyword (broad pass) and, when
# GITHUB_ORGS is set, adds one org-scoped pass per org. Emits SEARCH_CODE
# records; disclosure-semantics (feeds URL dedup + AI).
# Rate limit is ~10 req/min for code search — retry/backoff (http_request)
# handles secondary rate limits (403 w/ Retry-After, or 429).

github_search() {
    local keyword="$1"

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
        snippet="$(echo "$body" | jq -r ".items[$i].text_matches[0].fragment // \"\"" 2>/dev/null || echo "")"
        details="$(jq -nc \
            --arg r "$repo" --arg p "$path" --arg u "$html_url" \
            --arg s "$snippet" --arg l "$label" \
            '{repo: $r, path: $p, html_url: $u, snippet: $s, query_label: $l}')"
        emit_audit_record "SEARCH_CODE" "github_code" "$keyword" "found" "low" \
            "Code match: ${repo}/${path}" "$details"
    done
}
```

- [ ] **Step 4: Run test to verify it passes.**

Run: `bats test/bats/github.bats`
Expected: PASS (4 tests).

- [ ] **Step 5: Lint.**

Run: `bash -n lib/github.sh && shellcheck -e SC2064,SC2129,SC2016 lib/github.sh`
Expected: no errors.

- [ ] **Step 6: Commit.**

```bash
git add lib/github.sh test/bats/github.bats
git commit -m "feat(github): add code-search source with optional org scoping (SEARCH_CODE)"
```

---

### Task 6: URLScan.io module

**Files:**
- Create: `lib/urlscan.sh`
- Create: `test/bats/urlscan.bats`

**Interfaces:**
- Produces: `urlscan_search <keyword>`. Emits `CHECK_PHISH`/`urlscan` records; `details` = `{ url, page_domain, scan_time, result_uuid, malicious }`. Description carries the page URL so the default (non-web) dedup keys effectively by URL.
- Consumes: `http_request`, `url_encode`, `emit_audit_record`, `log_*`, `URLSCAN_API_KEY`.

- [ ] **Step 1: Write the failing test.**

Create `test/bats/urlscan.bats`:

```bash
#!/usr/bin/env bats
load helpers

setup() {
    load_common
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/audit.sh"
    export AUDIT_OUTPUT_FILE="$BATS_TEST_TMPDIR/out.jsonl"
    : > "$AUDIT_OUTPUT_FILE"
    _SCAN_ID="test-scan"; _FINDING_COUNT=0; _RECORD_COUNT=0
    export URLSCAN_API_KEY="x" DRY_RUN=false
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/urlscan.sh"
}

@test "emits CHECK_PHISH and raises severity on malicious verdict" {
    http_request() { printf '%s\n200' '{"results":[{"page":{"url":"https://acme-login.test/","domain":"acme-login.test"},"task":{"time":"2026-06-01T00:00:00Z"},"_id":"abc","verdicts":{"overall":{"malicious":true}}}]}'; }
    urlscan_search "acme" || true
    run jq -rs '.[0].event_type' "$AUDIT_OUTPUT_FILE"
    [ "$output" = "CHECK_PHISH" ]
    run jq -rs '.[0].severity' "$AUDIT_OUTPUT_FILE"
    [ "$output" = "medium" ]
}

@test "non-malicious result is low severity" {
    http_request() { printf '%s\n200' '{"results":[{"page":{"url":"https://acme.test/","domain":"acme.test"},"task":{"time":"t"},"_id":"z"}]}'; }
    urlscan_search "acme" || true
    run jq -rs '.[0].severity' "$AUDIT_OUTPUT_FILE"
    [ "$output" = "low" ]
}

@test "emits not_found on empty results" {
    http_request() { printf '%s\n200' '{"results":[]}'; }
    urlscan_search "acme" || true
    run jq -s '[.[] | select(.outcome=="not_found")] | length' "$AUDIT_OUTPUT_FILE"
    [ "$output" -eq 1 ]
}

@test "skips when key unset" {
    unset URLSCAN_API_KEY
    http_request() { printf '%s\n200' '{"results":[{"page":{"url":"x"}}]}'; }
    urlscan_search "acme" || true
    [ ! -s "$AUDIT_OUTPUT_FILE" ]
}
```

- [ ] **Step 2: Run test to verify it fails.**

Run: `bats test/bats/urlscan.bats`
Expected: FAIL — `urlscan_search: command not found`.

- [ ] **Step 3: Implement `lib/urlscan.sh`.**

```bash
#!/usr/bin/env bash
# lib/urlscan.sh — URLScan.io search source (brand / phishing page monitoring).
# Emits CHECK_PHISH records; standalone-semantics (rendered like OTX/NIST).

urlscan_search() {
    local keyword="$1"

    if [[ -z "${URLSCAN_API_KEY:-}" ]]; then
        log_warn "URLSCAN_API_KEY not set, skipping URLScan.io search"
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would call URLScan.io for: $keyword"
        return 0
    fi

    local count="${SEARCH_RESULT_COUNT:-10}"
    local encoded
    encoded="$(url_encode "$keyword")"
    local url="https://urlscan.io/api/v1/search/?q=${encoded}&size=${count}"

    log_info "URLScan.io: querying '$keyword'"

    local -a _us_hdrs=(-H "API-Key: $URLSCAN_API_KEY" -H "Accept: application/json")
    local response http_code body
    response="$(http_request GET "$url" _us_hdrs)"
    http_code="$(echo "$response" | tail -n1)"
    body="$(echo "$response" | sed '$d')"

    if [[ "$http_code" -ne 200 ]]; then
        log_error "URLScan.io returned HTTP $http_code for '$keyword'"
        emit_audit_record "CHECK_PHISH" "urlscan" "$keyword" "error" "info" \
            "URLScan.io API error: HTTP $http_code" \
            "$(jq -nc --arg code "$http_code" '{http_code: $code}')"
        return 1
    fi

    local rcount
    rcount="$(echo "$body" | jq '.results | length' 2>/dev/null || echo 0)"

    if [[ "$rcount" -eq 0 ]]; then
        log_info "URLScan.io: no results for '$keyword'"
        emit_audit_record "CHECK_PHISH" "urlscan" "$keyword" "not_found" "info" \
            "No URLScan.io results for keyword" "null"
        return 0
    fi

    log_info "URLScan.io: $rcount result(s) for '$keyword'"

    local i page_url page_domain scan_time result_uuid malicious severity details
    for (( i=0; i<rcount; i++ )); do
        page_url="$(echo "$body" | jq -r ".results[$i].page.url // \"\"")"
        page_domain="$(echo "$body" | jq -r ".results[$i].page.domain // \"\"")"
        scan_time="$(echo "$body" | jq -r ".results[$i].task.time // \"\"")"
        result_uuid="$(echo "$body" | jq -r ".results[$i]._id // \"\"")"
        malicious="$(echo "$body" | jq -r ".results[$i].verdicts.overall.malicious // false" 2>/dev/null || echo false)"
        severity="low"
        [[ "$malicious" == "true" ]] && severity="medium"
        details="$(jq -nc \
            --arg u "$page_url" --arg d "$page_domain" --arg t "$scan_time" \
            --arg id "$result_uuid" --argjson m "${malicious:-false}" \
            '{url: $u, page_domain: $d, scan_time: $t, result_uuid: $id, malicious: $m}')"
        emit_audit_record "CHECK_PHISH" "urlscan" "$keyword" "found" "$severity" \
            "URLScan result: ${page_url}" "$details"
    done
}
```

- [ ] **Step 4: Run test to verify it passes.**

Run: `bats test/bats/urlscan.bats`
Expected: PASS (4 tests).

- [ ] **Step 5: Lint.**

Run: `bash -n lib/urlscan.sh && shellcheck -e SC2064,SC2129,SC2016 lib/urlscan.sh`
Expected: no errors.

- [ ] **Step 6: Commit.**

```bash
git add lib/urlscan.sh test/bats/urlscan.bats
git commit -m "feat(urlscan): add URLScan.io brand/phishing source (CHECK_PHISH)"
```

---

### Task 7: Wire new sources into the scan loop + dedup

**Files:**
- Modify: `look4gold.sh:96` (source lines), `look4gold.sh:204` (calls), `look4gold.sh:211-219` (dedup `jq`)

**Interfaces:**
- Consumes: `crtsh_search`, `github_search`, `urlscan_search` (Tasks 4-6).

- [ ] **Step 1: Source the new modules.** After `source "$SCRIPT_DIR/lib/fourchan.sh"` (line 96), add:

```bash
source "$SCRIPT_DIR/lib/crtsh.sh"
source "$SCRIPT_DIR/lib/github.sh"
source "$SCRIPT_DIR/lib/urlscan.sh"
```

- [ ] **Step 2: Add the calls.** After `fourchan_search "$keyword" || true` (line 204), add:

```bash
    crtsh_search "$keyword" || true
    github_search "$keyword" || true
    urlscan_search "$keyword" || true
```

- [ ] **Step 3: Extend the AI-dedup `jq`.** Replace the `group_by(...)` expression (lines ~213-217) with:

```bash
            | group_by(
                if (.event_type == "SEARCH_WEB" or .event_type == "SEARCH_CHAN") then (.details.url // .description)
                elif (.event_type == "SEARCH_CODE") then (.details.html_url // .description)
                elif (.event_type == "SEARCH_CERT") then (.details.domain // .description)
                else (.event_type + "|" + .source + "|" + .description)
                end
              )
```

- [ ] **Step 4: Verify with a dry run and a syntax check.**

Run: `bash -n look4gold.sh && bash look4gold.sh --dry-run --verbose 2>&1 | tail -20`
Expected: dry run completes; log shows the new modules' `[DRY RUN] Would ...` lines for each keyword; scan summary prints with no errors.

- [ ] **Step 5: Lint.**

Run: `shellcheck -e SC2064,SC2129,SC2016 look4gold.sh`
Expected: no errors.

- [ ] **Step 6: Commit.**

```bash
git add look4gold.sh
git commit -m "feat(scan): run crtsh/github/urlscan per keyword and extend URL/domain dedup"
```

---

### Task 8: Config template, setup.sh prompts, and quota probes

**Files:**
- Modify: `.config/apis.conf.template`
- Modify: `setup.sh` (defaults block ~65-71, prompts ~115, apis.conf heredoc ~150-163, validation ~235-243)
- Modify: `lib/common.sh` `check_api_quotas` (add GitHub + URLScan probes)

**Interfaces:**
- Consumes: nothing new. Produces: populated `apis.conf` fields `GITHUB_TOKEN`, `GITHUB_ORGS`, `URLSCAN_API_KEY`, `CRTSH_ENABLED`.

- [ ] **Step 1: Extend `.config/apis.conf.template`.** Append:

```bash

# --- GitHub code search ---
# Personal access token (classic or fine-grained); no scopes are needed to
# search PUBLIC code. Create one at https://github.com/settings/tokens
GITHUB_TOKEN=""
# OPSEC: optional space/comma-separated GitHub orgs to scope searches to.
# This value identifies your organization — it is written ONLY to this local,
# gitignored, chmod-600 apis.conf and is NEVER committed. Leave blank to run
# broad keyword-only code searches.
GITHUB_ORGS=""

# --- URLScan.io (brand / phishing page monitoring) ---
# Free API key: https://urlscan.io/user/signup
URLSCAN_API_KEY=""

# --- crt.sh Certificate Transparency (no key required) ---
# Surfaces lookalike/phishing domains and shadow-IT certs. Set "false" to disable.
CRTSH_ENABLED="true"
```

- [ ] **Step 2: Add defaults to setup.sh.** In the "Load existing keys" block (after `CSE_ID=""`, line ~70), add:

```bash
GITHUB_TOKEN=""
GITHUB_ORGS=""
URLSCAN_API_KEY=""
CRTSH_ENABLED="true"
```

- [ ] **Step 3: Add key prompts.** After the xAI prompt block (after line 116, before the CSE section), add:

```bash
echo "  GitHub code search — https://github.com/settings/tokens (no scopes needed for public code)"
GITHUB_TOKEN=$(prompt_key "GITHUB_TOKEN" "$GITHUB_TOKEN" "GitHub")
echo
echo "  URLScan.io — https://urlscan.io/user/signup"
URLSCAN_API_KEY=$(prompt_key "URLSCAN_API_KEY" "$URLSCAN_API_KEY" "URLScan.io")
echo
# GITHUB_ORGS is OPSEC-sensitive but not a secret — plain read, stored locally only.
echo "  GitHub orgs to scope code search (optional; OPSEC-sensitive — stored locally, never committed)"
if [[ -n "$GITHUB_ORGS" ]]; then
    read -rp "  GITHUB_ORGS [$GITHUB_ORGS] (space/comma separated, Enter to keep): " _orgs_input
    GITHUB_ORGS="${_orgs_input:-$GITHUB_ORGS}"
else
    read -rp "  GITHUB_ORGS (space/comma separated, Enter to skip): " GITHUB_ORGS
fi
echo
```

- [ ] **Step 4: Extend the apis.conf writeout heredoc.** In the `cat > "$apis_file" <<EOF` block, after the `XAI_API_KEY="$XAI_API_KEY"` line, add:

```bash
GITHUB_TOKEN="$GITHUB_TOKEN"
GITHUB_ORGS="$GITHUB_ORGS"
URLSCAN_API_KEY="$URLSCAN_API_KEY"
CRTSH_ENABLED="$CRTSH_ENABLED"
```

- [ ] **Step 5: Add validation probes.** After the xAI validation block (line ~243), add:

```bash
if [[ -z "$GITHUB_TOKEN" ]]; then
    echo "  [SKIP] GitHub code search — no token provided"
elif curl -sf --max-time 15 --max-redirs 3 --proto =https \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    "https://api.github.com/rate_limit" &>/dev/null; then
    echo "  [OK]   GitHub code search"
else
    echo "  [FAIL] GitHub code search — token may be invalid (check manually)"
fi

if [[ -z "$URLSCAN_API_KEY" ]]; then
    echo "  [SKIP] URLScan.io — no key provided"
elif curl -sf --max-time 15 --max-redirs 3 --proto =https \
    -H "API-Key: $URLSCAN_API_KEY" \
    "https://urlscan.io/api/v1/search/?q=test&size=1" &>/dev/null; then
    echo "  [OK]   URLScan.io"
else
    echo "  [FAIL] URLScan.io — key may be invalid (check manually)"
fi
```

- [ ] **Step 6: Add runtime quota probes to `check_api_quotas` in `lib/common.sh`.** After the Tavily block (before the summary/return), add a GitHub and a URLScan block mirroring the existing style:

```bash
    # --- GitHub code search ---
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        total=$((total + 1))
        local gh_code
        gh_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --proto =https --max-time 15 --max-redirs 5 \
            -H "Authorization: Bearer $GITHUB_TOKEN" \
            "https://api.github.com/rate_limit" 2>/dev/null) || gh_code="000"
        if [[ "$gh_code" == "200" ]]; then
            _api_status[GitHub]="ready"; ready=$((ready + 1))
        elif [[ "$gh_code" == "401" || "$gh_code" == "403" ]]; then
            _api_status[GitHub]="invalid token (HTTP $gh_code)"
            log_error "GitHub code search: invalid token (HTTP $gh_code)"
        elif [[ "$gh_code" == "000" ]]; then
            _api_status[GitHub]="connection failed"
            log_error "GitHub code search: connection failed"
        else
            _api_status[GitHub]="unexpected HTTP $gh_code"
            log_warn "GitHub code search: unexpected HTTP $gh_code"
        fi
    else
        _api_status[GitHub]="no token configured"
    fi

    # --- URLScan.io ---
    if [[ -n "${URLSCAN_API_KEY:-}" ]]; then
        total=$((total + 1))
        local us_code
        us_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --proto =https --max-time 15 --max-redirs 5 \
            -H "API-Key: $URLSCAN_API_KEY" \
            "https://urlscan.io/api/v1/search/?q=test&size=1" 2>/dev/null) || us_code="000"
        if [[ "$us_code" == "200" ]]; then
            _api_status[URLScan]="ready"; ready=$((ready + 1))
        elif [[ "$us_code" == "401" || "$us_code" == "403" ]]; then
            _api_status[URLScan]="invalid key (HTTP $us_code)"
            log_error "URLScan.io: invalid key (HTTP $us_code)"
        elif [[ "$us_code" == "000" ]]; then
            _api_status[URLScan]="connection failed"
            log_error "URLScan.io: connection failed"
        else
            _api_status[URLScan]="unexpected HTTP $us_code"
            log_warn "URLScan.io: unexpected HTTP $us_code"
        fi
    else
        _api_status[URLScan]="no key configured"
    fi
```

(Confirm the loop that prints `_api_status` iterates all keys generically; the existing summary loop does. If it hard-codes source names, add `GitHub` and `URLScan` to that list.)

- [ ] **Step 7: Verify with a dry run.**

Run: `bash -n setup.sh lib/common.sh && bash look4gold.sh --dry-run --verbose 2>&1 | grep -i -E 'github|urlscan|api status'`
Expected: the API-status check runs without error and reports GitHub/URLScan as "no token/key configured" (or "ready" if keys are set).

- [ ] **Step 8: Lint.**

Run: `shellcheck -e SC2064,SC2129,SC2016 setup.sh lib/common.sh`
Expected: no errors.

- [ ] **Step 9: Commit.**

```bash
git add .config/apis.conf.template setup.sh lib/common.sh
git commit -m "feat(config): add GitHub/URLScan/crt.sh keys, setup prompts, and quota probes"
```

---

### Task 9: Render new event types in the HTML report

**Files:**
- Modify: `lib/report.sh:824-829` (Source Findings `jq` select)

**Interfaces:**
- Consumes: JSONL records with event types `SEARCH_CODE`, `SEARCH_CERT`, `CHECK_PHISH`.

- [ ] **Step 1: Extend the Source Findings selector.** Replace the `source_urls=$(jq ...)` block (lines 826-829) with:

```bash
    source_urls=$(jq -r --arg kw "$keyword" '
        select(.keyword == $kw
               and (.event_type == "SEARCH_WEB" or .event_type == "SEARCH_CHAN"
                    or .event_type == "SEARCH_CODE" or .event_type == "SEARCH_CERT"
                    or .event_type == "CHECK_PHISH")
               and .outcome == "found")
        | (.details.url // .details.html_url
           // (if (.details.domain // "") != "" then ("https://" + .details.domain) else empty end))
    ' "$jsonl_file" 2>/dev/null | sort -u)
```

- [ ] **Step 2: Build a fixture and generate a report to verify rendering.**

```bash
mkdir -p /tmp/l4g-test
cat > /tmp/l4g-test/in.jsonl <<'JSON'
{"timestamp":"2026-07-02T00:00:00Z","event_type":"SCAN_START","source":"look4gold","keyword":"N/A","outcome":"started","severity":"info","description":"s","details":{"keyword_count":1},"control_ref":"AU-13","scan_id":"t"}
{"timestamp":"2026-07-02T00:00:01Z","event_type":"SEARCH_CODE","source":"github_code","keyword":"acme","outcome":"found","severity":"low","description":"Code match: acme/leak/cfg.env","details":{"html_url":"https://github.com/acme/leak/blob/main/cfg.env"},"control_ref":"AU-13","scan_id":"t"}
{"timestamp":"2026-07-02T00:00:02Z","event_type":"SEARCH_CERT","source":"crtsh","keyword":"acme","outcome":"found","severity":"low","description":"Certificate domain: acme-login.test","details":{"domain":"acme-login.test"},"control_ref":"AU-13","scan_id":"t"}
{"timestamp":"2026-07-02T00:00:03Z","event_type":"CHECK_PHISH","source":"urlscan","keyword":"acme","outcome":"found","severity":"medium","description":"URLScan result: https://acme-login.test/","details":{"url":"https://acme-login.test/"},"control_ref":"AU-13","scan_id":"t"}
{"timestamp":"2026-07-02T00:00:04Z","event_type":"SCAN_END","source":"look4gold","keyword":"N/A","outcome":"completed","severity":"info","description":"e","details":{"total_records":3,"total_findings":3},"control_ref":"AU-13","scan_id":"t"}
JSON
bash -c 'source lib/common.sh; source lib/report.sh; generate_html /tmp/l4g-test/in.jsonl /tmp/l4g-test/out.html'
grep -c -E 'github.com/acme/leak|acme-login.test' /tmp/l4g-test/out.html
```

Expected: the `grep -c` returns a nonzero count (all three new-source URLs/domains appear as links in the Source Findings section).

- [ ] **Step 3: Lint.**

Run: `bash -n lib/report.sh && shellcheck -e SC2064,SC2129,SC2016 lib/report.sh`
Expected: no errors.

- [ ] **Step 4: Commit.**

```bash
git add lib/report.sh
git commit -m "feat(report): render SEARCH_CODE/SEARCH_CERT/CHECK_PHISH in HTML Source Findings"
```

---

### Task 10: Documentation (README)

**Files:**
- Modify: `README.md` (source table, API-keys table, classification notice, dependency section)

- [ ] **Step 1: Add the three sources to the "What It Does" source table.** Add rows:

```markdown
| **GitHub Code Search** | Public repository file contents matching keywords (leaked secrets/config), with optional org scoping | [GitHub code search](https://docs.github.com/en/rest/search) |
| **crt.sh** | Certificate Transparency logs — surfaces lookalike/phishing domains and shadow-IT certs | [crt.sh](https://crt.sh/) |
| **URLScan.io** | Submitted-and-screenshotted URLs matching a brand/domain — phishing and brand-abuse pages | [URLScan.io](https://urlscan.io/) |
```

- [ ] **Step 2: Add the keys to the "API Keys" table.** Add rows:

```markdown
| GitHub | 5,000 req/hr (code search ~10/min) | https://github.com/settings/tokens |
| URLScan.io | Free tier | https://urlscan.io/user/signup |
| crt.sh | No key required | https://crt.sh/ |
```

- [ ] **Step 3: Extend the classification notice** to list the new third-party endpoints. Change the parenthetical list of APIs (Brave, Tavily, NIST NVD, AlienVault OTX, xAI) to also include **GitHub, crt.sh, URLScan.io**. Add one sentence under the notice:

```markdown
> **OPSEC note:** `GITHUB_ORGS` (optional, used to scope GitHub code search to your organization) identifies your organization. It is stored only in the local, gitignored `.config/apis.conf` and is never committed. Leave it blank to run broad keyword-only code searches.
```

- [ ] **Step 4: Note the resilience settings.** In the settings/config section, document that all API calls now share retry/backoff/throttle via `RETRY_MAX_ATTEMPTS`, `API_TIMEOUT`, `RETRY_BACKOFF_BASE`, and `HTTP_THROTTLE_SECONDS` in `settings.conf`.

- [ ] **Step 5: Verify and commit.**

Run: `grep -E 'GitHub|crt.sh|URLScan|HTTP_THROTTLE_SECONDS' README.md`
Expected: matches present.

```bash
git add README.md
git commit -m "docs: document new sources, OPSEC note for GITHUB_ORGS, and resilience settings"
```

---

## Self-Review

**Spec coverage:**
- Shared `http_request()` with retry/backoff/throttle + live `RETRY_MAX_ATTEMPTS`/`API_TIMEOUT` → Task 1. ✅
- Retrofit brave/tavily/nist/otx → Task 3. ✅
- `bc`→`jq` NIST fix → Task 2. ✅
- crt.sh (`SEARCH_CERT`, dedup by domain, feeds AI) → Tasks 4, 7. ✅
- GitHub (`SEARCH_CODE`, broad + org passes, OPSEC `GITHUB_ORGS`, 422 handling, dedup by html_url) → Tasks 5, 7. ✅
- URLScan (`CHECK_PHISH`, standalone, malicious→medium) → Tasks 6, 7. ✅
- New settings (`HTTP_THROTTLE_SECONDS`, `RETRY_BACKOFF_BASE`) → Task 1. ✅
- apis.conf template + setup prompts + quota probes → Task 8. ✅
- HTML report rendering → Task 9. ✅
- README/docs + classification notice → Task 10. ✅
- No new hard deps; `bc` removed → Tasks 2, 5, 6 (curl+jq only). ✅

**Placeholder scan:** No TBD/TODO; every code step shows full code; every test step shows the assertion. ✅

**Type/name consistency:** `http_request`/`_hr_sleep`/`_hr_retry_after`, `_nist_severity`, `crtsh_search`, `github_search`/`_github_query`, `urlscan_search` used consistently across tasks. Event types `SEARCH_CERT`/`SEARCH_CODE`/`CHECK_PHISH` and `details` field names (`domain`, `html_url`, `url`) match between emitters (Tasks 4-6), the dedup `jq` (Task 7), and the report selector (Task 9). ✅

**Note for the executor:** if `check_api_quotas`'s summary loop enumerates a fixed list of source names rather than iterating the `_api_status` associative array, add `GitHub` and `URLScan` to that list (Task 8, Step 6).
