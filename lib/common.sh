#!/usr/bin/env bash
# lib/common.sh — Config loading, logging, validation utilities

# Resolve project root relative to this file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Default config directory (can be overridden via --config-dir)
CONFIG_DIR="${CONFIG_DIR:-$SCRIPT_DIR/.config}"

# Log levels
declare -A _LOG_LEVELS=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3)
_CURRENT_LOG_LEVEL=1

# Secure temporary directory (created once, cleaned up on exit)
_SECURE_TMPDIR=""

_init_secure_tmpdir() {
    if [[ -z "$_SECURE_TMPDIR" ]]; then
        _SECURE_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/look4gold.XXXXXX")
        chmod 700 "$_SECURE_TMPDIR"
        # Clean up on any exit (normal, error, signal)
        trap 'rm -rf "$_SECURE_TMPDIR"' EXIT
    fi
}

# Create a temp file inside the secure directory
_mktemp() {
    _init_secure_tmpdir
    mktemp "$_SECURE_TMPDIR/tmp.XXXXXX"
}

_log() {
    local level="$1"; shift
    local level_num="${_LOG_LEVELS[$level]:-1}"
    if (( level_num >= _CURRENT_LOG_LEVEL )); then
        printf '[%s] [%-5s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$level" "$*" >&2
    fi
}

log_debug() { _log "DEBUG" "$@"; }
log_info()  { _log "INFO"  "$@"; }
log_warn()  { _log "WARN"  "$@"; }
log_error() { _log "ERROR" "$@"; }

check_deps() {
    local missing=()
    for cmd in curl jq; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        log_error "Missing required dependencies: ${missing[*]}"
        log_error "Install them with your package manager (e.g., sudo apt install ${missing[*]})"
        return 1
    fi
}

load_config() {
    local settings_file="$CONFIG_DIR/settings.conf"
    local apis_file="$CONFIG_DIR/apis.conf"

    # Enforce restrictive permissions on config directory
    chmod 700 "$CONFIG_DIR" 2>/dev/null || true

    if [[ ! -f "$settings_file" ]]; then
        if [[ -e "$settings_file" ]]; then
            log_error "Settings path exists but is not a regular file: $settings_file"
        else
            log_error "Settings file not found: $settings_file"
        fi
        return 1
    fi
    if [[ ! -r "$settings_file" ]]; then
        log_error "Settings file is not readable (check permissions): $settings_file"
        return 1
    fi
    # shellcheck source=/dev/null
    source "$settings_file"

    if [[ ! -f "$apis_file" ]]; then
        log_error "API keys file not found: $apis_file"
        log_error "Run setup.sh first, or copy apis.conf.template to apis.conf and fill in your keys."
        return 1
    fi
    if [[ ! -r "$apis_file" ]]; then
        log_error "API keys file is not readable (check permissions): $apis_file"
        return 1
    fi
    # shellcheck source=/dev/null
    source "$apis_file"

    # Set log level from config
    if [[ -n "${LOG_LEVEL:-}" ]] && [[ -n "${_LOG_LEVELS[$LOG_LEVEL]:-}" ]]; then
        _CURRENT_LOG_LEVEL="${_LOG_LEVELS[$LOG_LEVEL]}"
    fi

    # Normalize boolean config values (accept True/TRUE/1/yes -> true)
    _normalize_bool() {
        local val="${1,,}"  # lowercase
        case "$val" in
            true|1|yes) echo "true" ;;
            *)          echo "false" ;;
        esac
    }
    FOURCHAN_ENABLED="$(_normalize_bool "${FOURCHAN_ENABLED:-false}")"
    XAI_WEB_SEARCH="$(_normalize_bool "${XAI_WEB_SEARCH:-true}")"

    # Support DORK_MODE as primary name, fall back to legacy BRAVE_DORK_MODE
    DORK_MODE="${DORK_MODE:-${BRAVE_DORK_MODE:-security}}"
    export DORK_MODE

    # Validate at least one API key or keyless source is enabled
    local has_source=false
    for key_var in BRAVE_API_KEY TAVILY_API_KEY NIST_API_KEY OTX_API_KEY XAI_API_KEY; do
        if [[ -n "${!key_var:-}" ]]; then
            has_source=true
            break
        fi
    done
    # 4chan archives now use web search dorks — require Brave or Tavily API key
    if [[ "$FOURCHAN_ENABLED" == "true" ]] && [[ -n "${BRAVE_API_KEY:-}" || -n "${TAVILY_API_KEY:-}" ]]; then
        has_source=true
    fi
    if [[ "$has_source" == "false" ]]; then
        log_error "No API keys configured and no keyless sources enabled. Run setup.sh or edit $apis_file."
        return 1
    fi
}

load_keywords() {
    local keywords_file="${KEYWORDS_FILE:-$CONFIG_DIR/keywords.conf}"

    if [[ ! -f "$keywords_file" ]]; then
        log_error "Keywords file not found: $keywords_file"
        log_error "Run setup.sh or copy keywords.conf.template to keywords.conf and add your keywords."
        return 1
    fi

    KEYWORDS=()
    local line_num=0
    while IFS= read -r line; do
        line_num=$((line_num + 1))
        # Strip leading/trailing whitespace
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        # Skip comments and blank lines
        [[ -z "$line" || "$line" == \#* ]] && continue
        # Validate keyword length (URLs have ~2000 char limit)
        if [[ ${#line} -gt 200 ]]; then
            log_warn "Keyword too long (${#line} chars, max 200) at $keywords_file:$line_num, skipping: ${line:0:50}..."
            continue
        fi
        KEYWORDS+=("$line")
    done < "$keywords_file"

    if (( ${#KEYWORDS[@]} == 0 )); then
        log_error "No keywords found in $keywords_file"
        return 1
    fi

    log_info "Loaded ${#KEYWORDS[@]} keyword(s)"
}

load_dorks() {
    local dorks_file="${DORKS_FILE:-$CONFIG_DIR/dorks.conf}"

    if [[ ! -f "$dorks_file" ]]; then
        log_error "Dorks file not found: $dorks_file"
        log_error "Run setup.sh or copy dorks.conf.template to dorks.conf."
        return 1
    fi

    _DISCLOSURE_DORK_GROUPS=()
    _BREACH_DORK_GROUPS=()
    _CHAN_DORK_GROUPS=()

    local current_section=""
    while IFS= read -r line; do
        # Strip leading/trailing whitespace
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        # Skip comments and blank lines
        [[ -z "$line" || "$line" == \#* ]] && continue
        # Section headers
        case "$line" in
            \[disclosure\]) current_section="disclosure"; continue ;;
            \[breach\])     current_section="breach"; continue ;;
            \[chan\])        current_section="chan"; continue ;;
            \[*\])          log_warn "Dorks: unknown section '$line', skipping"; current_section=""; continue ;;
        esac
        # Append to the appropriate array
        case "$current_section" in
            disclosure) _DISCLOSURE_DORK_GROUPS+=("$line") ;;
            breach)     _BREACH_DORK_GROUPS+=("$line") ;;
            chan)        _CHAN_DORK_GROUPS+=("$line") ;;
            *)          log_warn "Dorks: line outside a section, skipping: $line" ;;
        esac
    done < "$dorks_file"

    local total=$(( ${#_DISCLOSURE_DORK_GROUPS[@]} + ${#_BREACH_DORK_GROUPS[@]} + ${#_CHAN_DORK_GROUPS[@]} ))
    log_info "Loaded $total dork group(s) (${#_DISCLOSURE_DORK_GROUPS[@]} disclosure, ${#_BREACH_DORK_GROUPS[@]} breach, ${#_CHAN_DORK_GROUPS[@]} chan)"
}

url_encode() {
    local string="$1"
    # Pure bash/jq URL encoding to avoid curl warnings
    printf '%s' "$string" | jq -sRr @uri
}

# Check API key validity and report remaining quotas before scanning
check_api_quotas() {
    local no_ai="${1:-false}"
    local ready=0 total=0

    # Collect per-API status for summary
    declare -A _api_status

    log_info "Checking API status..."

    # --- Brave Search ---
    if [[ -n "${BRAVE_API_KEY:-}" ]]; then
        total=$((total + 1))
        local brave_hdr_file brave_code
        brave_hdr_file=$(_mktemp)
        brave_code=$(curl -s -o /dev/null -D "$brave_hdr_file" -w "%{http_code}" \
            --proto =https \
            --max-time 15 --max-redirs 5 \
            -H "Accept: application/json" \
            -H "Accept-Encoding: gzip" \
            -H "X-Subscription-Token: $BRAVE_API_KEY" \
            "https://api.search.brave.com/res/v1/web/search?q=test&count=1" \
            --compressed 2>/dev/null) || brave_code="000"

        if [[ "$brave_code" == "200" || "$brave_code" == "429" ]]; then
            local remaining limit
            remaining=$(grep -i '^x-ratelimit-remaining:' "$brave_hdr_file" | head -1 | sed 's/.*: *//' | tr -d '\r' | cut -d',' -f2 | tr -d ' ')
            limit=$(grep -i '^x-ratelimit-limit:' "$brave_hdr_file" | head -1 | sed 's/.*: *//' | tr -d '\r' | cut -d',' -f2 | tr -d ' ')
            if [[ -n "$remaining" && -n "$limit" ]]; then
                if [[ "$remaining" == "0" ]]; then
                    _api_status[Brave]="quota exhausted (${remaining}/${limit})"
                    log_warn "Brave Search: monthly quota exhausted"
                else
                    _api_status[Brave]="ready (${remaining}/${limit} remaining)"
                    ready=$((ready + 1))
                fi
            else
                _api_status[Brave]="ready"
                ready=$((ready + 1))
            fi
        elif [[ "$brave_code" == "401" || "$brave_code" == "403" ]]; then
            _api_status[Brave]="invalid key (HTTP $brave_code)"
            log_error "Brave Search: invalid API key (HTTP $brave_code)"
        elif [[ "$brave_code" == "000" ]]; then
            _api_status[Brave]="connection failed"
            log_error "Brave Search: connection failed (network error or TLS failure)"
        else
            _api_status[Brave]="unexpected HTTP $brave_code"
            log_warn "Brave Search: unexpected HTTP $brave_code"
        fi
        rm -f "$brave_hdr_file"
    else
        _api_status[Brave]="no key configured"
    fi

    # --- Tavily Search ---
    if [[ -n "${TAVILY_API_KEY:-}" ]]; then
        total=$((total + 1))
        local tavily_code
        tavily_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --proto =https \
            --max-time 15 --max-redirs 5 \
            -X POST \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TAVILY_API_KEY" \
            -d '{"query":"test","max_results":1}' \
            "https://api.tavily.com/search" \
            2>/dev/null) || tavily_code="000"
        if [[ "$tavily_code" == "200" ]]; then
            _api_status[Tavily]="ready"
            ready=$((ready + 1))
        elif [[ "$tavily_code" == "401" || "$tavily_code" == "403" ]]; then
            _api_status[Tavily]="invalid key (HTTP $tavily_code)"
            log_error "Tavily Search: invalid API key (HTTP $tavily_code)"
        elif [[ "$tavily_code" == "000" ]]; then
            _api_status[Tavily]="connection failed"
            log_error "Tavily Search: connection failed (network error or TLS failure)"
        else
            _api_status[Tavily]="unexpected HTTP $tavily_code"
            log_warn "Tavily Search: unexpected HTTP $tavily_code"
        fi
    else
        _api_status[Tavily]="no key configured"
    fi

    # --- NIST NVD ---
    if [[ -n "${NIST_API_KEY:-}" ]]; then
        total=$((total + 1))
        local nist_code
        nist_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --proto =https \
            --max-time 15 --max-redirs 5 \
            -H "apiKey: $NIST_API_KEY" \
            "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&keywordSearch=test" \
            2>/dev/null) || nist_code="000"
        if [[ "$nist_code" == "200" ]]; then
            _api_status[NIST]="ready (50 req/30s)"
            ready=$((ready + 1))
        elif [[ "$nist_code" == "401" || "$nist_code" == "403" ]]; then
            _api_status[NIST]="invalid key (HTTP $nist_code)"
            log_error "NIST NVD: invalid API key (HTTP $nist_code)"
        elif [[ "$nist_code" == "000" ]]; then
            _api_status[NIST]="connection failed"
            log_error "NIST NVD: connection failed (network error or TLS failure)"
        else
            _api_status[NIST]="unexpected HTTP $nist_code"
            log_warn "NIST NVD: unexpected HTTP $nist_code"
        fi
    else
        _api_status[NIST]="no key configured"
    fi

    # --- AlienVault OTX ---
    if [[ -n "${OTX_API_KEY:-}" ]]; then
        total=$((total + 1))
        local otx_code
        otx_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --proto =https \
            --max-time 15 --max-redirs 5 \
            -H "X-OTX-API-KEY: $OTX_API_KEY" \
            "https://otx.alienvault.com/api/v1/users/me" \
            2>/dev/null) || otx_code="000"
        if [[ "$otx_code" == "200" ]]; then
            _api_status[OTX]="ready"
            ready=$((ready + 1))
        elif [[ "$otx_code" == "401" || "$otx_code" == "403" ]]; then
            _api_status[OTX]="invalid key (HTTP $otx_code)"
            log_error "AlienVault OTX: invalid API key (HTTP $otx_code)"
        elif [[ "$otx_code" == "000" ]]; then
            _api_status[OTX]="connection failed"
            log_error "AlienVault OTX: connection failed (network error or TLS failure)"
        else
            _api_status[OTX]="unexpected HTTP $otx_code"
            log_warn "AlienVault OTX: unexpected HTTP $otx_code"
        fi
    else
        _api_status[OTX]="no key configured"
    fi

    # --- xAI ---
    if [[ "$no_ai" == "true" ]]; then
        _api_status[xAI]="disabled (--no-ai)"
    elif [[ -n "${XAI_API_KEY:-}" ]]; then
        total=$((total + 1))
        local xai_code
        xai_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --proto =https \
            --max-time 15 --max-redirs 5 \
            -H "Authorization: Bearer $XAI_API_KEY" \
            "https://api.x.ai/v1/models" \
            2>/dev/null) || xai_code="000"
        if [[ "$xai_code" == "200" ]]; then
            _api_status[xAI]="ready"
            ready=$((ready + 1))
        elif [[ "$xai_code" == "401" || "$xai_code" == "403" ]]; then
            _api_status[xAI]="invalid key (HTTP $xai_code)"
            log_error "xAI: invalid API key (HTTP $xai_code)"
        elif [[ "$xai_code" == "000" ]]; then
            _api_status[xAI]="connection failed"
            log_error "xAI: connection failed (network error or TLS failure)"
        else
            _api_status[xAI]="unexpected HTTP $xai_code"
            log_warn "xAI: unexpected HTTP $xai_code"
        fi
    else
        _api_status[xAI]="no key configured"
    fi

    # --- 4chan Archives (via web search dorks) ---
    if [[ "$FOURCHAN_ENABLED" == "true" ]]; then
        if [[ -n "${TAVILY_API_KEY:-}" || -n "${BRAVE_API_KEY:-}" ]]; then
            _api_status[4chan]="enabled (via web search)"
        else
            _api_status[4chan]="enabled but no web search API"
            log_warn "4chan archives: enabled but no web search API available"
        fi
    else
        _api_status[4chan]="disabled"
    fi

    # Print per-API status summary
    log_info "API status: ${ready}/${total} APIs ready"
    for api_name in Brave Tavily NIST OTX xAI 4chan; do
        log_debug "  ${api_name}: ${_api_status[$api_name]:-unknown}"
    done

    if [[ "$ready" -eq 0 && "$total" -gt 0 ]]; then
        log_error "No APIs available — aborting scan"
        return 1
    fi
}