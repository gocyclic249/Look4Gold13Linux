#!/usr/bin/env bash
# lib/common.sh — Config loading, logging, validation utilities

# Resolve project root relative to this file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Default config directory (can be overridden via --config-dir)
CONFIG_DIR="${CONFIG_DIR:-$SCRIPT_DIR/.config}"

# Log levels
declare -A _LOG_LEVELS=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3)
_CURRENT_LOG_LEVEL=1

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

    if [[ ! -f "$settings_file" ]]; then
        log_error "Settings file not found: $settings_file"
        return 1
    fi
    # shellcheck source=/dev/null
    source "$settings_file"

    if [[ ! -f "$apis_file" ]]; then
        log_error "API keys file not found: $apis_file"
        log_error "Run setup.sh first, or copy apis.conf.template to apis.conf and fill in your keys."
        return 1
    fi
    # shellcheck source=/dev/null
    source "$apis_file"

    # Set log level from config
    if [[ -n "${LOG_LEVEL:-}" ]] && [[ -n "${_LOG_LEVELS[$LOG_LEVEL]:-}" ]]; then
        _CURRENT_LOG_LEVEL="${_LOG_LEVELS[$LOG_LEVEL]}"
    fi

    # Validate at least one API key is set
    local has_key=false
    for key_var in BRAVE_API_KEY TAVILY_API_KEY NIST_API_KEY OTX_API_KEY XAI_API_KEY; do
        if [[ -n "${!key_var:-}" ]]; then
            has_key=true
            break
        fi
    done
    if [[ "$has_key" == "false" ]]; then
        log_error "No API keys configured. Run setup.sh or edit $apis_file."
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
    while IFS= read -r line; do
        # Strip leading/trailing whitespace
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        # Skip comments and blank lines
        [[ -z "$line" || "$line" == \#* ]] && continue
        KEYWORDS+=("$line")
    done < "$keywords_file"

    if (( ${#KEYWORDS[@]} == 0 )); then
        log_error "No keywords found in $keywords_file"
        return 1
    fi

    log_info "Loaded ${#KEYWORDS[@]} keyword(s)"
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

    log_info "Checking API status..."

    # --- Brave Search ---
    # Uses a GET request (Brave API does not support HEAD)
    # Dumps headers via -D to read rate limit info
    if [[ -n "${BRAVE_API_KEY:-}" ]]; then
        total=$((total + 1))
        local brave_hdr_file brave_code
        brave_hdr_file=$(mktemp)
        brave_code=$(curl -s -o /dev/null -D "$brave_hdr_file" -w "%{http_code}" \
            -H "Accept: application/json" \
            -H "Accept-Encoding: gzip" \
            -H "X-Subscription-Token: $BRAVE_API_KEY" \
            "https://api.search.brave.com/res/v1/web/search?q=test&count=1" \
            --compressed 2>/dev/null)

        if [[ "$brave_code" == "200" || "$brave_code" == "429" ]]; then
            local remaining limit
            remaining=$(grep -i '^x-ratelimit-remaining:' "$brave_hdr_file" | head -1 | sed 's/.*: *//' | tr -d '\r' | cut -d',' -f2 | tr -d ' ')
            limit=$(grep -i '^x-ratelimit-limit:' "$brave_hdr_file" | head -1 | sed 's/.*: *//' | tr -d '\r' | cut -d',' -f2 | tr -d ' ')
            if [[ -n "$remaining" && -n "$limit" ]]; then
                log_info "Brave Search: ${remaining}/${limit} monthly requests remaining"
                if [[ "$remaining" == "0" ]]; then
                    log_warn "Brave Search: monthly quota exhausted"
                else
                    ready=$((ready + 1))
                fi
            else
                log_info "Brave Search: API key valid"
                ready=$((ready + 1))
            fi
        elif [[ "$brave_code" == "401" || "$brave_code" == "403" ]]; then
            log_error "Brave Search: invalid API key (HTTP $brave_code)"
        else
            log_warn "Brave Search: unexpected HTTP $brave_code"
        fi
        rm -f "$brave_hdr_file"
    fi

    # --- Tavily Search ---
    if [[ -n "${TAVILY_API_KEY:-}" ]]; then
        total=$((total + 1))
        local tavily_code
        tavily_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TAVILY_API_KEY" \
            -d '{"query":"test","max_results":1}' \
            "https://api.tavily.com/search" \
            2>/dev/null)
        if [[ "$tavily_code" == "200" ]]; then
            log_info "Tavily Search: API key valid"
            ready=$((ready + 1))
        elif [[ "$tavily_code" == "401" || "$tavily_code" == "403" ]]; then
            log_error "Tavily Search: invalid API key (HTTP $tavily_code)"
        else
            log_warn "Tavily Search: unexpected HTTP $tavily_code"
        fi
    fi

    # --- NIST NVD ---
    if [[ -n "${NIST_API_KEY:-}" ]]; then
        total=$((total + 1))
        local nist_code
        nist_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "apiKey: $NIST_API_KEY" \
            "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&keywordSearch=test" \
            2>/dev/null)
        if [[ "$nist_code" == "200" ]]; then
            log_info "NIST NVD: API key valid (50 req/30s rate limit)"
            ready=$((ready + 1))
        elif [[ "$nist_code" == "401" || "$nist_code" == "403" ]]; then
            log_error "NIST NVD: invalid API key (HTTP $nist_code)"
        else
            log_warn "NIST NVD: unexpected HTTP $nist_code"
        fi
    fi

    # --- AlienVault OTX ---
    if [[ -n "${OTX_API_KEY:-}" ]]; then
        total=$((total + 1))
        local otx_code
        otx_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "X-OTX-API-KEY: $OTX_API_KEY" \
            "https://otx.alienvault.com/api/v1/users/me" \
            2>/dev/null)
        if [[ "$otx_code" == "200" ]]; then
            log_info "AlienVault OTX: API key valid"
            ready=$((ready + 1))
        elif [[ "$otx_code" == "401" || "$otx_code" == "403" ]]; then
            log_error "AlienVault OTX: invalid API key (HTTP $otx_code)"
        else
            log_warn "AlienVault OTX: unexpected HTTP $otx_code"
        fi
    fi

    # --- xAI ---
    if [[ -n "${XAI_API_KEY:-}" && "$no_ai" != "true" ]]; then
        total=$((total + 1))
        local xai_code
        xai_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer $XAI_API_KEY" \
            "https://api.x.ai/v1/models" \
            2>/dev/null)
        if [[ "$xai_code" == "200" ]]; then
            log_info "xAI: API key valid"
            ready=$((ready + 1))
        elif [[ "$xai_code" == "401" || "$xai_code" == "403" ]]; then
            log_error "xAI: invalid API key (HTTP $xai_code)"
        else
            log_warn "xAI: unexpected HTTP $xai_code"
        fi
    fi

    log_info "API status: ${ready}/${total} APIs ready"

    if [[ "$ready" -eq 0 && "$total" -gt 0 ]]; then
        log_error "No APIs available — aborting scan"
        return 1
    fi
}
