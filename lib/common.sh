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
    for key_var in BRAVE_API_KEY NIST_API_KEY OTX_API_KEY XAI_API_KEY; do
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
