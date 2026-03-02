#!/usr/bin/env bash
# look4gold.sh — NIST SP 800-53 AU-13 Information Disclosure Monitoring Tool
# Searches web and threat intelligence sources for unauthorized disclosure
# of organizational information and outputs AU-2/AU-3 compliant audit records.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Default options ---
CONFIG_DIR="$SCRIPT_DIR/.config"
OUTPUT_DIR=""
KEYWORDS_FILE=""
DORKS_FILE=""
NO_AI=false
DRY_RUN=false
VERBOSE=false
SILENT=false

usage() {
    cat <<EOF
Usage: look4gold.sh [OPTIONS]

NIST SP 800-53 AU-13 Information Disclosure Monitoring Tool

Options:
  --config-dir DIR     Config directory (default: .config/)
  --output-dir DIR     Output directory (default: from settings.conf)
  --keywords-file FILE Keywords file (default: .config/keywords.conf)
  --dorks-file FILE    Dorks file (default: .config/dorks.conf)
  --no-ai              Skip xAI/Grok analysis
  --dry-run            Load config and keywords but don't call APIs
  --verbose            Enable verbose (DEBUG) logging
  --silent, -s         Suppress all output (for cron jobs)
  -h, --help           Show this help message

Examples:
  bash look4gold.sh                        # Standard scan
  bash look4gold.sh --dry-run              # Validate config without API calls
  bash look4gold.sh --no-ai --verbose      # Skip AI, show debug output
  bash look4gold.sh --output-dir /tmp/out  # Custom output location
  bash look4gold.sh --silent               # Cron-friendly, no stdout/stderr
EOF
    exit 0
}

# --- Parse CLI arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config-dir)   CONFIG_DIR="$2"; shift 2 ;;
        --output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
        --keywords-file) KEYWORDS_FILE="$2"; shift 2 ;;
        --dorks-file)   DORKS_FILE="$2"; shift 2 ;;
        --prompt-file)  PROMPT_FILE="$2"; shift 2 ;;
        --no-ai)        NO_AI=true; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        --verbose)      VERBOSE=true; shift ;;
        --silent|-s)    SILENT=true; shift ;;
        -h|--help)      usage ;;
        *)              echo "Unknown option: $1" >&2; usage ;;
    esac
done

# --- Validate paths (prevent directory traversal) ---
_validate_path() {
    local label="$1" path="$2"
    # Reject paths containing ".." components
    case "$path" in
        */../*|*/..|../*|..) echo "ERROR: $label contains '..' (directory traversal not allowed): $path" >&2; exit 1 ;;
    esac
}
[[ -n "$CONFIG_DIR" ]]    && _validate_path "--config-dir" "$CONFIG_DIR"
[[ -n "$OUTPUT_DIR" ]]    && _validate_path "--output-dir" "$OUTPUT_DIR"
[[ -n "$KEYWORDS_FILE" ]] && _validate_path "--keywords-file" "$KEYWORDS_FILE"
[[ -n "$DORKS_FILE" ]]    && _validate_path "--dorks-file" "$DORKS_FILE"

# --- Source libraries ---
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/audit.sh"
source "$SCRIPT_DIR/lib/brave.sh"
source "$SCRIPT_DIR/lib/tavily.sh"
source "$SCRIPT_DIR/lib/nist.sh"
source "$SCRIPT_DIR/lib/otx.sh"
source "$SCRIPT_DIR/lib/fourchan.sh"
source "$SCRIPT_DIR/lib/xai.sh"
source "$SCRIPT_DIR/lib/report.sh"

# --- Initialize ---
check_deps || exit 1

# Override config dir if specified (common.sh uses CONFIG_DIR)
export CONFIG_DIR

load_config || exit 1

# Apply log level overrides AFTER load_config (which sets level from settings.conf)
if [[ "$SILENT" == "true" ]]; then
    _CURRENT_LOG_LEVEL=3  # ERROR only
elif [[ "$VERBOSE" == "true" ]]; then
    LOG_LEVEL="DEBUG"
    _CURRENT_LOG_LEVEL=0
fi

# Set keywords file if specified
if [[ -n "$KEYWORDS_FILE" ]]; then
    export KEYWORDS_FILE
fi
load_keywords || exit 1

# Set dorks file if specified
    if [[ -n "$DORKS_FILE" ]]; then
        export DORKS_FILE
    fi
    load_dorks || exit 1

    # Load prompt file if specified (for custom AI prompts)
    if [[ -n "${PROMPT_FILE:-}" ]]; then
        _validate_path "--prompt-file" "$PROMPT_FILE"
        # shellcheck source=/dev/null
        source "$PROMPT_FILE"
        log_info "Custom prompts loaded from $PROMPT_FILE"
    fi

# Determine output directory
# CLI --output-dir takes priority, then settings.conf OUTPUT_DIR, then default "output"
if [[ -z "$OUTPUT_DIR" ]]; then
    # OUTPUT_DIR may have been set by settings.conf via load_config
    OUTPUT_DIR="${OUTPUT_DIR:-output}"
    # Make relative paths relative to project root
    if [[ "$OUTPUT_DIR" != /* ]]; then
        OUTPUT_DIR="$SCRIPT_DIR/$OUTPUT_DIR"
    fi
fi

mkdir -p "$OUTPUT_DIR"

# Create per-scan folder with ISO date-time
SCAN_FOLDER="$OUTPUT_DIR/$(date -u '+%Y-%m-%dT%H-%M-%S')"
mkdir -p "$SCAN_FOLDER"
chmod 700 "$SCAN_FOLDER" 2>/dev/null || true

# Create AU13 files with restrictive permissions
AUDIT_OUTPUT_FILE="$SCAN_FOLDER/AU13.jsonl"
export AUDIT_OUTPUT_FILE
touch "$AUDIT_OUTPUT_FILE"
chmod 600 "$AUDIT_OUTPUT_FILE"

log_info "Look4Gold13 — AU-13 Information Disclosure Monitor"
log_info "Scan folder: $SCAN_FOLDER"
log_info "AU13 JSONL: $AUDIT_OUTPUT_FILE"
log_info "Keywords: ${#KEYWORDS[@]}"
log_info "Dry run: $DRY_RUN"
[[ "$NO_AI" == "true" ]] && log_info "AI analysis: disabled"

# --- Check API quotas ---
if [[ "$DRY_RUN" == "false" ]]; then
    check_api_quotas "$NO_AI" || exit 1
fi

# --- Run scan ---
start_scan_record "${#KEYWORDS[@]}"

for keyword in "${KEYWORDS[@]}"; do
    log_info "--- Scanning keyword: '$keyword' ---"

    brave_search "$keyword" || true
    tavily_search "$keyword" || true
    nist_search "$keyword" || true
    otx_search "$keyword" || true
    fourchan_search "$keyword" || true

    # Deduplicate web search results (Brave + Tavily) and run AI analysis
    if [[ "$NO_AI" == "false" && "$DRY_RUN" == "false" && -f "$AUDIT_OUTPUT_FILE" ]]; then
        # Deduplicate SEARCH_WEB findings by URL before sending to AI.
        # Keeps the first occurrence (preserves source priority: brave then tavily).
        # Non-web findings (NIST, OTX) pass through unchanged.
        keyword_findings=$(jq -sc --arg kw "$keyword" '
            [.[] | select(.keyword == $kw and .outcome == "found")]
            | group_by(
                if (.event_type == "SEARCH_WEB" or .event_type == "SEARCH_CHAN") then (.details.url // .description)
                else (.event_type + "|" + .source + "|" + .description)
                end
              )
            | [.[] | first]
        ' "$AUDIT_OUTPUT_FILE" 2>/dev/null || echo "[]")

        kw_finding_count=$(echo "$keyword_findings" | jq 'length' 2>/dev/null || echo "0")

        # Log dedup stats for web search results
        total_web=$(jq -sc --arg kw "$keyword" '
            [.[] | select(.keyword == $kw and .outcome == "found" and .event_type == "SEARCH_WEB")] | length
        ' "$AUDIT_OUTPUT_FILE" 2>/dev/null || echo "0")
        deduped_web=$(echo "$keyword_findings" | jq '[.[] | select(.event_type == "SEARCH_WEB")] | length' 2>/dev/null || echo "0")
        if [[ "$total_web" -gt 0 && "$total_web" != "$deduped_web" ]]; then
            log_info "Deduplicated web results for '$keyword': $total_web -> $deduped_web (removed $((total_web - deduped_web)) duplicates)"
        fi

        if [[ "$kw_finding_count" -gt 0 ]]; then
            log_info "Sending $kw_finding_count finding(s) for '$keyword' to xAI for analysis..."
            xai_analyze "$keyword" "$keyword_findings" || true
        else
            log_info "No findings for '$keyword' to analyze with AI"
        fi
    fi
done

# --- Finish ---
end_scan_record

# --- Generate reports ---
CSV_REPORT=""
HTML_REPORT=""
if [[ "$DRY_RUN" == "false" && -f "$AUDIT_OUTPUT_FILE" ]]; then
    CSV_REPORT=$(generate_csv "$AUDIT_OUTPUT_FILE") || true
    HTML_REPORT=$(generate_html "$AUDIT_OUTPUT_FILE") || true
    # Restrict report file permissions (scan results may contain sensitive findings)
    [[ -n "$CSV_REPORT" && -f "$CSV_REPORT" ]]   && chmod 600 "$CSV_REPORT"
    [[ -n "$HTML_REPORT" && -f "$HTML_REPORT" ]] && chmod 600 "$HTML_REPORT"
fi

# --- Print summary (suppressed in silent mode) ---
if [[ "$SILENT" != "true" ]]; then
    echo
    echo "========================================="
    echo "  Look4Gold13 — Scan Complete"
    echo "========================================="
    echo "  Scan ID:    $_SCAN_ID"
    echo "  Keywords:   ${#KEYWORDS[@]}"
    echo "  Records:    $_RECORD_COUNT"
    echo "  Findings:   $_FINDING_COUNT"
    echo "  JSONL:      $AUDIT_OUTPUT_FILE"
    echo "  Scan folder: $SCAN_FOLDER"
    [[ -n "$CSV_REPORT" ]]  && echo "  CSV:        $CSV_REPORT"
    [[ -n "$HTML_REPORT" ]] && echo "  HTML:       $HTML_REPORT"
    echo "========================================="

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  (Dry run — no API calls were made)"
    fi
fi
