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
        --no-ai)        NO_AI=true; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        --verbose)      VERBOSE=true; shift ;;
        --silent|-s)    SILENT=true; shift ;;
        -h|--help)      usage ;;
        *)              echo "Unknown option: $1" >&2; usage ;;
    esac
done

# --- Source libraries ---
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/audit.sh"
source "$SCRIPT_DIR/lib/brave.sh"
source "$SCRIPT_DIR/lib/nist.sh"
source "$SCRIPT_DIR/lib/otx.sh"
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

# Create output file
AUDIT_OUTPUT_FILE="$OUTPUT_DIR/scan_$(date -u '+%Y%m%d_%H%M%S').jsonl"
export AUDIT_OUTPUT_FILE

log_info "Look4Gold13 — AU-13 Information Disclosure Monitor"
log_info "Output: $AUDIT_OUTPUT_FILE"
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
    nist_search "$keyword" || true
    otx_search "$keyword" || true

    # Per-keyword AI analysis
    if [[ "$NO_AI" == "false" && "$DRY_RUN" == "false" && -f "$AUDIT_OUTPUT_FILE" ]]; then
        keyword_findings=$(jq -sc --arg kw "$keyword" \
            '[.[] | select(.keyword == $kw and .outcome == "found")]' \
            "$AUDIT_OUTPUT_FILE" 2>/dev/null || echo "[]")

        kw_finding_count=$(echo "$keyword_findings" | jq 'length' 2>/dev/null || echo "0")
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
    [[ -n "$CSV_REPORT" ]]  && echo "  CSV:        $CSV_REPORT"
    [[ -n "$HTML_REPORT" ]] && echo "  HTML:       $HTML_REPORT"
    echo "========================================="

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  (Dry run — no API calls were made)"
    fi
fi
