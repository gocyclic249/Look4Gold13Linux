#!/usr/bin/env bash
# lib/audit.sh — AU-2/AU-3 compliant audit record formatting

# Global counters for scan session
_SCAN_START=""
_SCAN_ID=""
_FINDING_COUNT=0
_RECORD_COUNT=0

# Output file (set by main script)
AUDIT_OUTPUT_FILE=""

emit_audit_record() {
    # AU-3 fields: what (event_type), when (timestamp), where (source),
    # source (keyword), outcome, identity/subject (control_ref)
    local event_type="$1"
    local source="$2"
    local keyword="$3"
    local outcome="$4"
    local severity="$5"
    local description="$6"
    local details="$7"  # JSON string

    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    # Write large fields to temp files to avoid "Argument list too long"
    local tmp_desc tmp_det
    tmp_desc=$(mktemp)
    tmp_det=$(mktemp)
    trap "rm -f '$tmp_desc' '$tmp_det'" RETURN

    printf '%s' "$description" > "$tmp_desc"
    printf '%s' "${details:-null}" > "$tmp_det"

    local record
    record=$(jq -nc \
        --arg ts "$timestamp" \
        --arg et "$event_type" \
        --arg src "$source" \
        --arg kw "$keyword" \
        --arg oc "$outcome" \
        --arg sev "$severity" \
        --rawfile desc "$tmp_desc" \
        --slurpfile det "$tmp_det" \
        --arg sid "${_SCAN_ID:-unknown}" \
        '{
            timestamp: $ts,
            event_type: $et,
            source: $src,
            keyword: $kw,
            outcome: $oc,
            severity: $sev,
            description: $desc,
            details: $det[0],
            control_ref: "AU-13",
            au2_event_class: "information_disclosure_monitoring",
            scan_id: $sid
        }')

    if [[ -n "$AUDIT_OUTPUT_FILE" ]]; then
        echo "$record" >> "$AUDIT_OUTPUT_FILE"
    fi

    (( _RECORD_COUNT++ ))
    if [[ "$outcome" == "found" ]]; then
        (( _FINDING_COUNT++ ))
    fi

    log_debug "Audit record: $event_type | $source | $keyword | $outcome"
}

start_scan_record() {
    local keyword_count="$1"

    _SCAN_START="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    _SCAN_ID="scan_$(date -u '+%Y%m%d_%H%M%S')_$$"
    _FINDING_COUNT=0
    _RECORD_COUNT=0

    local record
    record=$(jq -nc \
        --arg ts "$_SCAN_START" \
        --arg sid "$_SCAN_ID" \
        --argjson kc "$keyword_count" \
        --arg freq "${SCAN_FREQUENCY:-on_demand}" \
        '{
            timestamp: $ts,
            event_type: "SCAN_START",
            source: "look4gold",
            keyword: "N/A",
            outcome: "started",
            severity: "info",
            description: "AU-13 information disclosure monitoring scan initiated",
            details: {
                scan_id: $sid,
                keyword_count: $kc,
                scan_frequency: $freq
            },
            control_ref: "AU-13",
            au2_event_class: "information_disclosure_monitoring",
            scan_id: $sid
        }')

    if [[ -n "$AUDIT_OUTPUT_FILE" ]]; then
        echo "$record" >> "$AUDIT_OUTPUT_FILE"
    fi

    log_info "Scan started: $_SCAN_ID ($keyword_count keywords)"
}

end_scan_record() {
    local scan_end
    scan_end="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    local record
    record=$(jq -nc \
        --arg ts "$scan_end" \
        --arg sid "$_SCAN_ID" \
        --arg start "$_SCAN_START" \
        --argjson fc "$_FINDING_COUNT" \
        --argjson rc "$_RECORD_COUNT" \
        '{
            timestamp: $ts,
            event_type: "SCAN_END",
            source: "look4gold",
            keyword: "N/A",
            outcome: "completed",
            severity: "info",
            description: "AU-13 information disclosure monitoring scan completed",
            details: {
                scan_id: $sid,
                start_time: $start,
                end_time: $ts,
                total_records: $rc,
                total_findings: $fc
            },
            control_ref: "AU-13",
            au2_event_class: "information_disclosure_monitoring",
            scan_id: $sid
        }')

    if [[ -n "$AUDIT_OUTPUT_FILE" ]]; then
        echo "$record" >> "$AUDIT_OUTPUT_FILE"
    fi

    log_info "Scan completed: $_SCAN_ID — $_FINDING_COUNT findings, $_RECORD_COUNT records"
}
