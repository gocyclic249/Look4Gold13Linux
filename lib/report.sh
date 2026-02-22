#!/usr/bin/env bash
# lib/report.sh — CSV and HTML report generation from JSONL audit records

generate_csv() {
    local jsonl_file="$1"
    local csv_file="${jsonl_file%.jsonl}.csv"

    if [[ ! -f "$jsonl_file" ]]; then
        log_warn "CSV report: JSONL file not found: $jsonl_file"
        return 1
    fi

    log_info "Generating CSV report: $csv_file"

    # Header row
    echo 'timestamp,event_type,source,keyword,outcome,severity,description,control_ref,scan_id' > "$csv_file"

    # Data rows — skip SCAN_START/SCAN_END meta records, flatten top-level fields
    jq -r '
        select(.event_type != "SCAN_START" and .event_type != "SCAN_END")
        | [.timestamp, .event_type, .source, .keyword, .outcome, .severity,
           .description, .control_ref, .scan_id]
        | @csv
    ' "$jsonl_file" >> "$csv_file"

    log_info "CSV report written: $csv_file"
    echo "$csv_file"
}

generate_html() {
    local jsonl_file="$1"
    local html_file="${jsonl_file%.jsonl}.html"

    if [[ ! -f "$jsonl_file" ]]; then
        log_warn "HTML report: JSONL file not found: $jsonl_file"
        return 1
    fi

    log_info "Generating HTML report: $html_file"

    # Extract scan metadata
    local scan_id scan_start scan_end keyword_count finding_count record_count
    scan_id=$(jq -r 'select(.event_type=="SCAN_START") | .scan_id' "$jsonl_file" 2>/dev/null | head -1)
    scan_start=$(jq -r 'select(.event_type=="SCAN_START") | .timestamp' "$jsonl_file" 2>/dev/null | head -1)
    scan_end=$(jq -r 'select(.event_type=="SCAN_END") | .timestamp' "$jsonl_file" 2>/dev/null | head -1)
    keyword_count=$(jq -r 'select(.event_type=="SCAN_START") | .details.keyword_count' "$jsonl_file" 2>/dev/null | head -1)
    finding_count=$(jq -r 'select(.event_type=="SCAN_END") | .details.total_findings' "$jsonl_file" 2>/dev/null | head -1)
    record_count=$(jq -r 'select(.event_type=="SCAN_END") | .details.total_records' "$jsonl_file" 2>/dev/null | head -1)

    # Get ordered list of unique keywords (preserving scan order, excluding meta)
    local keywords_json
    keywords_json=$(jq -s '
        [.[] | select(.event_type != "SCAN_START" and .event_type != "SCAN_END" and .keyword != "aggregate")
         | .keyword] | unique
    ' "$jsonl_file" 2>/dev/null)

    # Extract AI analysis (aggregate record from xai_grok)
    local ai_summary ai_risk ai_available="false"
    ai_summary=$(jq -r '
        select(.event_type=="AI_ANALYSIS" and .source=="xai_grok" and .outcome=="found")
        | .details.summary // .details.raw_analysis // .description
    ' "$jsonl_file" 2>/dev/null | head -1)
    ai_risk=$(jq -r '
        select(.event_type=="AI_ANALYSIS" and .source=="xai_grok" and .outcome=="found")
        | .details.overall_risk // "info"
    ' "$jsonl_file" 2>/dev/null | head -1)
    if [[ -n "$ai_summary" && "$ai_summary" != "null" ]]; then
        ai_available="true"
    fi

    # Build the HTML — using a heredoc for the static shell, then jq for dynamic parts
    cat > "$html_file" <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Look4Gold13 — AU-13 Scan Report</title>
<style>
  :root { --bg: #0f1117; --card: #1a1d27; --border: #2a2d3a; --text: #e1e4ed;
          --muted: #8b8fa3; --accent: #6c8aff; --green: #4ade80; --yellow: #facc15;
          --orange: #fb923c; --red: #f87171; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
  .container { max-width: 960px; margin: 0 auto; }
  header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
  header h1 { font-size: 1.5rem; color: var(--accent); margin-bottom: 0.5rem; }
  .meta { display: flex; flex-wrap: wrap; gap: 1.5rem; color: var(--muted); font-size: 0.875rem; }
  .meta span { display: inline-flex; align-items: center; gap: 0.3rem; }
  .meta strong { color: var(--text); }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
           font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .badge-critical { background: var(--red); color: #000; }
  .badge-high { background: var(--orange); color: #000; }
  .badge-medium { background: var(--yellow); color: #000; }
  .badge-low { background: var(--green); color: #000; }
  .badge-info { background: var(--border); color: var(--muted); }
  .ai-box { background: var(--card); border: 1px solid var(--border); border-radius: 8px;
             padding: 1.25rem; margin-bottom: 2rem; }
  .ai-box h3 { font-size: 0.95rem; color: var(--accent); margin-bottom: 0.5rem; }
  .ai-box p { color: var(--muted); font-size: 0.9rem; }
  .keyword-section { margin-bottom: 2.5rem; }
  .keyword-section h2 { font-size: 1.2rem; border-bottom: 1px solid var(--border);
                         padding-bottom: 0.4rem; margin-bottom: 1rem; }
  .source-group { margin-bottom: 1.5rem; }
  .source-group h3 { font-size: 0.95rem; color: var(--muted); margin-bottom: 0.5rem; }
  .finding { background: var(--card); border: 1px solid var(--border); border-radius: 6px;
             padding: 0.75rem 1rem; margin-bottom: 0.5rem; }
  .finding a { color: var(--accent); text-decoration: none; word-break: break-all; }
  .finding a:hover { text-decoration: underline; }
  .finding .desc { color: var(--muted); font-size: 0.85rem; margin-top: 0.25rem; }
  .finding .sev { float: right; margin-left: 0.5rem; }
  .no-results { color: var(--muted); font-style: italic; font-size: 0.9rem; }
  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
           color: var(--muted); font-size: 0.8rem; text-align: center; }
</style>
</head>
<body>
<div class="container">
HTMLHEAD

    # Header section
    cat >> "$html_file" <<HTMLHDR
<header>
  <h1>Look4Gold13 &mdash; AU-13 Scan Report</h1>
  <div class="meta">
    <span>Scan ID: <strong>${scan_id:-N/A}</strong></span>
    <span>Started: <strong>${scan_start:-N/A}</strong></span>
    <span>Ended: <strong>${scan_end:-N/A}</strong></span>
    <span>Keywords: <strong>${keyword_count:-0}</strong></span>
    <span>Findings: <strong>${finding_count:-0}</strong></span>
    <span>Records: <strong>${record_count:-0}</strong></span>
  </div>
</header>
HTMLHDR

    # AI analysis box
    if [[ "$ai_available" == "true" ]]; then
        local risk_class="info"
        case "$ai_risk" in
            critical) risk_class="critical" ;;
            high)     risk_class="high" ;;
            medium)   risk_class="medium" ;;
            low)      risk_class="low" ;;
        esac
        # Escape HTML in ai_summary
        local safe_summary
        safe_summary=$(echo "$ai_summary" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
        cat >> "$html_file" <<HTMLAI
<div class="ai-box">
  <h3>xAI Risk Assessment <span class="badge badge-${risk_class}">${ai_risk}</span></h3>
  <p>${safe_summary}</p>
</div>
HTMLAI
    else
        cat >> "$html_file" <<'HTMLNOAI'
<div class="ai-box">
  <h3>xAI Risk Assessment</h3>
  <p>AI analysis not available</p>
</div>
HTMLNOAI
    fi

    # Per-keyword sections
    local keyword_list
    keyword_list=$(echo "$keywords_json" | jq -r '.[]' 2>/dev/null)

    while IFS= read -r kw; do
        [[ -z "$kw" ]] && continue

        local safe_kw
        safe_kw=$(echo "$kw" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')

        echo "<div class=\"keyword-section\">" >> "$html_file"
        echo "  <h2>${safe_kw}</h2>" >> "$html_file"

        # Source: Brave Search
        _html_source_section "$jsonl_file" "$html_file" "$kw" "brave_search" "Brave Search"

        # Source: NIST NVD
        _html_source_section "$jsonl_file" "$html_file" "$kw" "nist_nvd" "NIST NVD"

        # Source: OTX
        _html_source_section "$jsonl_file" "$html_file" "$kw" "otx" "AlienVault OTX"

        echo "</div>" >> "$html_file"
    done <<< "$keyword_list"

    # Footer
    cat >> "$html_file" <<'HTMLFOOT'
</div>
<footer>
  Generated by Look4Gold13 &mdash; NIST SP 800-53 AU-13 Information Disclosure Monitoring
</footer>
</body>
</html>
HTMLFOOT

    log_info "HTML report written: $html_file"
    echo "$html_file"
}

# Internal helper: write one source subsection into the HTML
_html_source_section() {
    local jsonl_file="$1" html_file="$2" keyword="$3" source_id="$4" source_label="$5"

    # Get findings for this keyword+source with outcome "found"
    local findings
    findings=$(jq -c --arg kw "$keyword" --arg src "$source_id" '
        select(.keyword == $kw and .source == $src and .outcome == "found")
    ' "$jsonl_file" 2>/dev/null)

    echo "  <div class=\"source-group\">" >> "$html_file"
    echo "    <h3>${source_label}</h3>" >> "$html_file"

    if [[ -z "$findings" ]]; then
        echo "    <p class=\"no-results\">No results</p>" >> "$html_file"
        echo "  </div>" >> "$html_file"
        return
    fi

    while IFS= read -r rec; do
        [[ -z "$rec" ]] && continue

        local sev desc link_url link_text extra_desc
        sev=$(echo "$rec" | jq -r '.severity // "info"')
        desc=$(echo "$rec" | jq -r '.description // ""')

        # Build link and description based on source type
        case "$source_id" in
            brave_search)
                link_url=$(echo "$rec" | jq -r '.details.url // ""')
                link_text=$(echo "$rec" | jq -r '.details.title // .description // ""')
                extra_desc=$(echo "$rec" | jq -r '.details.description // ""')
                ;;
            nist_nvd)
                local cve_id
                cve_id=$(echo "$rec" | jq -r '.details.cve_id // ""')
                link_url="https://nvd.nist.gov/vuln/detail/${cve_id}"
                link_text="$cve_id"
                extra_desc=$(echo "$rec" | jq -r '.details.cve_description // ""')
                ;;
            otx)
                link_url=""
                link_text=$(echo "$rec" | jq -r '.details.pulse_name // .description // ""')
                extra_desc=$(echo "$rec" | jq -r '.details.pulse_description // ""')
                ;;
        esac

        # Escape HTML
        link_text=$(echo "$link_text" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
        extra_desc=$(echo "$extra_desc" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
        # Truncate long descriptions
        if [[ ${#extra_desc} -gt 300 ]]; then
            extra_desc="${extra_desc:0:300}..."
        fi

        local sev_class="info"
        case "$sev" in
            critical) sev_class="critical" ;;
            high)     sev_class="high" ;;
            medium)   sev_class="medium" ;;
            low)      sev_class="low" ;;
        esac

        echo "    <div class=\"finding\">" >> "$html_file"
        echo "      <span class=\"sev badge badge-${sev_class}\">${sev}</span>" >> "$html_file"
        if [[ -n "$link_url" ]]; then
            # Escape ampersands in URL for valid HTML
            local safe_url
            safe_url=$(echo "$link_url" | sed 's/&/\&amp;/g')
            echo "      <a href=\"${safe_url}\" target=\"_blank\" rel=\"noopener\">${link_text}</a>" >> "$html_file"
        else
            echo "      <strong>${link_text}</strong>" >> "$html_file"
        fi
        if [[ -n "$extra_desc" ]]; then
            echo "      <div class=\"desc\">${extra_desc}</div>" >> "$html_file"
        fi
        echo "    </div>" >> "$html_file"
    done <<< "$findings"

    echo "  </div>" >> "$html_file"
}
