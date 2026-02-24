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

    # Get ordered list of unique keywords (preserving scan order, excluding meta/AI records)
    local keywords_json
    keywords_json=$(jq -s '
        [.[] | select(.event_type != "SCAN_START" and .event_type != "SCAN_END" and .event_type != "AI_ANALYSIS")
         | .keyword] | unique
    ' "$jsonl_file" 2>/dev/null)

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
  .source-group details { margin-top: 0.25rem; }
  .source-group summary { cursor: pointer; font-size: 0.9rem; color: var(--muted); font-weight: 500;
                           padding: 0.3rem 0; list-style: revert; }
  .source-group summary:hover { color: var(--text); }
  .source-group summary .count { font-size: 0.8rem; color: var(--muted); font-weight: 400; }
  .ai-section { margin-top: 1rem; }
  .ai-section h4 { font-size: 0.9rem; color: var(--accent); margin-bottom: 0.5rem;
                    border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }
  .ai-detail { color: var(--muted); font-size: 0.875rem; line-height: 1.7; margin-bottom: 1rem;
               white-space: pre-wrap; }
  .ai-finding-card { background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
                     padding: 1rem; margin-bottom: 0.75rem; }
  .ai-finding-card .title { font-weight: 600; font-size: 0.9rem; margin-bottom: 0.4rem; }
  .ai-finding-card .desc { color: var(--muted); font-size: 0.85rem; margin-bottom: 0.5rem; }
  .ai-finding-card .meta-row { font-size: 0.8rem; color: var(--muted); margin-bottom: 0.3rem; }
  .ai-finding-card .meta-row strong { color: var(--text); }
  .ai-remediation { margin-top: 0.5rem; }
  .ai-remediation summary { cursor: pointer; font-size: 0.85rem; color: var(--accent); font-weight: 500; }
  .ai-remediation ul { margin: 0.3rem 0 0 1.2rem; font-size: 0.8rem; color: var(--muted); }
  .ai-remediation li { margin-bottom: 0.2rem; }
  .ai-pattern { background: var(--bg); border-left: 3px solid var(--yellow); padding: 0.75rem 1rem;
                margin-bottom: 0.5rem; border-radius: 0 4px 4px 0; }
  .ai-pattern .pattern-title { font-weight: 600; font-size: 0.85rem; margin-bottom: 0.3rem; }
  .ai-pattern .pattern-desc { color: var(--muted); font-size: 0.8rem; }
  .ai-sources { list-style: none; padding: 0; }
  .ai-sources li { font-size: 0.8rem; color: var(--muted); padding: 0.15rem 0; }
  .ai-sources a { color: var(--accent); text-decoration: none; word-break: break-all; }
  .ai-sources a:hover { text-decoration: underline; }
  .threat-indicators { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.3rem; }
  .threat-ind { font-size: 0.7rem; padding: 0.1rem 0.4rem; border-radius: 3px;
                background: var(--border); color: var(--muted); }
  .threat-ind.active { background: var(--red); color: #000; font-weight: 600; }
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

    # Per-keyword sections
    local keyword_list
    keyword_list=$(echo "$keywords_json" | jq -r '.[]' 2>/dev/null)

    while IFS= read -r kw; do
        [[ -z "$kw" ]] && continue

        local safe_kw
        safe_kw=$(echo "$kw" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')

        echo "<div class=\"keyword-section\">" >> "$html_file"
        echo "  <h2>${safe_kw}</h2>" >> "$html_file"

        # AI analysis for this keyword (shown first)
        _html_ai_section "$jsonl_file" "$html_file" "$kw"

        # Source: Web Search (Brave + Tavily combined)
        _html_web_search_section "$jsonl_file" "$html_file" "$kw"

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

# Internal helper: write combined Web Search (Brave + Tavily) subsection
_html_web_search_section() {
    local jsonl_file="$1" html_file="$2" keyword="$3"

    # Get findings from both brave_search and tavily_search
    local findings
    findings=$(jq -c --arg kw "$keyword" '
        select(.keyword == $kw and (.source == "brave_search" or .source == "tavily_search") and .outcome == "found")
    ' "$jsonl_file" 2>/dev/null)

    echo "  <div class=\"source-group\">" >> "$html_file"

    if [[ -z "$findings" ]]; then
        echo "    <h3>Web Search</h3>" >> "$html_file"
        echo "    <p class=\"no-results\">No results</p>" >> "$html_file"
        echo "  </div>" >> "$html_file"
        return
    fi

    local result_count
    result_count=$(echo "$findings" | wc -l)
    echo "    <details>" >> "$html_file"
    echo "      <summary>Web Search <span class=\"count\">(${result_count} results)</span></summary>" >> "$html_file"

    while IFS= read -r rec; do
        [[ -z "$rec" ]] && continue

        local sev link_url link_text extra_desc
        sev=$(echo "$rec" | jq -r '.severity // "info"')
        link_url=$(echo "$rec" | jq -r '.details.url // ""')
        link_text=$(echo "$rec" | jq -r '.details.title // .description // ""')
        extra_desc=$(echo "$rec" | jq -r '.details.description // ""')

        # Escape HTML
        link_text=$(echo "$link_text" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
        extra_desc=$(echo "$extra_desc" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
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

    echo "    </details>" >> "$html_file"
    echo "  </div>" >> "$html_file"
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

    if [[ -z "$findings" ]]; then
        echo "    <h3>${source_label}</h3>" >> "$html_file"
        echo "    <p class=\"no-results\">No results</p>" >> "$html_file"
        echo "  </div>" >> "$html_file"
        return
    fi

    local result_count
    result_count=$(echo "$findings" | wc -l)
    echo "    <details>" >> "$html_file"
    echo "      <summary>${source_label} <span class=\"count\">(${result_count} results)</span></summary>" >> "$html_file"

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
                local pulse_id
                pulse_id=$(echo "$rec" | jq -r '.details.pulse_id // ""')
                if [[ -n "$pulse_id" ]]; then
                    link_url="https://otx.alienvault.com/pulse/${pulse_id}"
                else
                    link_url=""
                fi
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

    echo "    </details>" >> "$html_file"
    echo "  </div>" >> "$html_file"
}

# Internal helper: write AI analysis subsection for a keyword
_html_ai_section() {
    local jsonl_file="$1" html_file="$2" keyword="$3"

    # Extract AI analysis record for this keyword
    local ai_record
    ai_record=$(jq -c --arg kw "$keyword" '
        select(.event_type=="AI_ANALYSIS" and .source=="xai_grok" and .keyword==$kw and .outcome=="found")
    ' "$jsonl_file" 2>/dev/null | head -1)

    if [[ -z "$ai_record" ]]; then
        return 0
    fi

    local ai_summary ai_risk ai_detailed ai_findings_json ai_patterns_json ai_sources_json
    ai_summary=$(echo "$ai_record" | jq -r '.details.executive_summary // .details.summary // .details.raw_analysis // .description' 2>/dev/null)
    ai_risk=$(echo "$ai_record" | jq -r '.details.overall_risk // "info"' 2>/dev/null)
    ai_detailed=$(echo "$ai_record" | jq -r '.details.detailed_assessment // ""' 2>/dev/null)
    ai_findings_json=$(echo "$ai_record" | jq -c '.details.prioritized_findings // []' 2>/dev/null)
    ai_patterns_json=$(echo "$ai_record" | jq -c '.details.pattern_analysis // []' 2>/dev/null)
    ai_sources_json=$(echo "$ai_record" | jq -c '.details.research_sources // []' 2>/dev/null)

    # Fall back to grok_citations when research_sources is empty
    local sources_label="Research Sources"
    if [[ -z "$ai_sources_json" || "$ai_sources_json" == "[]" || "$ai_sources_json" == "null" ]]; then
        ai_sources_json=$(echo "$ai_record" | jq -c '.details.grok_citations // []' 2>/dev/null)
        sources_label="Sources"
    fi

    if [[ -z "$ai_summary" || "$ai_summary" == "null" ]]; then
        return 0
    fi

    local risk_class="info"
    case "$ai_risk" in
        critical) risk_class="critical" ;;
        high)     risk_class="high" ;;
        medium)   risk_class="medium" ;;
        low)      risk_class="low" ;;
    esac

    local safe_summary safe_detailed
    safe_summary=$(echo "$ai_summary" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
    safe_detailed=$(echo "$ai_detailed" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')

    cat >> "$html_file" <<HTMLAI
  <div class="ai-box">
    <h3>xAI Risk Assessment <span class="badge badge-${risk_class}">${ai_risk}</span></h3>
    <p>${safe_summary}</p>
HTMLAI

    # Detailed assessment
    if [[ -n "$safe_detailed" && "$safe_detailed" != "null" ]]; then
        cat >> "$html_file" <<HTMLDETAIL
    <div class="ai-section">
      <h4>Detailed Assessment</h4>
      <div class="ai-detail">${safe_detailed}</div>
    </div>
HTMLDETAIL
    fi

    # Pattern analysis
    if [[ -n "$ai_patterns_json" && "$ai_patterns_json" != "[]" && "$ai_patterns_json" != "null" ]]; then
        echo '    <div class="ai-section">' >> "$html_file"
        echo '      <h4>Pattern Analysis</h4>' >> "$html_file"
        local pattern_count pi=0
        pattern_count=$(echo "$ai_patterns_json" | jq 'length' 2>/dev/null || echo "0")
        while [[ $pi -lt $pattern_count ]]; do
            local p_title p_risk
            p_title=$(echo "$ai_patterns_json" | jq -r ".[$pi].pattern // \"\"" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            p_risk=$(echo "$ai_patterns_json" | jq -r ".[$pi].compound_risk // \"\"" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            cat >> "$html_file" <<HTMLPAT
      <div class="ai-pattern">
        <div class="pattern-title">${p_title}</div>
        <div class="pattern-desc">${p_risk}</div>
      </div>
HTMLPAT
            pi=$((pi + 1))
        done
        echo '    </div>' >> "$html_file"
    fi

    # Prioritized findings
    if [[ -n "$ai_findings_json" && "$ai_findings_json" != "[]" && "$ai_findings_json" != "null" ]]; then
        echo '    <div class="ai-section">' >> "$html_file"
        echo '      <h4>Prioritized Findings</h4>' >> "$html_file"
        local fc fi_idx=0
        fc=$(echo "$ai_findings_json" | jq 'length' 2>/dev/null || echo "0")
        while [[ $fi_idx -lt $fc ]]; do
            local f_risk f_title f_desc f_justification f_cat
            f_risk=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].risk_level // \"info\"" 2>/dev/null)
            f_title=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].title // \"Finding\"" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            f_desc=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].detailed_description // .[$fi_idx].description // \"\"" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            f_justification=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].risk_justification // \"\"" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            f_cat=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].category // \"\"" 2>/dev/null | sed 's/_/ /g')

            local f_risk_class="info"
            case "$f_risk" in
                critical) f_risk_class="critical" ;;
                high)     f_risk_class="high" ;;
                medium)   f_risk_class="medium" ;;
                low)      f_risk_class="low" ;;
            esac

            cat >> "$html_file" <<HTMLFINDING
      <div class="ai-finding-card">
        <div class="title"><span class="badge badge-${f_risk_class}">${f_risk}</span> ${f_title}</div>
        <div class="desc">${f_desc}</div>
HTMLFINDING

            if [[ -n "$f_justification" ]]; then
                echo "        <div class=\"meta-row\"><strong>Risk Justification:</strong> ${f_justification}</div>" >> "$html_file"
            fi
            if [[ -n "$f_cat" ]]; then
                echo "        <div class=\"meta-row\"><strong>Category:</strong> ${f_cat}</div>" >> "$html_file"
            fi

            local f_systems
            f_systems=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].affected_systems // [] | join(\", \")" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            if [[ -n "$f_systems" ]]; then
                echo "        <div class=\"meta-row\"><strong>Affected Systems:</strong> ${f_systems}</div>" >> "$html_file"
            fi

            # Threat context indicators
            local t_active t_exploit t_kev t_notes
            t_active=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].threat_context.active_exploitation // false" 2>/dev/null)
            t_exploit=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].threat_context.exploit_available // false" 2>/dev/null)
            t_kev=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].threat_context.cisa_kev // false" 2>/dev/null)
            t_notes=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].threat_context.notes // \"\"" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')

            echo '        <div class="threat-indicators">' >> "$html_file"
            [[ "$t_active" == "true" ]] && echo '          <span class="threat-ind active">ACTIVELY EXPLOITED</span>' >> "$html_file"
            [[ "$t_exploit" == "true" ]] && echo '          <span class="threat-ind active">EXPLOIT AVAILABLE</span>' >> "$html_file"
            [[ "$t_kev" == "true" ]] && echo '          <span class="threat-ind active">CISA KEV</span>' >> "$html_file"
            echo '        </div>' >> "$html_file"
            if [[ -n "$t_notes" ]]; then
                echo "        <div class=\"meta-row\"><strong>Threat Context:</strong> ${t_notes}</div>" >> "$html_file"
            fi

            # Remediation (collapsible)
            local rem_immediate rem_short rem_long
            rem_immediate=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].remediation.immediate // [] | .[]" 2>/dev/null)
            rem_short=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].remediation.short_term // [] | .[]" 2>/dev/null)
            rem_long=$(echo "$ai_findings_json" | jq -r ".[$fi_idx].remediation.long_term // [] | .[]" 2>/dev/null)

            if [[ -n "$rem_immediate" || -n "$rem_short" || -n "$rem_long" ]]; then
                echo '        <details class="ai-remediation">' >> "$html_file"
                echo '          <summary>Remediation Steps</summary>' >> "$html_file"
                if [[ -n "$rem_immediate" ]]; then
                    echo '          <strong style="font-size:0.8rem;color:var(--red)">Immediate (24-72h):</strong><ul>' >> "$html_file"
                    while IFS= read -r item; do
                        local safe_item
                        safe_item=$(echo "$item" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
                        echo "            <li>${safe_item}</li>" >> "$html_file"
                    done <<< "$rem_immediate"
                    echo '          </ul>' >> "$html_file"
                fi
                if [[ -n "$rem_short" ]]; then
                    echo '          <strong style="font-size:0.8rem;color:var(--orange)">Short-term (1-2 weeks):</strong><ul>' >> "$html_file"
                    while IFS= read -r item; do
                        local safe_item
                        safe_item=$(echo "$item" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
                        echo "            <li>${safe_item}</li>" >> "$html_file"
                    done <<< "$rem_short"
                    echo '          </ul>' >> "$html_file"
                fi
                if [[ -n "$rem_long" ]]; then
                    echo '          <strong style="font-size:0.8rem;color:var(--accent)">Long-term:</strong><ul>' >> "$html_file"
                    while IFS= read -r item; do
                        local safe_item
                        safe_item=$(echo "$item" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
                        echo "            <li>${safe_item}</li>" >> "$html_file"
                    done <<< "$rem_long"
                    echo '          </ul>' >> "$html_file"
                fi
                echo '        </details>' >> "$html_file"
            fi

            echo '      </div>' >> "$html_file"
            fi_idx=$((fi_idx + 1))
        done
        echo '    </div>' >> "$html_file"
    fi

    # Research sources (or grok_citations fallback)
    if [[ -n "$ai_sources_json" && "$ai_sources_json" != "[]" && "$ai_sources_json" != "null" ]]; then
        echo '    <div class="ai-section">' >> "$html_file"
        echo "      <h4>${sources_label}</h4>" >> "$html_file"
        echo '      <ul class="ai-sources">' >> "$html_file"
        echo "$ai_sources_json" | jq -r '.[]' 2>/dev/null | while IFS= read -r src; do
            local safe_src
            safe_src=$(echo "$src" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            if echo "$src" | grep -q '^https\?://'; then
                local safe_href
                safe_href=$(echo "$src" | sed 's/&/\&amp;/g')
                echo "        <li><a href=\"${safe_href}\" target=\"_blank\" rel=\"noopener\">${safe_src}</a></li>" >> "$html_file"
            else
                echo "        <li>${safe_src}</li>" >> "$html_file"
            fi
        done
        echo '      </ul>' >> "$html_file"
        echo '    </div>' >> "$html_file"
    fi

    echo '  </div>' >> "$html_file"
}
