#!/usr/bin/env bash
# lib/xai.sh — xAI (Grok) API module for GenAI analysis
# Uses the /v1/responses endpoint with web_search and x_search tools

xai_analyze() {
    local keyword="$1"
    local findings_json="$2"

    if [[ -z "${XAI_API_KEY:-}" ]]; then
        log_warn "XAI_API_KEY not set, skipping AI analysis"
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would call xAI API for analysis of '$keyword'"
        return 0
    fi

    local model="${XAI_MODEL:-grok-4-1-fast-reasoning}"

    # Build tools array based on settings
    local tools_json="[]"
    if [[ "${XAI_WEB_SEARCH:-true}" == "true" ]]; then
        tools_json=$(echo "$tools_json" | jq -c '. + [{"type":"web_search"}]')
    fi

    local tools_desc
    tools_desc=$(echo "$tools_json" | jq -r '[.[].type] | join("+")' 2>/dev/null)
    log_info "xAI: analyzing keyword '$keyword' (model: $model, tools: ${tools_desc:-none})"

    local system_prompt
    system_prompt='You are an expert cybersecurity analyst and threat intelligence specialist with deep expertise in NIST SP 800-53 AU-13 (Monitoring for Information Disclosure). You have been tasked with performing a thorough, in-depth risk assessment of organizational information disclosure findings.

You will receive aggregated findings from multiple intelligence sources: web search results (Brave Search), vulnerability databases (NIST NVD CVEs), and threat intelligence feeds (AlienVault OTX pulses). These findings represent the STARTING POINT of your analysis — not the final picture.

YOUR MANDATE:
- Think deeply and critically about each finding. Do not provide surface-level summaries.
- USE YOUR WEB SEARCH CAPABILITY to actively research, verify, and EXPAND on the provided findings. Look up CVE details, check for active exploitation, find related advisories, identify threat actor campaigns, and discover context not present in the raw data.
- Cross-reference findings against each other to identify patterns, attack chains, and compounding risks.
- Consider the findings from an attacker'\''s perspective: what could an adversary learn or exploit from this disclosed information?

FOR EACH FINDING OR GROUP OF RELATED FINDINGS, PROVIDE:

1. RISK LEVEL: critical / high / medium / low / info — with explicit justification for the rating
2. CATEGORY: vulnerability_exposure / data_leak / brand_exposure / threat_actor_interest / credential_exposure / configuration_disclosure / supply_chain_risk / reconnaissance_value / other
3. DETAILED DESCRIPTION: A thorough analysis (not a summary) that includes:
   - What specific information is being disclosed
   - The context and significance of this disclosure
   - How this information could be leveraged by threat actors
   - Any related CVEs, advisories, or campaigns you found through your own research
4. AFFECTED SYSTEMS AND SCOPE: Identify specific products, versions, and deployment scenarios at risk
5. THREAT CONTEXT: Known exploitation in the wild, threat actor interest, availability of exploit code, relevant CISA KEV entries
6. DETAILED REMEDIATION STEPS: Specific, actionable steps (not generic advice) including:
   - Immediate actions (within 24-72 hours)
   - Short-term mitigations
   - Long-term strategic recommendations
   - Specific patch versions, configuration changes, or compensating controls where applicable
7. CROSS-REFERENCES: How this finding relates to other findings in the dataset; compound risk scenarios

ADDITIONALLY, PROVIDE:
- An EXECUTIVE SUMMARY (3-5 sentences) that a CISO could read to understand the overall risk posture
- A DETAILED OVERALL ASSESSMENT explaining the aggregate risk landscape, patterns observed, and strategic concerns
- PATTERN ANALYSIS: Identify if multiple findings point to a systemic issue (e.g., multiple vulns in one vendor product line, coordinated threat actor interest)
- A list of SOURCES you consulted during your expanded research

Respond ONLY in JSON format (no markdown fences) with this structure:
{
  "overall_risk": "critical|high|medium|low|info",
  "executive_summary": "3-5 sentence CISO-level summary of overall risk posture",
  "detailed_assessment": "Multi-paragraph detailed analysis of the overall risk landscape, patterns, and strategic concerns",
  "pattern_analysis": [
    {
      "pattern": "Description of identified pattern",
      "findings_involved": ["finding references"],
      "compound_risk": "How these findings together create greater risk than individually"
    }
  ],
  "prioritized_findings": [
    {
      "risk_level": "critical|high|medium|low|info",
      "risk_justification": "Why this risk level was assigned",
      "category": "vulnerability_exposure|data_leak|brand_exposure|threat_actor_interest|credential_exposure|configuration_disclosure|supply_chain_risk|reconnaissance_value",
      "title": "Short finding title",
      "detailed_description": "Thorough multi-sentence analysis of this finding",
      "affected_systems": ["Specific products, versions, platforms at risk"],
      "threat_context": {
        "active_exploitation": true,
        "exploit_available": true,
        "cisa_kev": false,
        "threat_actors": ["Known threat groups if applicable"],
        "notes": "Additional context from your research"
      },
      "remediation": {
        "immediate": ["Actions for next 24-72 hours"],
        "short_term": ["Actions for next 1-2 weeks"],
        "long_term": ["Strategic recommendations"]
      },
      "cross_references": ["Related findings in this dataset"],
      "sources_consulted": ["URLs or references from your expanded research"]
    }
  ],
  "research_sources": ["All URLs and references consulted during analysis"]
}'

    local user_message
    user_message="Perform a comprehensive AU-13 information disclosure risk assessment for the keyword/asset: \"${keyword}\".

Use your web search capability to research, verify, and expand on each finding. Do not merely summarize the data provided — investigate deeply, cross-reference across sources, and provide actionable intelligence with specific remediation guidance.

Findings data for \"${keyword}\":

$findings_json"

    local request_body
    request_body=$(jq -nc \
        --arg model "$model" \
        --arg system "$system_prompt" \
        --arg user_msg "$user_message" \
        --argjson tools "$tools_json" \
        '{
            model: $model,
            input: [
                {role: "system", content: $system},
                {role: "user", content: $user_msg}
            ],
            tools: $tools
        }')

    local response http_code body
    response=$(echo "$request_body" | curl -s -w "\n%{http_code}" \
        -X POST \
        --max-time "${XAI_TIMEOUT:-300}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $XAI_API_KEY" \
        -d @- \
        "https://api.x.ai/v1/responses" \
        2>/dev/null)

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" -ne 200 ]]; then
        log_error "xAI API returned HTTP $http_code"
        emit_audit_record "AI_ANALYSIS" "xai_grok" "$keyword" "error" "info" \
            "xAI API error: HTTP $http_code" \
            "$(jq -nc --arg code "$http_code" '{http_code: $code}')"
        return 1
    fi

    # Extract content from the Responses API format
    # Note: xAI /v1/responses uses content type "output_text" (not "text")
    local ai_content
    ai_content=$(echo "$body" | jq -r '
        [.output[] | select(.type == "message") | .content[] | select(.type == "output_text") | .text]
        | first // ""
    ' 2>/dev/null)

    # Fallback: grab first text from any message output regardless of content type
    if [[ -z "$ai_content" ]]; then
        ai_content=$(echo "$body" | jq -r '
            [.output[] | select(.type == "message") | .content[]? | .text // empty]
            | first // ""
        ' 2>/dev/null)
    fi

    if [[ -z "$ai_content" ]]; then
        log_warn "xAI: empty response"
        emit_audit_record "AI_ANALYSIS" "xai_grok" "$keyword" "error" "info" \
            "xAI returned empty analysis" "null"
        return 1
    fi

    # Extract citations from Grok's web search annotations
    local ai_citations
    ai_citations=$(echo "$body" | jq -c '
        [.output[] | select(.type == "message") | .content[]?
         | .annotations[]? | select(.type == "url_citation") | .url]
        // []
    ' 2>/dev/null)

    # Try to parse AI response as structured JSON
    # Strategy: try raw first, then strip code fences, then extract { } block
    local ai_details parsed_json=""

    # Attempt 1: parse ai_content directly as JSON
    if printf '%s' "$ai_content" | jq . &>/dev/null; then
        parsed_json="$ai_content"
    fi

    # Attempt 2: strip markdown code fences (permissive pattern)
    if [[ -z "$parsed_json" ]]; then
        local stripped
        stripped=$(printf '%s' "$ai_content" | sed -n '/^```[jJ][sS][oO][nN]\?[[:space:]]*$/,/^```[[:space:]]*$/p' | sed '1d;$d')
        if [[ -n "$stripped" ]] && printf '%s' "$stripped" | jq . &>/dev/null; then
            parsed_json="$stripped"
        fi
    fi

    # Attempt 3: extract first JSON object between outermost { }
    if [[ -z "$parsed_json" ]]; then
        local extracted
        extracted=$(printf '%s' "$ai_content" | sed -n '/^[[:space:]]*{/,/^[[:space:]]*}[[:space:]]*$/p')
        if [[ -n "$extracted" ]] && printf '%s' "$extracted" | jq . &>/dev/null; then
            parsed_json="$extracted"
        fi
    fi

    if [[ -n "$parsed_json" ]]; then
        ai_details="$parsed_json"
    else
        ai_details=$(jq -nc --arg raw "$ai_content" '{raw_analysis: $raw}')
    fi

    # Merge citations into details if available
    if [[ -n "$ai_citations" && "$ai_citations" != "[]" && "$ai_citations" != "null" ]]; then
        ai_details=$(printf '%s' "$ai_details" | jq --argjson citations "$ai_citations" '. + {grok_citations: $citations}')
    fi

    # Extract risk and summary from the parsed details (not raw content)
    local overall_risk
    overall_risk=$(printf '%s' "$ai_details" | jq -r '.overall_risk // "info"' 2>/dev/null)
    [[ "$overall_risk" == "null" || -z "$overall_risk" ]] && overall_risk="info"

    local summary
    summary=$(printf '%s' "$ai_details" | jq -r '.executive_summary // .summary // .raw_analysis // "AI analysis completed"' 2>/dev/null)
    [[ "$summary" == "null" || -z "$summary" ]] && summary="AI analysis completed"
    # Truncate long raw text summaries
    if [[ ${#summary} -gt 500 ]]; then
        summary="${summary:0:497}..."
    fi

    emit_audit_record "AI_ANALYSIS" "xai_grok" "$keyword" "found" "$overall_risk" \
        "AI Risk Assessment: $summary" "$ai_details"

    log_info "xAI analysis complete for '$keyword' — overall risk: $overall_risk"
}
