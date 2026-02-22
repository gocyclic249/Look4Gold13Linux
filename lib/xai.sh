#!/usr/bin/env bash
# lib/xai.sh — xAI (Grok) API module for GenAI analysis

xai_analyze() {
    local findings_json="$1"

    if [[ -z "${XAI_API_KEY:-}" ]]; then
        log_warn "XAI_API_KEY not set, skipping AI analysis"
        return 0
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would call xAI API for analysis"
        return 0
    fi

    local model="${XAI_MODEL:-grok-4-1-fast-reasoning}"
    log_info "xAI: sending findings for analysis (model: $model)"

    local system_prompt
    system_prompt="You are a security analyst specializing in NIST SP 800-53 AU-13 (Monitoring for Information Disclosure). Analyze the following findings from web searches, CVE databases, and threat intelligence sources. For each finding or group of findings:

1. Assess the disclosure risk level (critical/high/medium/low/info).
2. Identify what type of information may be disclosed (brand exposure, vulnerability exposure, threat actor interest, data leak, etc.).
3. Provide a brief recommended action.
4. Prioritize the most concerning findings first.

Respond in JSON format with this structure:
{
  \"overall_risk\": \"critical|high|medium|low|info\",
  \"summary\": \"Brief overall assessment\",
  \"prioritized_findings\": [
    {
      \"risk_level\": \"high\",
      \"category\": \"vulnerability_exposure\",
      \"description\": \"...\",
      \"recommendation\": \"...\"
    }
  ]
}"

    local request_body
    request_body=$(jq -nc \
        --arg model "$model" \
        --arg system "$system_prompt" \
        --arg findings "$findings_json" \
        '{
            model: $model,
            messages: [
                {role: "system", content: $system},
                {role: "user", content: ("Analyze these AU-13 monitoring findings:\n\n" + $findings)}
            ],
            temperature: 0.3
        }')

    local response http_code body
    response=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $XAI_API_KEY" \
        -d "$request_body" \
        "https://api.x.ai/v1/chat/completions" \
        2>/dev/null)

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" -ne 200 ]]; then
        log_error "xAI API returned HTTP $http_code"
        emit_audit_record "AI_ANALYSIS" "xai_grok" "aggregate" "error" "info" \
            "xAI API error: HTTP $http_code" \
            "$(jq -nc --arg code "$http_code" '{http_code: $code}')"
        return 1
    fi

    local ai_content
    ai_content=$(echo "$body" | jq -r '.choices[0].message.content // ""' 2>/dev/null)

    if [[ -z "$ai_content" ]]; then
        log_warn "xAI: empty response"
        emit_audit_record "AI_ANALYSIS" "xai_grok" "aggregate" "error" "info" \
            "xAI returned empty analysis" "null"
        return 1
    fi

    # Try to parse AI response as JSON for structured details
    local ai_details
    if echo "$ai_content" | jq . &>/dev/null; then
        ai_details="$ai_content"
    else
        ai_details=$(jq -nc --arg raw "$ai_content" '{raw_analysis: $raw}')
    fi

    local overall_risk
    overall_risk=$(echo "$ai_content" | jq -r '.overall_risk // "info"' 2>/dev/null)
    [[ "$overall_risk" == "null" || -z "$overall_risk" ]] && overall_risk="info"

    local summary
    summary=$(echo "$ai_content" | jq -r '.summary // "AI analysis completed"' 2>/dev/null)
    [[ "$summary" == "null" || -z "$summary" ]] && summary="AI analysis completed"

    emit_audit_record "AI_ANALYSIS" "xai_grok" "aggregate" "found" "$overall_risk" \
        "AI Risk Assessment: $summary" "$ai_details"

    log_info "xAI analysis complete — overall risk: $overall_risk"
}
