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
    if [[ "${XAI_WEB_SEARCH}" == "true" ]]; then
        tools_json=$(echo "$tools_json" | jq -c '. + [{"type":"web_search"}]')
    fi

    local tools_desc
    tools_desc=$(echo "$tools_json" | jq -r '[.[].type] | join("+")' 2>/dev/null)
    log_info "xAI: analyzing keyword '$keyword' (model: $model, tools: ${tools_desc:-none})"

    # Use custom prompts if set (via --prompt-file or prompts.conf), otherwise use defaults
    local system_prompt user_message
    system_prompt="${SYSTEM_PROMPT:-You are an expert cybersecurity analyst specializing in NIST SP 800-53 AU-13 information disclosure monitoring. You assess findings from web searches, vulnerability databases, and threat intelligence sources to determine disclosure risk levels and provide actionable remediation guidance.}"

    if [[ -n "${USER_MESSAGE_TEMPLATE:-}" ]]; then
        # Custom prompt template — substitute placeholders
        user_message="${USER_MESSAGE_TEMPLATE}"
        user_message="${user_message//%keyword%/$keyword}"
        user_message="${user_message//%findings_json%/$findings_json}"
    else
        # Default prompt
        user_message="Perform a comprehensive AU-13 information disclosure risk assessment for the keyword/asset: \"${keyword}\".

Use your web search capability to research, verify, and expand on each finding. Do not merely summarize the data provided — investigate deeply, cross-reference across sources, and provide actionable intelligence with specific remediation guidance.

Findings data for \"${keyword}\":

$findings_json"
    fi

    # Write large content to temp files to avoid "Argument list too long"
    # (jq --arg passes data via argv which has OS limits; --rawfile reads from disk)
    local tmp_system tmp_user tmp_response tmp_body tmp_ai_content tmp_ai_details
    tmp_system=$(_mktemp)
    tmp_user=$(_mktemp)
    tmp_response=$(_mktemp)
    tmp_body=$(_mktemp)
    tmp_ai_content=$(_mktemp)
    tmp_ai_details=$(_mktemp)
    # Single trap cleans up ALL temp files on function return (normal or error)
    # shellcheck disable=SC2064
    trap "rm -f '$tmp_system' '$tmp_user' '$tmp_response' '$tmp_body' '$tmp_ai_content' '$tmp_ai_details'" RETURN

    printf '%s' "$system_prompt" > "$tmp_system"
    printf '%s' "$user_message" > "$tmp_user"

    local request_body
    request_body=$(jq -nc \
        --arg model "$model" \
        --rawfile system "$tmp_system" \
        --rawfile user_msg "$tmp_user" \
        --argjson tools "$tools_json" \
        '{
            model: $model,
            input: [
                {role: "system", content: $system},
                {role: "user", content: $user_msg}
            ],
            tools: $tools
        }')

    echo "$request_body" | curl -s -w "\n%{http_code}" \
        -X POST \
        --proto =https \
        --max-time "${XAI_TIMEOUT:-300}" --max-redirs 5 \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $XAI_API_KEY" \
        -d @- \
        "https://api.x.ai/v1/responses" \
        2>/dev/null > "$tmp_response"

    local http_code
    http_code=$(tail -n1 "$tmp_response")
    sed '$d' "$tmp_response" > "$tmp_body"

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
    ai_content=$(jq -r '
        [.output[] | select(.type == "message") | .content[] | select(.type == "output_text") | .text]
        | first // ""
    ' < "$tmp_body" 2>/dev/null)

    # Fallback: grab first text from any message output regardless of content type
    if [[ -z "$ai_content" ]]; then
        ai_content=$(jq -r '
            [.output[] | select(.type == "message") | .content[]? | .text // empty]
            | first // ""
        ' < "$tmp_body" 2>/dev/null)
    fi

    if [[ -z "$ai_content" ]]; then
        log_warn "xAI: empty response"
        emit_audit_record "AI_ANALYSIS" "xai_grok" "$keyword" "error" "info" \
            "xAI returned empty analysis" "null"
        return 1
    fi

    # Strip Grok proprietary rendering tags (inline citations already captured via annotations)
    # e.g. <grok:render type="render_inline_citation"><argument name="citation_id">60</argument></grok:render>
    ai_content=$(printf '%s' "$ai_content" | sed \
        -e 's/<grok:[^>]*>//g' \
        -e 's/<\/grok:[^>]*>//g' \
        -e 's/<argument [^>]*>[^<]*<\/argument>//g')

    # Extract citations from Grok's web search annotations
    local ai_citations
    ai_citations=$(jq -c '
        [.output[] | select(.type == "message") | .content[]?
         | .annotations[]? | select(.type == "url_citation") | .url]
        // []
    ' < "$tmp_body" 2>/dev/null)

    # Write ai_content to temp file to avoid "Argument list too long" on large responses
    printf '%s' "$ai_content" > "$tmp_ai_content"

    # Try to parse AI response as structured JSON
    # Strategy: try raw first, then strip code fences, then extract { } block
    local ai_details parsed_json=""

    # Attempt 1: parse ai_content directly as JSON
    if jq . < "$tmp_ai_content" &>/dev/null; then
        parsed_json="$ai_content"
    fi

    # Attempt 2: strip markdown code fences (permissive pattern)
    if [[ -z "$parsed_json" ]]; then
        local stripped
        stripped=$(sed -n '/^```[jJ][sS][oO][nN]\?[[:space:]]*$/,/^```[[:space:]]*$/p' < "$tmp_ai_content" | sed '1d;$d')
        if [[ -n "$stripped" ]] && printf '%s' "$stripped" | jq . &>/dev/null; then
            parsed_json="$stripped"
        fi
    fi

    # Attempt 3: try parsing JSON from each { line as a starting position
    # The AI response may have prose -> small JSON fragment -> prose -> real analysis JSON.
    # jq stops at non-JSON text between objects, so we must try multiple start positions.
    if [[ -z "$parsed_json" ]]; then
        while IFS= read -r line_num; do
            [[ -z "$line_num" ]] && continue
            local candidate
            candidate=$(sed -n "${line_num},\$p" < "$tmp_ai_content" | sed '1s/^[^{]*//' | jq -c '.' 2>/dev/null | head -1)
            [[ -z "$candidate" ]] && continue
            local has_keys
            has_keys=$(echo "$candidate" | jq 'has("overall_risk") or has("overall_threat_level") or has("executive_summary") or has("prioritized_findings")' 2>/dev/null)
            if [[ "$has_keys" == "true" ]]; then
                parsed_json="$candidate"
                break
            fi
        done < <(grep -n '{' "$tmp_ai_content" | cut -d: -f1)
    fi

    # Attempt 4: streaming parser for near-valid JSON (LLM occasionally drops a bracket)
    # jq --stream can extract fields that appear BEFORE the first parse error.
    if [[ -z "$parsed_json" ]]; then
        local stream_obj
        stream_obj=$(jq --stream -c \
            'select(length == 2 and (.[0] | length) == 1 and
                    (.[0][0] | IN("overall_risk","overall_threat_level","executive_summary","detailed_assessment")))
             | {(.[0][0]): .[1]}' < "$tmp_ai_content" 2>/dev/null \
            | jq -sc 'add // empty')
        if [[ -n "$stream_obj" ]]; then
            local has_keys
            has_keys=$(echo "$stream_obj" | jq 'has("overall_risk") or has("overall_threat_level") or has("executive_summary")' 2>/dev/null)
            if [[ "$has_keys" == "true" ]]; then
                parsed_json="$stream_obj"
                log_info "xAI: recovered key fields via streaming parser"
            fi
        fi
    fi

    if [[ -n "$parsed_json" ]]; then
        ai_details="$parsed_json"
    else
        ai_details=$(jq -Rsc '{raw_analysis: .}' < "$tmp_ai_content")
    fi

    # Write ai_details to temp file for subsequent jq operations
    printf '%s' "$ai_details" > "$tmp_ai_details"

    # Merge citations into details if available
    if [[ -n "$ai_citations" && "$ai_citations" != "[]" && "$ai_citations" != "null" ]]; then
        ai_details=$(jq --argjson citations "$ai_citations" '. + {grok_citations: $citations}' < "$tmp_ai_details")
        printf '%s' "$ai_details" > "$tmp_ai_details"
    fi

    # Extract risk and summary from the parsed details (not raw content)
    local overall_risk
    overall_risk=$(jq -r '.overall_risk // .overall_threat_level // "low"' < "$tmp_ai_details" 2>/dev/null)
    [[ "$overall_risk" == "null" || -z "$overall_risk" ]] && overall_risk="low"
    # Remap "info" to "low" — AU-13 findings always represent some disclosure risk
    [[ "$overall_risk" == "info" ]] && overall_risk="low"

    local summary
    summary=$(jq -r '.executive_summary // .summary // .raw_analysis // "AI analysis completed"' < "$tmp_ai_details" 2>/dev/null)
    [[ "$summary" == "null" || -z "$summary" ]] && summary="AI analysis completed"
    # Truncate long raw text summaries
    if [[ ${#summary} -gt 500 ]]; then
        summary="${summary:0:497}..."
    fi

    emit_audit_record "AI_ANALYSIS" "xai_grok" "$keyword" "found" "$overall_risk" \
        "AI Risk Assessment: $summary" "$ai_details"

    log_info "xAI analysis complete for '$keyword' — overall risk: $overall_risk"
}
