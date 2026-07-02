# Design: New OSINT Sources + HTTP Resilience Pass

**Date:** 2026-07-02
**Status:** Approved (design), pending implementation plan
**Scope:** Add three new OSINT sources (crt.sh, GitHub code search, URLScan.io), introduce a shared HTTP helper with retry/backoff/throttle, and fix the `bc` severity bug in `lib/nist.sh`.

## Background

Look4Gold13 is a pure-Bash NIST SP 800-53 AU-13 information-disclosure monitor. It queries web/threat-intel APIs per keyword, emits AU-3 JSONL audit records, and renders CSV/HTML reports with optional xAI (Grok) analysis. Current sources: Brave, Tavily (+ precision pass), NIST NVD, AlienVault OTX, 4chan archives (via web dorks), optional Google CSE scrape.

This work expands coverage for the disclosure/breach use case and hardens the HTTP layer. It was scoped from a project assessment that identified: (a) high value in adding GitHub code search + certificate-transparency + brand/phishing sources; (b) a dead retry/throttle config (`RETRY_MAX_ATTEMPTS`, `API_TIMEOUT` are defined in `settings.conf` but never read); and (c) a latent `bc` bug in NIST severity mapping. (Intelligence X was considered and dropped from scope: complex two-phase async API and stingy free-tier credits made it the weakest yield-for-effort; it can be revisited later.)

Non-goals for this spec: SearXNG self-hosting (deferred), changes to xAI or dork logic beyond a dedup-key extension, any unrelated refactoring.

## Constraints & Decisions

- **Retry/throttle (COA A):** A single shared `http_request()` helper owns timeout, retry, backoff, and throttle. All curl-based modules (existing Brave/Tavily/NIST/OTX and the three new ones) are retrofitted to call it. Rationale: consistency, DRY, and it satisfies the request to make resilience apply across *all* sources. Accepted cost: careful refactor of four working modules, mitigated by tests.
- **GitHub scope:** Run **both** a broad `keyword` pass and org-scoped `keyword org:<org>` passes. Org names are OPSEC-sensitive (spillage risk), so they live in the gitignored `apis.conf` (`chmod 600`, matched by the `*.conf` gitignore rule), never in a committed template value.
- **Pipeline fit (match source semantics):** crt.sh and GitHub are disclosure-type and feed URL/domain dedup + xAI analysis like web results. URLScan gets its own event type and flows to reports like NIST/OTX. (Note: the existing scan loop already sends *all* `outcome=="found"` records for a keyword to xAI; "match semantics" governs the dedup key and report rendering, not whether AI sees them.)
- **No new hard dependencies:** all three modules use only `curl` + `jq`, already required.
- **Backward compatibility:** `http_request()` preserves the existing `body\n<http_code>` return convention so current response-parsing (`tail -n1` / `sed '$d'`) is unchanged.

## Architecture

### Component 1 — Shared HTTP helper (`lib/common.sh`)

`http_request()` — the single choke point for outbound API calls.

- **Interface:** `http_request <method> <url> <curl_args_array_name> [<<< body]`
  - `method`: `GET` or `POST`.
  - `url`: full URL (caller URL-encodes query params as today).
  - `curl_args_array_name`: name of a bash array holding per-call curl args (auth headers, `Accept`, `--compressed`, etc.), passed by nameref so each module keeps its own header shape.
  - Optional request body on stdin (used by Tavily POSTs).
  - **Output:** response body followed by a final line containing the HTTP status code (unchanged convention). On total failure after retries, emits `000` as the code so callers' existing `!= 200` branches fire.
- **Behavior:**
  - Uses `--proto =https`, `--max-time "${API_TIMEOUT}"`, `--max-redirs 5`.
  - Bounded retry loop with an explicit safety counter (rule #2): retry on `429`, `5xx`, and `000` (timeout/network/TLS). Do **not** retry on `4xx` other than `429`.
  - Exponential backoff: `RETRY_BACKOFF_BASE * 2^(attempt-1)` seconds, capped. On `429`, honor a `Retry-After` header when present (overrides computed backoff).
  - Light throttle: sleep `HTTP_THROTTLE_SECONDS` before returning (applies to every call, success or fail) to smooth burst behavior.
  - Every `curl` invocation's exit status is checked; no blanket error suppression beyond deliberately classified cases.
- **New settings** (`settings.conf` + template), with defaults chosen for paid Brave/Tavily tiers:
  - `HTTP_THROTTLE_SECONDS` (default `0.2`)
  - `RETRY_BACKOFF_BASE` (default `1`)
  - `RETRY_MAX_ATTEMPTS` (already present, default `3`) — now live.
  - `API_TIMEOUT` (already present, default `30`) — now live.
- **Retrofit:** `brave.sh`, `tavily.sh`, `nist.sh`, `otx.sh` replace their inline `curl -s -w "\n%{http_code}"` blocks with `http_request` calls. Header arrays are built locally per module and passed by nameref. Behavior is otherwise identical; only resilience is added.

### Component 2 — `bc` fix (`lib/nist.sh`)

Replace the three `bc -l` CVSS comparisons (`nist.sh:102-108`) with jq numeric tests, e.g. `[[ "$(jq -n --argjson s "$base_score" '$s >= 9.0')" == "true" ]]`. Removes the undeclared `bc` dependency and the current silent failure where a missing `bc` maps every CVE to `low` severity.

### Component 3 — New source modules (`lib/*.sh`)

Each module follows existing conventions: single public `<name>_search()` function, skip-with-`return 0` when its key is unset, honor `DRY_RUN`, call `emit_audit_record` per finding, sourced in `look4gold.sh` after `common.sh`.

**`lib/crtsh.sh` — Certificate Transparency (no key)**
- Request: `GET https://crt.sh/?q=%25<keyword>%25&output=json` (substring match on cert identities).
- Gated by `CRTSH_ENABLED` (default `true`) since there is no key to gate on.
- Parse JSON array; per unique `name_value` (domain) emit `event_type=SEARCH_CERT`, `source=crtsh`, `outcome=found`, `severity=low`. `details`: `{ domain, issuer_name, not_before, not_after, cert_id }`.
- Dedup key: `name_value` (domain). Disclosure-semantics → included in the xAI dedup/feed and the HTML findings section.
- Resilience note: crt.sh intermittently returns `502`/non-JSON under load; `http_request` retries handle this, and a non-array/parse failure emits a single `error` record and returns non-fatal.

**`lib/github.sh` — GitHub code search (`GITHUB_TOKEN`)**
- Request: `GET https://api.github.com/search/code?q=<query>&per_page=<count>` with `Authorization: Bearer $GITHUB_TOKEN` and `Accept: application/vnd.github.text-match+json`.
- Passes: (1) broad `"<keyword>"`; (2) for each org in `GITHUB_ORGS` (space/comma-separated, from `apis.conf`), `"<keyword>" org:<org>`.
- Rate limit is ~10 req/min for code search → retry/backoff (including secondary-rate-limit `403` with `Retry-After`) is essential; `422` (unprocessable query) is treated as "no results", non-fatal.
- Per item emit `event_type=SEARCH_CODE`, `source=github_code`, `severity=low`. `details`: `{ repo, path, html_url, text_matches_snippet }`.
- Dedup key: `html_url`. Disclosure-semantics → xAI dedup/feed + HTML findings section.

**`lib/urlscan.sh` — URLScan.io (`URLSCAN_API_KEY`)**
- Request: `GET https://urlscan.io/api/v1/search/?q=<keyword>` with `API-Key: $URLSCAN_API_KEY`.
- Per result emit `event_type=CHECK_PHISH`, `source=urlscan`, `severity=low` (raise to `medium` when `verdicts.overall.malicious == true`). `details`: `{ page_url, page_domain, scan_time, verdict, result_uuid }`.
- Dedup key: `page_url`. Standalone-semantics (rendered like OTX/NIST in reports).

### Component 4 — Orchestration & config

- **`look4gold.sh`:** source the three new modules after `common.sh`; add `crtsh_search`, `github_search`, `urlscan_search` calls (each `|| true`) into the per-keyword loop after the existing sources. Extend the AI-dedup `jq` (currently keys `SEARCH_WEB`/`SEARCH_CHAN` by `details.url`) to also key `SEARCH_CODE` by `details.html_url` and `SEARCH_CERT` by `details.domain`.
- **`apis.conf.template`:** add `GITHUB_TOKEN`, `GITHUB_ORGS` (with an explicit OPSEC comment: stored locally only, never commit, org identity is sensitive), `URLSCAN_API_KEY`, `CRTSH_ENABLED="true"`.
- **`setup.sh`:** prompt for the two new keys (`GITHUB_TOKEN`, `URLSCAN_API_KEY`) via `read -rs`; prompt for `GITHUB_ORGS` via plain `read` with a "stored locally, never committed" note; write them into `apis.conf`.
- **`common.sh` `check_api_quotas`:** add lightweight health probes for the two keyed sources (GitHub `/rate_limit`, URLScan a minimal search), mirroring the existing per-API status summary. crt.sh needs none.
- **`check_deps`:** unchanged (no new hard deps); confirm `bc` is not referenced anywhere after the fix.

### Component 5 — Reports (`lib/report.sh`)

- **CSV:** no change — the generator dumps all event types except `SCAN_START`/`SCAN_END` generically.
- **HTML:** extend the per-keyword "Source Findings" renderer (around `report.sh:824`, which currently selects only `SEARCH_WEB`/`SEARCH_CHAN`) to also render `SEARCH_CODE`, `SEARCH_CERT`, `CHECK_PHISH`, with source labels/icons and correct URL/domain fields. Continue using `_html_escape()` and `_sanitize_url()` for all new fields.

### Component 6 — Tests (`test/bats/`)

TDD; existing suite must stay green through the refactor.
- `http_request`: retry on 429/5xx/000, no-retry on non-429 4xx, exponential backoff timing, `Retry-After` honoring, throttle applied — via a stubbed `curl` shim.
- NIST severity: `bc`→`jq` mapping produces `critical/high/medium/low` at the right CVSS boundaries, and works with `bc` absent.
- Each new module: response parsing against fixture JSON (found / empty / error), DRY_RUN skip, key-unset skip.

## Data Flow (per keyword, additions in **bold**)

1. brave → tavily → tavily_precision → cse → nist → otx → fourchan → **crtsh → github → urlscan**
2. Each `emit_audit_record` appends AU-3 JSONL to `$AUDIT_OUTPUT_FILE`.
3. Dedup `outcome=="found"` records: web/chan/**code**/**cert** by URL/domain; others by `event_type|source|description`.
4. Deduped set → `xai_analyze` (unless `--no-ai`).
5. CSV + HTML generated; HTML now renders the three new source types.

## Error Handling

- Every new module is non-fatal (`|| true` at the call site); API/parse errors emit an `error` audit record and `return 1`.
- `http_request` classifies retryable vs terminal statuses explicitly; no blanket `2>/dev/null` suppression of unclassified errors (rule #7). Exhausted retries surface as `000`/non-200 to the caller, which logs and emits an `error` record.
- Bounded loops everywhere (the retry loop) carry explicit safety counters (rule #2).

## Rollout / Verification

- `bash -n` + `shellcheck` clean on all changed files.
- `bats test/bats/` green (existing + new).
- `bash look4gold.sh --dry-run --verbose` validates config/keys with the new sources present.
- A live `--no-ai` scan against a benign test keyword confirms each new source emits well-formed JSONL (`jq . output/*/json*.jsonl`).
