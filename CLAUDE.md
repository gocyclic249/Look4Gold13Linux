# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Look4Gold13 is a pure Bash NIST SP 800-53 AU-13 information disclosure monitoring tool. It queries multiple web/threat intelligence APIs for each configured keyword, produces AU-2/AU-3 compliant JSONL audit records, and generates CSV/HTML reports with optional AI-powered risk analysis via xAI Grok.

**No build step.** Dependencies: bash 4.0+, curl, jq. No package managers (npm, pip, cargo).

## Commands

```bash
# Setup
bash setup.sh                          # Interactive API key setup + dependency check

# Run
bash look4gold.sh                      # Full scan
bash look4gold.sh --dry-run --verbose  # Validate config without API calls
bash look4gold.sh --no-ai             # Skip xAI analysis (saves credits)
bash look4gold.sh --silent            # Cron mode (stderr suppressed)

# Lint
bash -n look4gold.sh lib/*.sh setup.sh  # Syntax check (always available)
shellcheck look4gold.sh setup.sh lib/*.sh  # Full lint (if shellcheck installed)
./test/lint.sh                         # Lint wrapper (tolerates SC2064/SC2129/SC2016)

# Test
bats test/bats/                        # All Bats tests (if bats installed)
bats test/bats/audit.bats             # Single test file
./test/run_tests.sh                    # Test runner wrapper

# Validate output
jq . output/*/scan.jsonl              # Check JSONL is valid
```

## Architecture

### Execution Flow

`look4gold.sh` is the entry point. It sources all `lib/*.sh` modules (common.sh must be first), then for each keyword in `keywords.conf`:

1. Runs search modules in order: `brave_search` -> `tavily_search` -> `nist_search` -> `otx_search` -> `fourchan_search`
2. Each module calls `emit_audit_record()` to append JSONL records to `$AUDIT_OUTPUT_FILE`
3. Deduplicates web results (SEARCH_WEB + SEARCH_CHAN) by URL using `jq -sc 'group_by(...) | [.[] | first]'`
4. Sends deduplicated findings to `xai_analyze()` for AI risk assessment (unless `--no-ai`)
5. Generates CSV and HTML reports from the JSONL file

### Module Responsibilities

- **common.sh** — Must be sourced first. Provides `log_*()`, `load_config()`, `load_keywords()`, `load_dorks()`, `url_encode()`, `check_api_quotas()`, `_mktemp()`. Sets `SCRIPT_DIR`, `CONFIG_DIR`. Boolean config values are normalized in `load_config()` (accepts `true/True/TRUE/1/yes`). `DORK_MODE` is the primary setting name (legacy `BRAVE_DORK_MODE` is aliased).
- **audit.sh** — `emit_audit_record()` writes AU-3 JSONL records. Uses `jq -nc --rawfile --slurpfile` to handle large payloads without hitting argv limits. Tracks `_SCAN_ID`, `_FINDING_COUNT`, `_RECORD_COUNT`.
- **brave.sh / tavily.sh** — Share the same dork groups (`_DISCLOSURE_DORK_GROUPS[]`, `_BREACH_DORK_GROUPS[]`). Each dork group becomes a separate API call per keyword. Internal `_brave_query()` / `_tavily_query()` accept `event_type` and `source_name` params (used by fourchan.sh).
- **fourchan.sh** — Reuses `_brave_query()` / `_tavily_query()` with `event_type=SEARCH_CHAN` and `source_name=fourchan_dork`, passing `_CHAN_DORK_GROUPS[]`.
- **xai.sh** — Sends findings to xAI `/v1/responses` endpoint. Has a 4-attempt JSON parsing pipeline for AI responses: direct parse -> strip code fences -> scan for `{` lines -> streaming parser fallback.
- **report.sh** — Generates CSV/HTML from JSONL. HTML uses `_html_escape()` (5 entities) and `_sanitize_url()` (blocks javascript:/data: schemes) for XSS prevention.

### Config System

Dorks are organized in sections (`[disclosure]`, `[breach]`, `[chan]`) in `dorks.conf`. Two operational modes are configured by copying template files:
- **Disclosure mode** (AU-13): `dorks-disclosure.template` + `prompts-disclosure.template`
- **Threat mode**: `dorks-threat.template` + `prompts-threat.template`

Custom AI prompts use `SYSTEM_PROMPT` and `USER_MESSAGE_TEMPLATE` variables with `%keyword%` and `%findings_json%` placeholders.

### Output

Scans write to `output/YYYYMMDDHHMMSS/` with `scan.jsonl`, `scan.csv`, `scan.html`. All output files are `chmod 600`. Each JSONL record has mandatory AU-3 fields: `timestamp`, `event_type`, `source`, `keyword`, `outcome`, `severity`, `description`, `details`, `control_ref`, `scan_id`.

## Code Conventions

- `set -euo pipefail` in all entry points
- snake_case functions, UPPER_CASE globals, 4-space indent
- Private functions prefixed with `_` (e.g., `_brave_query`, `_html_escape`)
- Use `log_*()` instead of echo for messages (timestamped, leveled)
- Large jq payloads: use `--rawfile`/`--slurpfile` with temp files + `trap rm RETURN` (not `--arg`, which hits argv limits)
- Use `_mktemp` (not bare `mktemp`) for temp files — writes to a secure `chmod 700` directory, auto-cleaned on exit
- All API modules gracefully skip when their key is unset (`return 0`)
- All curl calls use `--proto =https` to enforce HTTPS-only connections
- Non-fatal API errors: `api_call || true`; fatal config errors: `func || exit 1`
- Path traversal prevention: `_validate_path()` rejects `..` and uses `realpath` when available
- SIGINT/TERM is trapped to write a `SCAN_END` record before exiting

## Security Rules

- **Never commit `.config/apis.conf`** (contains API keys, gitignored)
- `.config/` directory is `chmod 700`, secrets files are `chmod 600`
- Output files created atomically with `install -m 600` (no world-readable window)
- Temp files use `_mktemp` which writes to a secure per-process directory (not `/tmp`)
- HTML reports escape all 5 critical entities and sanitize URLs
- No new runtime dependencies — stick to bash/curl/jq
- Keywords must be unclassified/publicly releasable (sent to third-party APIs)
- API key input in `setup.sh` uses `read -rs` (hidden from terminal)

## Adding a New Search Module

1. Create `lib/newmodule.sh` with a `newmodule_search()` function
2. Source it in `look4gold.sh` (after common.sh)
3. Call `emit_audit_record()` for each finding with appropriate `event_type`
4. Add API key to `apis.conf.template` and `setup.sh`
5. Handle `$DRY_RUN` and missing API key (skip gracefully)
6. Add quota check to `check_api_quotas()` in common.sh
