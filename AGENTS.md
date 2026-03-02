# AGENTS.md for Look4Gold13Linux

## Overview
This repository is a pure Bash implementation of NIST SP 800-53 AU-13 Information Disclosure Monitoring Tool.
- No package managers (npm, pip, cargo).
- Dependencies: bash 4.0+, curl, jq (checked via `check_deps`).
- Main entry: `look4gold.sh`
- Libs: `lib/*.sh` (sourced by main).
- Config: `.config/*.conf` (gitignored secrets: apis.conf, keywords.conf, dorks.conf).
- Output: JSONL (audit), CSV/HTML reports in `output/` (or custom `--output-dir`).

## Build Commands
No build step required.
- Install deps: `sudo apt install bash curl jq`
- Setup: `bash setup.sh` (interactive API keys, deps check, templates).
- Validate config: `bash look4gold.sh --dry-run`
- Run scan: `bash look4gold.sh [--verbose] [--no-ai] [--silent]`

## Lint Commands
No built-in linter.
- Syntax check: `bash -n look4gold.sh lib/*.sh setup.sh`
- Shellcheck: `./test/lint.sh` (install shellcheck first)
- Run after edits: If shellcheck available, run it. Otherwise, `bash -n **/*.sh`

## Test Commands
Bats tests in `test/bats/`.
- Dry-run (functional test): `bash look4gold.sh --dry-run`
- Full scan test: `bash look4gold.sh --verbose` (check JSONL output).
- Single test: `bats test/bats/NAME.bats`
- Add tests? Create `test/` dir, use Bats (github.com/bats-core/bats-core).

## Run Commands for Dev
```
bash setup.sh                    # Setup APIs/config
bash look4gold.sh --dry-run      # Validate
bash look4gold.sh --verbose      # Debug scan
bash look4gold.sh --no-ai        # Skip AI
head -n 20 output/*.jsonl        # View audit records
```

## Directory Structure
```
.
├── look4gold.sh     # Main CLI
├── setup.sh         # Setup wizard
├── lib/             # Sourced modules
│   ├── common.sh    # Config/log/deps/url_encode/check_api_quotas
│   ├── audit.sh     # JSONL AU-3 records (emit_audit_record)
│   ├── brave.sh     # Brave Search w/ dorks
│   ├── tavily.sh    # Tavily Search + dedup
│   ├── nist.sh      # NIST NVD
│   ├── otx.sh       # AlienVault OTX
│   ├── fourchan.sh  # 4chan archives (dorks)
│   └── xai.sh       # xAI Grok analysis
├── .config/         # Config (gitignore secrets)
│   ├── settings.conf
│   ├── apis.conf    # Secrets (chmod 600)
│   ├── keywords.conf
│   └── dorks.conf
└── output/          # Results (gitignore)
```

## Code Style Guidelines

### Shebang & Flags (look4gold.sh:1-5)
```
#!/usr/bin/env bash
set -euo pipefail
```
- Always first lines.
- `SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"` (common.sh:5)

### Sourcing Libs (look4gold.sh:76-84)
```
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/audit.sh"
source "$SCRIPT_DIR/lib/brave.sh"
# ... (order: common first)
```
- Source from main/script dir.
- common.sh first (defines log_* funcs).
- Full list: common, audit, brave, tavily, nist, otx, fourchan, xai, report.

### Functions
- snake_case: `load_config()`, `_log()`, `emit_audit_record()` (private: _prefix).
- 4-space indent.
- Locals: `local var="$1"`
- Arrays: `KEYWORDS=()` (load_keywords:92).
- Return early: `[[ ! -f file ]] && log_error ... && return 1`

### Variables
- Globals/Exports: UPPER_CASE (KEYWORDS[], LOG_LEVEL, BRAVE_API_KEY).
- Locals: snake_case (keyword, event_type).
- Quote all vars: `"$var"`
- Default: `${VAR:-default}`

### Logging (common.sh:14-25)
```
log_info "Message"
log_debug() { _log DEBUG "$@"; }  # etc.
```
- Use log_* over echo (timestamped, leveled).
- Levels: DEBUG(0), INFO(1), WARN(2), ERROR(3).
- CLI override: --verbose (DEBUG), --silent (ERROR).

### Error Handling
- Fatal: `func || exit 1` (load_config:42).
- Non-fatal: `api_call || true`
- Validate: `check_deps || exit 1`
- Paths: `_validate_path() { case "$path" in */../*) exit 1;; esac }` (look4gold.sh:63).
- API errors: emit_audit_record "error" ...
- chmod 600 secrets/output.

### CLI Parsing (look4gold.sh:47-60)
```
while [[ $# -gt 0 ]]; do
  case "$1" in --flag) ... ;; esac
done
```
- Long opts only (--no-ai).
- Validate paths no '..'.

### jq Usage
- Always: `jq -r -c --arg var "$value"`
- JSONL: `echo "$json" >> file`
- Safe: `--slurpfile`, `--rawfile` for large fields (audit.sh:37).

### Config Loading (common.sh:42)
```
source "$CONFIG_DIR/settings.conf"
source "$CONFIG_DIR/apis.conf"  # Secrets!
```
- Strip whitespace/comments: `sed 's/^[[:space:]]*//;s/[[:space:]]*$//'`
- Validate keys present.

### URL Handling
- `url_encode() { jq -sRr @uri; }` (common.sh:148)

### Security
- No secrets in logs/code.
- chmod 600 apis.conf, output files.
- Path traversal check.
- Temp files: `mktemp; trap rm RETURN`
- HTML reports: _html_escape, _sanitize_url (report.sh:6,16).

### Comments
- File header: # purpose (line 1-4).
- Func purpose.
- No inline unless complex.

### Indentation/Formatting
- 4 spaces (no tabs).
- 80-100 char lines.
- Align cases/arrays.
- Heredocs: <<EOF (indented).

## Existing Patterns to Mimic
### Audit Record (audit.sh:37)
```
jq -nc --arg ts ... --rawfile desc ... '{timestamp: $ts, ...}'
```
### Loop Keywords (look4gold.sh:148)
```
for keyword in "${KEYWORDS[@]}"; do
  brave_search "$keyword" || true
  # ...
done
```
### Dedup (look4gold.sh:162)
```
jq -sc 'group_by(.details.url) | [.[] | first]'
```

## Post-Edit Verification
1. `bash -n **/*.sh`
2. `bash setup.sh` (re-run if config changed).
3. `bash look4gold.sh --dry-run --verbose`
4. If shellcheck: `shellcheck **/*.sh`
5. Manual: Check JSONL valid `jq . output/*.jsonl`

## Pro Tips for Agents
- NEVER commit .config/apis.conf (secrets).
- Edit templates: *.template (tracked).
- Add feature? New lib/*.sh, source in main.
- No new deps (stick to bash/curl/jq).
- Mimic README examples in usage().
- AU-3 fields mandatory: timestamp,event_type,source,keyword,outcome,...

Length: ~170 lines. Updated: $(date)