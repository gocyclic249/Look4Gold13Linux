# Look4Gold13Linux

NIST SP 800-53 AU-13 (Monitoring for Information Disclosure) tool for Linux.

## What It Does

Searches web and threat intelligence sources for evidence of unauthorized disclosure of organizational information (brand names, hardware, company data, etc.) and outputs AU-2/AU-3 compliant audit records in JSONL, CSV, and HTML formats.

## Architecture

- **Bash-based** — all scripts in `lib/` are sourced by `look4gold.sh`
- **API modules**: Brave Search (`lib/brave.sh`), Tavily Search (`lib/tavily.sh`), NIST NVD (`lib/nist.sh`), AlienVault OTX (`lib/otx.sh`), 4chan Archives (`lib/fourchan.sh`), xAI Grok (`lib/xai.sh`)
- **Deduplication**: Web search results from Brave and Tavily are deduplicated by URL before AI analysis
- **Audit records**: `lib/audit.sh` formats all output as AU-3 compliant JSONL
- **Reports**: `lib/report.sh` generates CSV and HTML reports from the JSONL output
- **Config**: `.config/settings.conf` (tracked), `.config/apis.conf` (gitignored, secrets), `.config/keywords.conf` (gitignored, user-specific)

## Key Files

| File | Purpose |
|------|---------|
| `look4gold.sh` | Main entry point — CLI arg parsing, scan orchestration |
| `setup.sh` | Interactive setup for API keys and config |
| `lib/common.sh` | Config loading, logging, url_encode, dep checks |
| `lib/audit.sh` | AU-2/AU-3 record formatting (emit_audit_record, start/end_scan_record) |
| `lib/brave.sh` | Brave Search API integration |
| `lib/tavily.sh` | Tavily Search API integration |
| `lib/nist.sh` | NIST NVD CVE search |
| `lib/otx.sh` | AlienVault OTX threat intel |
| `lib/fourchan.sh` | 4chan archive search (via Brave/Tavily web search dorks) |
| `lib/xai.sh` | xAI Grok AI analysis of findings |
| `lib/report.sh` | CSV and HTML report generation from JSONL |

## Dependencies

- `bash` (4.0+), `curl`, `jq`
- API keys: Brave Search, Tavily Search, NIST NVD, AlienVault OTX, xAI (all optional individually; Brave and Tavily can be used independently or together)
- 4chan archives: via Brave/Tavily web search dorks (requires Brave or Tavily API key)

## Running

```bash
bash setup.sh                        # Configure API keys
bash look4gold.sh --help             # Show options
bash look4gold.sh --dry-run          # Validate config without API calls
bash look4gold.sh --verbose          # Full scan with debug output
bash look4gold.sh --no-ai            # Skip xAI analysis
```

## Conventions

- Primary output is JSONL (one audit record per line); CSV and HTML reports are generated alongside
- Secrets live in `.config/apis.conf` (never committed)
- Templates (`*.template`) are tracked and serve as documentation for config format
- Logging goes to stderr, audit records go to the output file
- CLI flags: `--config-dir`, `--output-dir`, `--keywords-file`, `--no-ai`, `--dry-run`, `--verbose`
