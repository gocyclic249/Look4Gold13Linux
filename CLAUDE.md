# Look4Gold13Linux

NIST SP 800-53 AU-13 (Monitoring for Information Disclosure) tool for Linux.

## What It Does

Searches web and threat intelligence sources for evidence of unauthorized disclosure of organizational information (brand names, hardware, company data, etc.) and outputs AU-2/AU-3 compliant audit records in JSONL format.

## Architecture

- **Bash-based** — all scripts in `lib/` are sourced by `look4gold.sh`
- **API modules**: Brave Search (`lib/brave.sh`), NIST NVD (`lib/nist.sh`), AlienVault OTX (`lib/otx.sh`), xAI Grok (`lib/xai.sh`)
- **Audit records**: `lib/audit.sh` formats all output as AU-3 compliant JSONL
- **Config**: `.config/settings.conf` (tracked), `.config/apis.conf` (gitignored, secrets), `.config/keywords.conf` (gitignored, user-specific)

## Key Files

| File | Purpose |
|------|---------|
| `look4gold.sh` | Main entry point — CLI arg parsing, scan orchestration |
| `setup.sh` | Interactive setup for API keys and config |
| `lib/common.sh` | Config loading, logging, url_encode, dep checks |
| `lib/audit.sh` | AU-2/AU-3 record formatting (emit_audit_record, start/end_scan_record) |
| `lib/brave.sh` | Brave Search API integration |
| `lib/nist.sh` | NIST NVD CVE search |
| `lib/otx.sh` | AlienVault OTX threat intel |
| `lib/xai.sh` | xAI Grok AI analysis of findings |

## Dependencies

- `bash` (4.0+), `curl`, `jq`
- API keys: Brave Search, NIST NVD, AlienVault OTX, xAI (all optional individually)

## Running

```bash
bash setup.sh                        # Configure API keys
bash look4gold.sh --help             # Show options
bash look4gold.sh --dry-run          # Validate config without API calls
bash look4gold.sh --verbose          # Full scan with debug output
bash look4gold.sh --no-ai            # Skip xAI analysis
```

## Conventions

- All output is JSONL, one audit record per line
- Secrets live in `.config/apis.conf` (never committed)
- Templates (`*.template`) are tracked and serve as documentation for config format
- Logging goes to stderr, audit records go to the output file
- CLI flags: `--config-dir`, `--output-dir`, `--keywords-file`, `--no-ai`, `--dry-run`, `--verbose`
