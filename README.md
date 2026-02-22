# Look4Gold13 — AU-13 Information Disclosure Monitoring Tool

A bash-based NIST SP 800-53 AU-13 monitoring tool that searches web and threat intelligence sources for unauthorized disclosure of organizational information, then generates AU-2/AU-3 compliant audit records with AI-powered risk analysis.

> **CLASSIFICATION NOTICE**
>
> **DO NOT** enter Controlled Unclassified Information (CUI), classified, or otherwise sensitive keywords into this tool. Keywords are sent to **third-party commercial APIs** (Brave Search, NIST NVD, AlienVault OTX, xAI) over the public internet. Use only **unclassified, publicly releasable** search terms such as organization names, brand names, product names, and domain names.
>
> Before running a scan, verify that:
> - All keywords in `keywords.conf` are **unclassified and approved for public disclosure**
> - Search results returned by the tool will not inadvertently surface CUI or classified material that should not be stored on the system running this tool
> - Output files (JSONL, CSV, HTML) are handled according to your organization's data handling policies
>
> **You are responsible** for ensuring compliance with your organization's information security policies, marking requirements, and any applicable regulations (e.g., NIST SP 800-171, CMMC, ITAR, EAR).

## What It Does

For each keyword you configure, Look4Gold13 queries multiple intelligence sources and produces a consolidated report:

| Source | What It Searches | API |
|--------|-----------------|-----|
| **Brave Search** | Web results using security-focused dork queries (paste sites, code repos, breach databases, threat intel news) | [Brave Search API](https://brave.com/search/api/) |
| **NIST NVD** | CVE vulnerability records matching keywords | [NVD API](https://nvd.nist.gov/developers) |
| **AlienVault OTX** | Threat intelligence pulses and indicators | [OTX API](https://otx.alienvault.com/api) |
| **xAI (Grok)** | AI-powered deep analysis of all findings with live web research | [xAI API](https://console.x.ai/) |

## Output

Each scan produces:

- **JSONL** — Machine-readable AU-3 compliant audit records (one JSON object per line)
- **CSV** — Spreadsheet-friendly summary of all findings
- **HTML** — Dark-themed report with per-keyword AI risk assessments, source findings with clickable links, threat indicators, and remediation guidance

## Requirements

- **bash** 4.0+
- **curl**
- **jq**
- At least one API key (Brave, NIST NVD, OTX, or xAI)

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/gocyclic249/Look4Gold13Linux.git
cd Look4Gold13Linux

# 2. Run interactive setup (checks dependencies, prompts for API keys)
bash setup.sh

# 3. Edit keywords — add your organization's search terms
#    WARNING: Use ONLY unclassified, publicly releasable keywords
nano .config/keywords.conf

# 4. Run a scan
bash look4gold.sh
```

## API Keys

All API keys are free tier or have free options:

| API | Free Tier | Sign Up |
|-----|-----------|---------|
| Brave Search | 2,000 queries/month | https://brave.com/search/api/ |
| NIST NVD | 50 requests/30 seconds | https://nvd.nist.gov/developers/request-an-api-key |
| AlienVault OTX | Unlimited (community) | https://otx.alienvault.com/api |
| xAI (Grok) | Usage-based credits | https://console.x.ai/ |

Run `bash setup.sh` to configure keys interactively, or copy `.config/apis.conf.template` to `.config/apis.conf` and fill in manually.

## Usage

```
Usage: look4gold.sh [OPTIONS]

Options:
  --config-dir DIR     Config directory (default: .config/)
  --output-dir DIR     Output directory (default: from settings.conf)
  --keywords-file FILE Keywords file (default: .config/keywords.conf)
  --no-ai              Skip xAI/Grok analysis
  --dry-run            Load config and keywords but don't call APIs
  --verbose            Enable verbose (DEBUG) logging
  --silent, -s         Suppress all output (for cron jobs)
  -h, --help           Show this help message
```

### Examples

```bash
# Standard scan
bash look4gold.sh

# Validate config without making API calls
bash look4gold.sh --dry-run

# Skip AI analysis, show debug output
bash look4gold.sh --no-ai --verbose

# Custom output location
bash look4gold.sh --output-dir /tmp/scan-results

# Cron-friendly (no stdout/stderr, only writes files)
bash look4gold.sh --silent
```

### Cron Job

```bash
# Run daily at 06:00 UTC
0 6 * * * /path/to/Look4Gold13Linux/look4gold.sh --silent
```

## Configuration

### .config/settings.conf

| Setting | Default | Description |
|---------|---------|-------------|
| `OUTPUT_DIR` | `output` | Where scan results are written |
| `LOG_LEVEL` | `INFO` | Logging verbosity: DEBUG, INFO, WARN, ERROR |
| `SEARCH_RESULT_COUNT` | `10` | Brave Search results per query |
| `SEARCH_DAYS_BACK` | `7` | Limit results to the last N days |
| `BRAVE_DORK_MODE` | `security` | `security` uses AU-13 disclosure dorks; `raw` uses plain keyword |
| `XAI_MODEL` | `grok-4-1-fast-reasoning` | xAI model for AI analysis |
| `XAI_TIMEOUT` | `300` | API timeout in seconds |
| `XAI_WEB_SEARCH` | `true` | Let Grok search the web during analysis |
| `SCAN_FREQUENCY` | `on_demand` | Metadata label for audit records |

### .config/keywords.conf

One keyword or phrase per line. Comments (`#`) and blank lines are ignored.

```
# WARNING: Use ONLY unclassified, publicly releasable keywords
Acme Corporation
Acme Corp
AcmeTech Router X500
acme-corp.com
```

## Project Structure

```
Look4Gold13Linux/
  look4gold.sh          Main entry point
  setup.sh              Interactive setup wizard
  lib/
    common.sh           Config loading, logging, API quota checks
    audit.sh            AU-3 compliant audit record formatting
    brave.sh            Brave Search with security-focused dork queries
    nist.sh             NIST NVD CVE search
    otx.sh              AlienVault OTX threat intelligence
    xai.sh              xAI Grok AI analysis with web search
    report.sh           CSV and HTML report generation
  .config/
    settings.conf       General settings
    apis.conf.template  API key template
    keywords.conf.template  Keywords template
  output/               Scan results (gitignored)
```

## NIST SP 800-53 Alignment

This tool supports the following NIST SP 800-53 controls:

- **AU-13 (Monitoring for Information Disclosure)** — Monitors open sources for evidence of unauthorized disclosure of organizational information
- **AU-2 (Event Logging)** — Identifies events requiring logging (web searches, vulnerability checks, threat intel queries, AI analysis)
- **AU-3 (Content of Audit Records)** — Each JSONL record contains: timestamp, event type, source, keyword, outcome, severity, description, details, control reference, and scan ID

## License

See [LICENSE](LICENSE) for details.
