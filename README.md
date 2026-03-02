# Look4Gold13 — AU-13 Information Disclosure Monitoring Tool

A bash-based NIST SP 800-53 AU-13 monitoring tool that searches web and threat intelligence sources for unauthorized disclosure of organizational information, then generates AU-2/AU-3 compliant audit records with AI-powered risk analysis.

> **CLASSIFICATION NOTICE**
>
> **DO NOT** enter Controlled Unclassified Information (CUI), classified, or otherwise sensitive keywords into this tool. Keywords are sent to **third-party commercial APIs** (Brave Search, Tavily Search, NIST NVD, AlienVault OTX, xAI) over the public internet. Use only **unclassified, publicly releasable** search terms such as organization names, brand names, product names, and domain names.
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
| **Tavily Search** | Web results using the same security dork queries as Brave, providing a second independent search source | [Tavily Search API](https://app.tavily.com/home) |
| **NIST NVD** | CVE vulnerability records matching keywords | [NVD API](https://nvd.nist.gov/developers) |
| **AlienVault OTX** | Threat intelligence pulses and indicators | [OTX API](https://otx.alienvault.com/api) |
| **4chan Archives** | Indexed archive pages from 4plebs, desuarchive, archived.moe — known venues for data leaks, credential dumps, and organizational exposure | Via Brave/Tavily web search dorks (requires Brave or Tavily API key) |
| **xAI (Grok)** | AI-powered deep analysis of all findings with live web research | [xAI API](https://console.x.ai/) |

Brave and Tavily can be used independently or together. When both are enabled, results are **deduplicated by URL** before being sent to AI analysis — the first occurrence is kept (Brave results take priority), so duplicate URLs from Tavily are removed automatically. 4chan archive results use a separate event type (`SEARCH_CHAN`) and are also deduplicated by URL, preventing duplicates if the same archive page appears in both chan dork and web dork results.

## Output

Each scan produces:

- **JSONL** — Machine-readable AU-3 compliant audit records (one JSON object per line)
- **CSV** — Spreadsheet-friendly summary of all findings
- **HTML** — Dark-themed report with per-keyword AI risk assessments, combined web search findings (Brave + Tavily), clickable links, threat indicators, and remediation guidance

## Requirements

- **bash** 4.0+
- **curl**
- **jq**
- At least one API key (Brave, Tavily, NIST NVD, OTX, or xAI); 4chan archive search requires Brave or Tavily

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
| Tavily Search | 1,000 credits/month | https://app.tavily.com/home |
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
  --dorks-file FILE    Dorks file (default: .config/dorks.conf)
  --no-ai              Skip xAI/Grok analysis
  --dry-run            Load config and keywords but don't call APIs
  --verbose            Enable verbose (DEBUG) logging
  --silent, -s         Suppress all output (for cron jobs)
  -h, --help           Show this help message
```

### Detailed Usage Examples

#### Cyber Mode (AU-13 Disclosure Monitoring)
```bash
# Setup
cp .config/dorks-disclosure.template .config/dorks.conf
cp .config/prompts-cyber.template .config/prompts.conf
echo "Dell" > .config/keywords.conf

# Run with AI analysis
bash look4gold.sh --verbose

# Dry-run validation
bash look4gold.sh --dry-run
```

#### Threat Mode (Terrorism Monitoring)
```bash
# Setup
cp .config/dorks-threat.template .config/dorks.conf
cp .config/prompts-threat.template .config/prompts.conf
echo "Colorado Springs" > .config/keywords.conf

# Run without AI (saves credits)
bash look4gold.sh --no-ai --verbose
```

#### Advanced Options
```bash
# Custom output dir
bash look4gold.sh --output-dir /secure/scans

# Force specific dorks/prompts
bash look4gold.sh --dorks-file .config/dorks-threat.template --prompt-file .config/prompts-threat.template

# Cron job (silent, no logs to stdout)
0 6 * * * /path/to/look4gold.sh --silent
```

#### Output Structure
Scans create folders: `output/YYYYMMDDHHMMSS/`
- `scan.jsonl`: Audit records
- `scan.csv`: Spreadsheet summary
- `scan.html`: Web report

**Viewing Results**:
```bash
# Latest scan folder
FOLDER=$(ls -td output/*/ | head -1)
cat "$FOLDER/scan.jsonl" | jq '.event_type, .outcome, .keyword'
open "$FOLDER/scan.html"  # On macOS
```

### Automation & Scheduling

#### Cron Job Example
```bash
# Run daily at 06:00 UTC (silent mode for logs)
0 6 * * * /path/to/Look4Gold13Linux/look4gold.sh --silent
```

#### Output File Structure
Scans create timestamped folders: `output/YYYYMMDDHHMMSS/`
- `scan.jsonl`: AU-3 audit records
- `scan.csv`: Spreadsheet summary
- `scan.html`: Web report with AI analysis

#### Log Analysis
Check logs for issues:
```bash
# Recent scans
ls -la output/ | tail -10

# View latest scan logs
tail -f output/$(ls -td output/*/ | head -1)/scan.jsonl | jq '.event_type, .outcome'
```

## Detailed Configuration

### Template Files
All configuration is managed via template files in `.config/`. Copy the desired template to the config file name for auto-loading.

| Template | Config File | Purpose |
|----------|-------------|---------|
| `dorks-disclosure.template` | `dorks.conf` | AU-13 disclosure dorks |
| `dorks-threat.template` | `dorks.conf` | Terrorism threat dorks |
| `prompts-cyber.template` | `prompts.conf` | Cyber security AI prompts |
| `prompts-threat.template` | `prompts.conf` | Threat intel AI prompts |
| `keywords.conf.template` | `keywords.conf` | Example keywords |
| `apis.conf.template` | `apis.conf` | API key placeholders |

**Copy Example**:
```
cp .config/dorks-disclosure.template .config/dorks.conf
cp .config/prompts-cyber.template .config/prompts.conf
```

### Settings File (.config/settings.conf)

| Setting | Default | Description |
|---------|---------|-------------|
| `OUTPUT_DIR` | `output` | Where scan results are written (relative to script dir) |
| `LOG_LEVEL` | `INFO` | Logging verbosity: DEBUG, INFO, WARN, ERROR |
| `SEARCH_RESULT_COUNT` | `10` | Max results per query (Brave/Tavily) |
| `SEARCH_DAYS_BACK` | `7` | Limit results to last N days |
| `BRAVE_DORK_MODE` | `security` | `security` (dorks) or `raw` (plain keyword) |
| `TAVILY_SEARCH_DEPTH` | `basic` | Search depth: basic/advanced |
| `XAI_MODEL` | `grok-4-1-fast-reasoning` | xAI model for analysis |
| `XAI_TIMEOUT` | `300` | API timeout in seconds |
| `XAI_WEB_SEARCH` | `true` | Enable Grok web search |
| `RETRY_MAX_ATTEMPTS` | `3` | API retry attempts |
| `API_TIMEOUT` | `30` | General API timeout |
| `SCAN_FREQUENCY` | `on_demand` | Audit metadata label |
| `FOURCHAN_ENABLED` | `true` | Enable 4chan archive search |

### Keywords File (.config/keywords.conf)

One keyword per line. Comments (`#`) and blanks ignored. Sanitized for shell safety.

**Cyber Mode Examples**:
```
Acme Corporation
acme-corp.com
AcmeTech Router X500
```

**Threat Mode Examples**:
```
New York City
Washington DC
Colorado Springs
```

### Dorks File (.config/dorks.conf)

Organized by section. Each line is a dork appended to keyword.

**Disclosure Section** (Cyber):
```
site:pastebin.com OR site:github.com
"password" OR "credential"
```

**Threat Section** (Threat):
```
(bomb | attack) site:telegram.org
(plot | threat) site:4chan.org
```

### Prompts File (.config/prompts.conf)

Defines AI prompts. Variables: `SYSTEM_PROMPT`, `USER_MESSAGE_TEMPLATE`.

**Cyber Example** (AU-13 focus):
```
SYSTEM_PROMPT="You are an expert cybersecurity analyst..."
USER_MESSAGE_TEMPLATE='Perform AU-13 assessment for "%keyword%"...'
```

**Threat Example** (Terrorism focus):
```
SYSTEM_PROMPT="You are an expert threat intelligence analyst..."
USER_MESSAGE_TEMPLATE='Assess threats to "%keyword%"...'
```
# WARNING: Use ONLY unclassified, publicly releasable keywords
Acme Corporation
Acme Corp
AcmeTech Router X500
acme-corp.com
```

### .config/dorks.conf

Customizable search dork groups organized by section. Copy from `dorks.conf.template` and edit to fit your threat profile. Each non-comment line within a section becomes a separate API call per keyword.

```
# Sections: [disclosure], [breach], [chan]
[disclosure]
site:pastebin.com OR site:github.com OR site:gist.github.com OR site:reddit.com
site:your-industry-forum.com OR site:your-paste-site.com

[breach]
breach data leak compromised
ransomware attack security incident

[chan]
site:archive.4plebs.org OR site:desuarchive.org
```

## Project Structure

```
Look4Gold13Linux/
├── look4gold.sh                    Main entry point
├── setup.sh                        Interactive setup wizard
├── lib/
│   ├── common.sh                   Config loading, logging, API quota checks
│   ├── audit.sh                    AU-3 compliant audit record formatting
│   ├── brave.sh                    Brave Search with security-focused dork queries
│   ├── tavily.sh                   Tavily Search with shared dork queries + deduplication
│   ├── nist.sh                     NIST NVD CVE search
│   ├── otx.sh                      AlienVault OTX threat intelligence
│   ├── fourchan.sh                 4chan archive search (via Brave/Tavily web search dorks)
│   ├── xai.sh                      xAI Grok AI analysis with web search
│   └── report.sh                   CSV and HTML report generation (combined web search view)
├── .config/
│   ├── settings.conf               General settings
│   ├── apis.conf                   API keys (copy from apis.conf.template)
│   ├── keywords.conf               Search keywords (edit manually)
│   ├── dorks.conf                  Search dork groups (copy from templates)
│   ├── prompts.conf                AI prompts (copy from templates)
│   ├── apis.conf.template          API key template
│   ├── dorks-disclosure.template   AU-13 disclosure dorks
│   ├── dorks-threat.template       Threat intel dorks
│   ├── prompts-cyber.template      AU-13 cyber prompts
│   └── prompts-threat.template     Threat intel prompts
└── output/                         Scan results (gitignored)
```

## NIST SP 800-53 Alignment

This tool supports the following NIST SP 800-53 controls:

- **AU-13 (Monitoring for Information Disclosure)** — Monitors open sources for evidence of unauthorized disclosure of organizational information.
- **AU-2 (Event Logging)** — Identifies events requiring logging (web searches, vulnerability checks, threat intel queries, AI analysis).
- **AU-3 (Content of Audit Records)** — Each JSONL record contains: timestamp, event_type, source, keyword, outcome, severity, description, details, control_ref, scan_id.

### Threat Intelligence Mode Notes
- **Not AU-13 Compliant**: Terrorism searches are for authorized threat intel only.
- **False Positives**: AI helps mitigate, but expect noise.
- **Legal Compliance**: Consult policies; avoid CUI aggregation.

## Modes of Operation

Look4Gold13 supports two primary modes:

### 1. Cyber Security / Information Disclosure Mode (AU-13 Compliant)
**Purpose**: Monitor for unauthorized disclosure of organizational information (NIST SP 800-53 AU-13).

**Setup**:
```
cp .config/dorks-disclosure.template .config/dorks.conf
cp .config/prompts-cyber.template .config/prompts.conf
```

**Use Case**: Scan for leaked credentials, internal docs, CVE exposures for company assets.

### 2. Threat Intelligence Mode (Non-AU-13)
**WARNING**: Not AU-13 compliant. Use for authorized threat intelligence only.

**Purpose**: Monitor terrorism/extremism threats to locations.

**Setup**:
```
cp .config/dorks-threat.template .config/dorks.conf
cp .config/prompts-threat.template .config/prompts.conf
```

**Use Case**: Scan for bomb threats, extremist chatter targeting cities.

### Switching Modes
- Copy the desired `.template` files to `.config/dorks.conf` and `.config/prompts.conf`.
- The script auto-loads these configs on startup.
- Keywords in `.config/keywords.conf` should match the mode (org names for cyber, locations for threat).

**Security Note**: Do not use keywords that aggregate to CUI or sensitive data. Consult your org's policies.

### Custom AI Prompts
- `--prompt-file .config/prompts-cyber.conf`: Default cyber disclosure (AU-13)
- `--prompt-file .config/prompts-terror.conf`: Threat intel mode

Copy templates to .conf files and customize.

## License

See [LICENSE](LICENSE) for details.
