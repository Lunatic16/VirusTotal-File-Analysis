# vt_analysis.sh

A feature-rich bash script for scanning files against VirusTotal using the `vt-cli` tool. Submits files for scanning, decodes the Base64 analysis ID, polls for completion, and displays a detailed colour-coded threat report in the terminal — with support for batch scanning, caching, HTML reports, sandbox behaviour, YARA rules, webhook alerts, and more.

---

## Requirements

| Tool | Purpose | Install |
|------|---------|---------|
| [`vt-cli`](https://github.com/VirusTotal/vt-cli) | VirusTotal CLI client | See below |
| `jq` | JSON parsing | `sudo apt install jq` / `brew install jq` |
| `base64` | Decode analysis ID | Pre-installed on Linux/macOS |
| `sha256sum` | File hashing | Pre-installed on Linux (`coreutils`) |
| `curl` | Webhook notifications *(optional)* | `sudo apt install curl` |
| `unzip` | Recursive archive scanning *(optional)* | `sudo apt install unzip` |
| `file` | MIME type detection for archives *(optional)* | Pre-installed on most systems |

### Installing vt-cli

```bash
# macOS
brew install virustotal/virustotal/vt

# Linux
wget https://github.com/VirusTotal/vt-cli/releases/latest/download/Linux64.zip
unzip Linux64.zip && sudo mv vt /usr/local/bin/

# Configure with your API key (free account at virustotal.com)
vt init
```

> A free VirusTotal API key is required. Register at [virustotal.com](https://www.virustotal.com).
> Some features (VT Intelligence, threat severity) require a **premium** API key.

---

## Usage

```bash
chmod +x vt_analysis.sh
./vt_analysis.sh <file|dir|glob|url> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-w, --wait` | Poll every 15s until the scan completes (**recommended**) |
| `-o, --output <file>` | Save the full raw JSON report to a file |
| `-t, --threshold <n>` | Exit with code `2` if malicious detections ≥ `n` (for CI/CD) |
| `--html <file>` | Generate a self-contained HTML report |
| `--behaviour` | Show sandbox behaviour summary (DNS, IPs, files dropped, permissions) |
| `--yara` | Show crowdsourced YARA rule matches |
| `--intel` | Show VT Intelligence enrichment — Sigma rules, IDS hits, threat severity *(premium)* |
| `--all` | Enable `--behaviour`, `--yara`, and `--intel` together |
| `--notify <url>` | POST a Slack-compatible summary to a webhook URL on completion |
| `--recursive` | Unpack `.zip`/`.apk`/`.jar` archives and scan inner files individually |
| `--no-cache` | Skip the local cache and always re-query VirusTotal |
| `--log <file>` | Append scan result to a markdown log file (default: `vt_scan_log.md`) |
| `--no-log` | Disable markdown logging entirely |
| `--url <url>` | Explicitly scan a URL (useful in scripts/pipelines) |
| `-h, --help` | Show usage information |

---

## Examples

```bash
# Scan a file
./vt_analysis.sh suspicious.apk --wait

# Scan a URL (auto-detected from https:// prefix)
./vt_analysis.sh https://suspicious-site.com --wait

# Scan a URL explicitly
./vt_analysis.sh --url https://malware.example.com --wait --html url_report.html

# Full analysis with all enrichment and an HTML report
./vt_analysis.sh malware.apk --wait --all --html report.html

# Batch scan all APKs in current directory
./vt_analysis.sh *.apk --wait

# Scan entire directory recursively (unpack archives too)
./vt_analysis.sh /downloads/ --wait --recursive

# CI/CD pipeline: fail the build if any detections found
./vt_analysis.sh build-artifact.bin --wait --threshold 1 || exit 1

# Save JSON + send Slack alert when done
./vt_analysis.sh payload.bin --wait --output report.json --notify https://hooks.slack.com/services/XXX/YYY/ZZZ

# Re-scan ignoring cached results
./vt_analysis.sh file.apk --wait --no-cache
```

---

## Features

### URL Scanning
Pass any `http://` or `https://` URL as a positional argument and the script automatically routes it through URL scanning instead of file scanning. You can also use the explicit `--url` flag.

```bash
./vt_analysis.sh https://suspicious-site.com --wait
./vt_analysis.sh --url https://phishing.example.com --wait --html report.html
```

URL scans use `vt scan url <url>` to submit, then poll `vt analysis <id>` the same way file scans do. Results include:
- Full colour-coded engine results table (70+ URL scanners and reputation services)
- Detection stats (malicious / suspicious / harmless / undetected)
- **URL Details** section — final URL after redirects, HTTP status code, page title, and redirect chain
- URL categories (with `--intel`, premium API)
- Caching with a 1-hour TTL (shorter than files since URLs change faster)
- Markdown log entries tagged with a 🌐 URL icon
- HTML report and webhook notification support, same as files

URLs and files can be mixed freely in a single command for batch scanning:
```bash
./vt_analysis.sh suspicious.apk https://malware-site.com another.exe --wait
```

### Hash Lookup Before Upload
Before submitting a file, the script checks whether its SHA-256 is already known to VirusTotal using `vt file <hash>`. If a previous analysis exists, the upload is skipped entirely and existing results are fetched directly — saving API quota and time. For large files like APKs, this is a significant speed improvement on repeat scans.

### Local Result Cache
Completed scan results are cached in `~/.vt_cache.json`, keyed by SHA-256. On subsequent runs, if a completed result is less than 24 hours old, it is used immediately without any API call. Use `--no-cache` to bypass this and force a fresh lookup.

### Colour-Coded Engine Results Table
All engine results are displayed in a formatted table with colour-coding by category:
- **Red** — malicious
- **Yellow** — suspicious
- **Green** — harmless
- **Dim/grey** — undetected or unsupported

### Behaviour / Sandbox Report (`--behaviour`)
Fetches dynamic analysis data from VirusTotal's sandbox via `vt file <hash> --include behaviour_summary`. Displays:
- DNS lookups made
- IP traffic (destination IPs and ports)
- HTTP conversations
- Files written or dropped
- Android permissions requested

Particularly useful for APK analysis.

### YARA Rule Matches (`--yara`)
Fetches crowdsourced YARA rules that matched the file via `--include crowdsourced_yara_results`. Each match includes the rule name, author, and source — often revealing a threat family name even when AV engines disagree.

### VT Intelligence Enrichment (`--intel`)
For premium API users, fetches additional threat intelligence including:
- Threat severity level
- Sigma rule matches (with severity ratings)
- Crowdsourced IDS/IPS rule hits

### Batch / Multi-File Mode
Pass multiple files, a glob, or a directory path and the script will scan each file sequentially, then print a consolidated summary table at the end with colour-coded verdicts for each file.

### Threshold Alerting for CI/CD (`--threshold`)
The `-t`/`--threshold <n>` flag causes the script to exit with code `2` if the number of malicious detections is ≥ `n`. This makes it easy to integrate into CI/CD pipelines or pre-commit hooks to block builds or deployments when flagged files are detected.

### HTML Report (`--html`)
Generates a polished, self-contained HTML report with:
- File metadata and SHA-256
- Colour-coded verdict banner
- Detection stats summary cards
- Full engine results table styled by category
- Direct link to the VirusTotal GUI

No external dependencies — the HTML file is fully portable.

### Slack / Webhook Notifications (`--notify`)
On scan completion, posts a Slack-compatible JSON payload to the provided webhook URL including file name, verdict, detection ratio, SHA-256, and a link to the full VT report. Works with any service that accepts Slack-format webhooks (Slack, Discord, Teams with a relay, etc.).

### Recursive Archive Scanning (`--recursive`)
If the target file is a `.zip`, `.apk`, or `.jar`, the script unpacks it into a temporary directory and scans each inner file individually. Results are shown per inner file, and the temp directory is cleaned up automatically. APKs contain embedded DEX files and native libraries that sometimes have different detection rates than the outer package.

---

## How the Core Flow Works

**Step 1 — Hash lookup**
Computes the SHA-256 of the file and checks `~/.vt_cache.json` for a recent completed result. If found, skips to display. Otherwise, queries `vt file <hash>` to check if VT already has results, skipping the upload if so.

**Step 2 — Submit (if needed)**
Runs `vt scan file <file>` and extracts the Base64 analysis ID from the last token of the output line. The ID is decoded to display the MD5 hash and submission timestamp.

**Step 3 — Poll and fetch**
With `--wait`, polls `vt analysis <id>` every 15 seconds until `status` is `completed`. Without `--wait`, fetches once and warns if still queued. Results are cached on completion.

**Step 4 — Display and enrich**
Prints the engine results table, stats summary, and verdict. Optionally fetches behaviour, YARA, and intelligence data. Generates HTML and/or fires webhook if requested.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success — all files scanned, threshold not exceeded |
| `1` | Error — missing dependency, file not found, API failure |
| `2` | Threshold exceeded — malicious detections ≥ `--threshold` value |

---

## Cache File

The cache is stored at `~/.vt_cache.json` as a JSON object keyed by SHA-256 hash. Each entry is the raw analysis result plus a `cached_at` Unix timestamp. Entries older than 24 hours or with non-`completed` status are ignored and re-queried.

To clear the cache entirely:
```bash
rm ~/.vt_cache.json
```

---


### Markdown Scan Log (`--log`)
After every completed scan, an entry is automatically appended to `vt_scan_log.md` (or a custom path via `--log <file>`). The log is a standard markdown table, so it renders cleanly on GitHub, GitLab, Obsidian, or any markdown viewer.

The header row is written automatically the first time the file is created. Each subsequent scan appends a new row — so the log builds up over time as a full scan history.

**Example log output:**

| Scanned At | File | Verdict | Detections | SHA-256 | Report |
|------------|------|---------|------------|---------|--------|
| 2026-02-21 18:06:26 EST | `Netfly2.5.3.apk` | 🔴 MALICIOUS | 5 / 72 | `ec78885a...` | [View](https://www.virustotal.com/gui/file/ec78885a...) |
| 2026-02-21 18:30:11 EST | `setup.exe` | 🟢 CLEAN | 0 / 71 | `a1b2c3d4...` | [View](https://www.virustotal.com/gui/file/a1b2c3d4...) |

To disable logging for a specific run: `./vt_analysis.sh file.apk --no-log`
To use a custom log path: `./vt_analysis.sh file.apk --log ~/reports/vt_history.md`

## Notes

- **Large files** (50MB+) take longer to process — always use `--wait`.
- **Free API accounts** are rate-limited to 4 requests/minute and 500/day. The hash-lookup-first and caching features help stay within these limits.
- **`--behaviour`, `--yara`, `--intel`** each make an additional API call per file.
- **`--intel`** features (Sigma rules, threat severity) require a VT Intelligence / premium API subscription.
- Webhook payloads use Slack's attachment format and are compatible with most modern webhook receivers.

---

## License

MIT — free to use and modify.
