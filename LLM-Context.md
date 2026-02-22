# LLM-Context.md — vt_analysis.sh

This file provides context for AI-assisted development of `vt_analysis.sh`. It describes the project's purpose, architecture, conventions, known behaviours, and guidelines for making changes safely.

---

## Project Overview

`vt_analysis.sh` is a bash script that wraps the [`vt-cli`](https://github.com/VirusTotal/vt-cli) tool to provide rich VirusTotal analysis of files and URLs directly from the terminal. It handles submission, polling, result parsing, reporting, caching, logging, and notifications in a single self-contained script.

**Files in this project:**

| File | Purpose |
|------|---------|
| `vt_analysis.sh` | Main script — all logic lives here |
| `README.md` | User-facing documentation |
| `CLAUDE.md or GEMINI.md` | This file — AI development context |
| `vt_scan_log.md` | Auto-generated markdown scan log (created at runtime) |
| `~/.vt_cache.json` | Auto-generated local result cache (created at runtime) |

---

## Architecture

The script is structured as a set of functions called from a linear main block at the bottom.

### Core flow

```
main
 ├── scan_single_url()     — for each URL target
 └── scan_single_file()    — for each file target
      ├── cache_get()
      ├── vt file <hash>    — hash lookup (skip upload if known)
      ├── vt scan file/url  — submit if new
      ├── vt analysis <id>  — poll for results
      ├── cache_set()
      ├── print_engine_table()
      ├── parse_stats()
      ├── print_stats_summary()
      ├── determine_verdict()
      ├── print_behaviour()   — if --behaviour
      ├── print_yara()        — if --yara
      ├── print_intel()       — if --intel
      ├── generate_html()     — if --html
      ├── send_notification() — if --notify
      └── write_log()         — always (unless --no-log)
```

### Key design decisions

**No `set -e`.** Many `vt-cli` commands return non-zero exit codes for normal conditions (e.g. a file not found on VT). Using `set -e` causes silent exits. Instead, every command that can legitimately fail uses `|| true` or `2>/dev/null || true`. The ERR trap catches genuinely unexpected failures and reports the line number.

**`set -uo pipefail` is used.** `-u` catches undefined variable references. `-o pipefail` ensures pipeline failures propagate. These are safe to keep.

**Boolean flags are stored as strings `"true"`/`"false"`.** Due to the no-`set -e` constraint, using bare variable expansion as commands (e.g. `if $WAIT_FOR_RESULT`) is unreliable. All boolean checks use `[[ "$FLAG" == "true" ]]`.

**JSON from `vt-cli --format json` is always a flat array `[{...}]`.** The API wrapper does NOT return `{"data": {"attributes": {...}}}`. Fields like `status`, `stats`, and `results` are directly on `.[0]`. Every `jq` filter must start with `.[0].field`, not `.data.attributes.field`.

**Cache keys:** Files use SHA-256 hash. URLs use base64url encoding of the raw URL string (`base64 | tr '+/' '-_' | tr -d '='`). Cache TTL is 24 hours for files, 1 hour for URLs.

**Shared display helpers** (`print_engine_table`, `parse_stats`, `print_stats_summary`, `determine_verdict`, `print_behaviour`, `print_yara`, `print_intel`) are used by both `scan_single_file` and `scan_single_url` to avoid duplication. `parse_stats` sets variables in the **caller's scope** — this is intentional, not a bug.

---

## All Flags & Defaults

| Flag | Default | Description |
|------|---------|-------------|
| `-w, --wait` | `false` | Poll every 15s until scan status is `completed` |
| `-o, --output <file>` | `""` | Save raw analysis JSON to file |
| `-t, --threshold <n>` | `-1` (disabled) | Exit code 2 if malicious count ≥ n |
| `--html <file>` | `""` | Write self-contained HTML report |
| `--behaviour` | `false` | Fetch and display sandbox behaviour summary |
| `--yara` | `false` | Fetch and display YARA rule matches |
| `--intel` | `false` | Fetch VT Intelligence data (premium API key required) |
| `--all` | — | Sets `--behaviour`, `--yara`, and `--intel` together |
| `--notify <url>` | `""` | POST Slack-compatible JSON to webhook on completion |
| `--recursive` | `false` | Unpack `.zip`/`.apk`/`.jar` and scan inner files |
| `--no-cache` | `false` | Skip cache read/write, always re-query VT |
| `--log <file>` | `vt_scan_log.md` | Markdown log file path |
| `--no-log` | — | Sets `LOG_FILE=""` to disable logging |
| `--url <url>` | — | Explicit URL target (also auto-detected from `https?://` prefix) |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Fatal error (missing dep, no valid targets, API failure) |
| `2` | Threshold exceeded (malicious count ≥ `--threshold`) |

---

## vt-cli Command Reference

These are the exact `vt-cli` commands the script uses. Do not change them without testing — the output format matters.

| Command | Usage in script | Notes |
|---------|----------------|-------|
| `vt scan file <path>` | Submit a file for scanning | Returns: `<filename> <base64_analysis_id>` |
| `vt scan url <url>` | Submit a URL for scanning | Returns: `<url> <base64_analysis_id>` |
| `vt analysis <id>` | Fetch analysis result by ID | Returns flat JSON array `[{status, stats, results}]` |
| `vt file <hash>` | Look up existing file by SHA-256 | Returns object or array; may fail with non-zero if not found |
| `vt file <hash> --include behaviour_summary` | Fetch sandbox behaviour | May be empty if file not sandboxed |
| `vt file <hash> --include crowdsourced_yara_results` | Fetch YARA matches | May be empty |
| `vt file <hash> --include sigma_analysis_results,...` | Fetch intel enrichment | Requires premium API |
| `vt url <url> --include threat_severity,categories` | Fetch URL intel | Requires premium API |

**Analysis ID format:** `vt scan` returns a Base64-encoded string that decodes to `<md5_or_url_hash>:<unix_timestamp>`. This raw Base64 string is passed directly to `vt analysis`.

---

## JSON Structure

`vt analysis <id> --format json` returns:

```json
[
  {
    "_id": "base64_id",
    "_type": "analysis",
    "date": 1234567890,
    "status": "completed",
    "stats": {
      "malicious": 5,
      "suspicious": 1,
      "harmless": 61,
      "undetected": 5,
      "timeout": 0,
      "type-unsupported": 0,
      "confirmed-timeout": 0,
      "failure": 0
    },
    "results": {
      "EngineName": {
        "category": "malicious",
        "result": "Trojan.AndroidOS.Agent",
        "method": "blacklist",
        "engine_version": "1.0"
      }
    }
  }
]
```

**Important:** There is no `.data` or `.attributes` wrapper. All fields are directly on `.[0]`.

---

## Markdown Log Format

The log (`vt_scan_log.md`) is a GFM table. The header is written once on first creation. Each scan appends one row.

**Columns:** Scanned At | Type | Target | Verdict | Detections | Identifier | Report

**Type icons:** `📄 File` or `🌐 URL`

**Verdict badges:** `🔴 MALICIOUS` / `🟡 SUSPICIOUS` / `🟢 CLEAN` / `⏳ PENDING`

**Identifier:** SHA-256 for files, base64url of URL for URLs (matches VT GUI link format)

---

## HTML Report

Generated by `generate_html()`. Self-contained single HTML file with:
- Dark theme (`#0f1117` background)
- File/URL metadata block
- Colour-coded verdict banner (green/orange/red)
- Detection stat cards
- Full engine results table sorted by category, styled by verdict colour
- Footer with VirusTotal GUI deep-link

VT links: `/gui/file/<sha256>` for files, `/gui/url/<base64url_id>` for URLs.

---

## Webhook / Slack Payload

`send_notification()` POSTs a Slack attachment-format JSON payload. Compatible with Slack incoming webhooks, Discord (via Slack-compat mode), and any service accepting this format.

Fields in the attachment: Target, Verdict, Detections (`n/total`), Identifier, Report URL.

Color: `"danger"` (red) for MALICIOUS, `"warning"` (yellow) for SUSPICIOUS, `"good"` (green) otherwise.

---

## Common Patterns When Making Changes

### Adding a new flag

1. Add default value in the argument defaults block (lines ~116–128)
2. Add a `case` entry in the `while [[ $# -gt 0 ]]` parser
3. Add a line to `usage()`
4. Use `[[ "$MY_FLAG" == "true" ]]` for boolean checks — never `if $MY_FLAG`
5. Update `README.md` options table and feature section
6. Update `CLAUDE.md` flags table

### Adding a new vt-cli data fetch

1. Add a new `print_*` helper function following the pattern of `print_behaviour` / `print_yara`
2. Always guard with `2>/dev/null || true` on the `vt` call
3. Always use `(if type=="array" then .[0] else . end)` in jq to handle both array and object responses from `vt file`
4. Call from `scan_single_file` and/or `scan_single_url` behind an appropriate flag check

### Modifying JSON parsing

- `vt analysis` → always use `.[0].field`
- `vt file` → always use `(if type=="array" then .[0] else . end) | .field // .attributes.field` (the file lookup response structure varies)
- Always provide a `// "default"` fallback in jq to avoid null propagation
- Always append `2>/dev/null || echo "fallback"` to the shell command

### Testing changes

```bash
# Syntax check
bash -n vt_analysis.sh

# Dry run help
./vt_analysis.sh --help

# Quick file scan (no wait, uses cache if available)
./vt_analysis.sh /path/to/file.apk

# Full file scan with all features
./vt_analysis.sh /path/to/file.apk --wait --all --html report.html

# URL scan
./vt_analysis.sh https://example.com --wait

# Batch
./vt_analysis.sh *.apk --wait --threshold 1

# Verify cache was written
cat ~/.vt_cache.json | jq 'keys'

# Verify log was written
cat vt_scan_log.md
```

---

## Known Limitations & Gotchas

- **`vt file <hash>` returns non-zero if the file is not in VT.** This is normal. The script handles this with `|| true`. Do not treat this as an error.
- **`vt scan` for large files (50MB+) can take minutes to complete.** Always use `--wait` for reliable results on large files.
- **Free API rate limits:** 4 requests/minute, 500/day. The hash-lookup-first logic and caching reduce unnecessary API calls significantly.
- **`--behaviour`, `--yara`, `--intel` each consume one additional API request per target.**
- **`--intel` requires a premium VT API key.** On free keys it returns empty data without an explicit error — the script warns about this.
- **`--recursive` scans each inner file as a separate VT submission.** For large archives with many files, this consumes significant API quota.
- **URL cache TTL is 1 hour** (vs 24 hours for files) because URLs can change rapidly.
- **`parse_stats()` sets variables in the caller's scope.** This is a deliberate use of bash's dynamic scoping for functions — the variables `STATUS`, `MALICIOUS`, `SUSPICIOUS`, etc. must be declared `local` in the calling function before `parse_stats` is called.
- **`set -e` must NOT be re-added.** Many `vt-cli` commands return non-zero for normal conditions. Adding `set -e` will cause silent exits that are very difficult to debug.
- **`--format json` always produces a flat array from `vt analysis`.** Never assume an object response from this command.

---

## Dependencies

| Tool | Required | Purpose |
|------|----------|---------|
| `vt` (vt-cli) | ✅ Required | All VirusTotal API calls |
| `jq` | ✅ Required | JSON parsing |
| `base64` | ✅ Required | Decode analysis IDs |
| `sha256sum` | ✅ Required | File hashing and cache keys |
| `curl` | ⚠️ Optional | Webhook notifications (`--notify`) |
| `unzip` | ⚠️ Optional | Recursive archive scanning (`--recursive`) |
| `file` | ⚠️ Optional | MIME type detection for archive unpacking |

Missing optional tools produce a `[WARN]` at startup but do not exit.
