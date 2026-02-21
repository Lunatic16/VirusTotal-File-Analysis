# vt_analysis.sh

A bash script for scanning files against VirusTotal using the `vt-cli` tool. It submits a file for scanning, decodes the returned Base64 analysis ID, polls for completion, and displays a formatted threat summary in the terminal.

---

## Requirements

| Tool | Purpose | Install |
|------|---------|---------|
| [`vt-cli`](https://github.com/VirusTotal/vt-cli) | VirusTotal CLI client | See below |
| `jq` | JSON parsing | `sudo apt install jq` / `brew install jq` |
| `base64` | Decode analysis ID | Pre-installed on Linux/macOS |
| `sha256sum` | File hashing | Pre-installed on Linux (`coreutils`) |

### Installing vt-cli

```bash
# macOS
brew install virustotal/virustotal/vt

# Linux (download latest release binary)
wget https://github.com/VirusTotal/vt-cli/releases/latest/download/Linux64.zip
unzip Linux64.zip && sudo mv vt /usr/local/bin/

# Configure with your API key (free account at virustotal.com)
vt init
```

> A free VirusTotal API key is required. Register at [virustotal.com](https://www.virustotal.com).

---

## Usage

```bash
chmod +x vt_analysis.sh
./vt_analysis.sh <file> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-w, --wait` | Poll every 15s until the scan completes (**recommended**) |
| `-o, --output <file>` | Save the full raw JSON report to a file |
| `-h, --help` | Show usage information |

### Examples

```bash
# Basic scan (may show 'queued' if VT hasn't finished yet)
./vt_analysis.sh suspicious.apk

# Wait for scan to fully complete before showing results
./vt_analysis.sh suspicious.apk --wait

# Wait and save the full JSON report
./vt_analysis.sh malware.bin --wait --output report.json
```

---

## How It Works

**Step 1 — Submit the file**
Runs `vt scan file <file>` which uploads the file to VirusTotal and returns a line in the format:
```
<filename>  <Base64_analysis_id>
```
The script extracts the Base64 ID from the last token (safe for filenames with spaces).

**Step 2 — Decode the analysis ID**
The Base64 string decodes to `<md5_hash>:<unix_timestamp>`, which is displayed for reference. The raw Base64 string is passed to the next step as `vt analysis` expects it in that form.

**Step 3 — Fetch and display results**
Runs `vt analysis <id> --format json` and parses the flat JSON array returned by vt-cli. If `--wait` is set, it polls every 15 seconds until `status` becomes `completed`.

---

## Output

```
════════════════════════════════════════════════════
  VirusTotal File Analysis
════════════════════════════════════════════════════
[INFO]  Target file : Test.apk
[INFO]  File size   : 59M
[INFO]  SHA-256     : ec78885a4d48e5ef0ab6b2...

[INFO]  Step 1/3 — Submitting file to VirusTotal...
[OK]    Analysis ID (Base64) obtained: ZjAyYjYw...

[INFO]  Step 2/3 — Decoding Base64 analysis ID...
[OK]    Decoded analysis ID: f02b60fea454...
  File hash  : f02b60fea4545019f6f82803347ed16c
  Submitted  : Sat Feb 21 06:06:26 PM EST 2026

[INFO]  Step 3/3 — Fetching analysis report...
[WARN]  Status: queued — waiting 15 seconds...
[OK]    Analysis completed!

────────────────────────────────────────────────────
  Analysis Summary
────────────────────────────────────────────────────
  Status           : completed
  Total engines    : 72
  Malicious        : 5
  Suspicious       : 1
  Harmless         : 61
  Undetected       : 5

  ⚠  VERDICT: MALICIOUS — 5 engine(s) flagged this file!

  Malicious Engine Results (top 10):
  BitDefender: Android.Trojan.Agent
  Kaspersky: HEUR:Trojan-Spy.AndroidOS.Agent
  ...
────────────────────────────────────────────────────

  Full report: https://www.virustotal.com/gui/file/ec78885a...
```

---

## Notes

- **Large files** (50MB+) take longer to process on VT's backend — always use `--wait` for reliable results.
- **Free API accounts** have rate limits (4 requests/minute, 500/day). Avoid scanning the same file repeatedly.
- **`status: queued`** without `--wait` will show all-zero stats and a misleading CLEAN verdict — the script will warn you if this happens.
- The script uses the SHA-256 of the local file for the final VirusTotal GUI link, which works even if the analysis ID has changed between scans.

---

## License

MIT — free to use and modify.
