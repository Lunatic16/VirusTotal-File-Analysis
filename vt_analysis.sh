#!/bin/bash
# ============================================================
# vt_analysis.sh — VirusTotal File Scan & Analysis via vt-cli
# Usage: ./vt_analysis.sh <file_path> [options]
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

check_deps() {
    for cmd in vt base64 jq; do
        if ! command -v "$cmd" &>/dev/null; then
            error "Required command not found: $cmd"
            [[ "$cmd" == "vt" ]] && echo "  → Install vt-cli: https://github.com/VirusTotal/vt-cli"
            [[ "$cmd" == "jq" ]] && echo "  → Install jq:     https://stedolan.github.io/jq/"
            exit 1
        fi
    done
}

usage() {
    echo -e "${BOLD}Usage:${RESET} $0 <file_path> [options]"
    echo ""
    echo "Options:"
    echo "  -o, --output <file>   Save full analysis JSON to file"
    echo "  -w, --wait            Poll until analysis completes (recommended)"
    echo "  -h, --help            Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 suspicious.apk --wait"
    echo "  $0 malware.bin --wait --output report.json"
    exit 0
}

# jq helper — vt-cli returns a flat array: .[0].field (NO .data.attributes wrapper)
jq_vt() {
    local filter="$1"
    echo "$ANALYSIS_JSON" | jq -r ".[0]${filter} // \"N/A\"" 2>/dev/null || echo "N/A"
}

FILE=""
OUTPUT_FILE=""
WAIT_FOR_RESULT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)   usage ;;
        -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
        -w|--wait)   WAIT_FOR_RESULT=true; shift ;;
        -*)          error "Unknown option: $1"; usage ;;
        *)           FILE="$1"; shift ;;
    esac
done

[[ -z "$FILE" ]] && { error "No file specified."; usage; }
[[ -f "$FILE" ]] || { error "File not found: $FILE"; exit 1; }

check_deps

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  VirusTotal File Analysis${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo ""
info "Target file : $FILE"
info "File size   : $(du -sh "$FILE" | cut -f1)"
info "SHA-256     : $(sha256sum "$FILE" | awk '{print $1}')"
echo ""

# ── Step 1 — Submit file ─────────────────────────────────────
info "Step 1/3 — Submitting file to VirusTotal..."

SCAN_OUTPUT=$(vt scan file "$FILE" 2>&1)

if [[ -z "$SCAN_OUTPUT" ]]; then
    error "vt scan file returned no output. Check your API key: vt config"
    exit 1
fi

echo -e "  Raw scan output: ${YELLOW}${SCAN_OUTPUT}${RESET}"

# Base64 ID is always the last token (safe for filenames with spaces)
ANALYSIS_ID=$(echo "$SCAN_OUTPUT" | awk '{print $NF}')

if [[ -z "$ANALYSIS_ID" ]]; then
    error "Could not extract analysis ID from scan output."
    exit 1
fi

success "Analysis ID (Base64) obtained: $ANALYSIS_ID"
echo ""

# ── Step 2 — Decode the ID ───────────────────────────────────
info "Step 2/3 — Decoding Base64 analysis ID..."

DECODED_ID=$(echo "$ANALYSIS_ID" | base64 --decode 2>/dev/null || true)

if [[ -n "$DECODED_ID" ]]; then
    success "Decoded analysis ID: $DECODED_ID"
    HASH_PART=$(echo "$DECODED_ID" | cut -d':' -f1)
    TIMESTAMP_PART=$(echo "$DECODED_ID" | cut -d':' -f2)
    [[ -n "$HASH_PART" ]]      && echo -e "  File hash  : ${HASH_PART}"
    [[ -n "$TIMESTAMP_PART" ]] && echo -e "  Submitted  : $(date -d "@${TIMESTAMP_PART}" 2>/dev/null || date -r "${TIMESTAMP_PART}" 2>/dev/null || echo "$TIMESTAMP_PART")"
else
    warn "Base64 decode produced no output — using raw ID."
fi
echo ""

# ── Step 3 — Fetch results (with optional polling) ───────────
info "Step 3/3 — Fetching analysis report..."
info "Using analysis ID: $ANALYSIS_ID"
echo ""

if $WAIT_FOR_RESULT; then
    info "Polling until analysis completes (large files may take several minutes)..."
    while true; do
        ANALYSIS_JSON=$(vt analysis "$ANALYSIS_ID" --format json 2>/dev/null || true)
        POLL_STATUS=$(echo "$ANALYSIS_JSON" | jq -r '.[0].status // "queued"' 2>/dev/null || echo "queued")
        if [[ "$POLL_STATUS" == "completed" ]]; then
            success "Analysis completed!"
            break
        fi
        warn "Status: ${POLL_STATUS} — waiting 15 seconds..."
        sleep 15
    done
else
    ANALYSIS_JSON=$(vt analysis "$ANALYSIS_ID" --format json 2>&1)
    CURRENT_STATUS=$(echo "$ANALYSIS_JSON" | jq -r '.[0].status // "unknown"' 2>/dev/null || echo "unknown")
    if [[ "$CURRENT_STATUS" == "queued" || "$CURRENT_STATUS" == "in-progress" ]]; then
        warn "Scan is still '${CURRENT_STATUS}'. Results will show zeros until complete."
        warn "Re-run with --wait for final results: $0 $FILE --wait"
        echo ""
    fi
fi

if [[ -z "$ANALYSIS_JSON" ]]; then
    error "No output from 'vt analysis'. Check API key: vt config"
    exit 1
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"
echo -e "${BOLD}  Analysis Summary${RESET}"
echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"

STATUS=$(jq_vt '.status')
MALICIOUS=$(jq_vt '.stats.malicious')
SUSPICIOUS=$(jq_vt '.stats.suspicious')
HARMLESS=$(jq_vt '.stats.harmless')
UNDETECTED=$(jq_vt '.stats.undetected')
TIMEOUT=$(jq_vt '.stats.timeout')
UNSUPPORTED=$(jq_vt '."stats"."type-unsupported"')
TOTAL=$(echo "$ANALYSIS_JSON" | jq -r '.[0].stats | to_entries | map(.value) | add // "N/A"' 2>/dev/null || echo "N/A")

echo -e "  Status           : ${BOLD}${STATUS}${RESET}"
echo -e "  Total engines    : ${BOLD}${TOTAL}${RESET}"
echo -e "  Malicious        : ${RED}${MALICIOUS}${RESET}"
echo -e "  Suspicious       : ${YELLOW}${SUSPICIOUS}${RESET}"
echo -e "  Harmless         : ${GREEN}${HARMLESS}${RESET}"
echo -e "  Undetected       : ${UNDETECTED}"
echo -e "  Timeout          : ${TIMEOUT}"
echo -e "  Type-unsupported : ${UNSUPPORTED}"

echo ""
if [[ "$MALICIOUS" != "N/A" && "$MALICIOUS" -gt 0 ]]; then
    echo -e "  ${RED}${BOLD}⚠  VERDICT: MALICIOUS — ${MALICIOUS} engine(s) flagged this file!${RESET}"
elif [[ "$SUSPICIOUS" != "N/A" && "$SUSPICIOUS" -gt 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}⚠  VERDICT: SUSPICIOUS — ${SUSPICIOUS} engine(s) flagged this file.${RESET}"
elif [[ "$STATUS" == "completed" ]]; then
    echo -e "  ${GREEN}${BOLD}✔  VERDICT: CLEAN — No malicious or suspicious detections.${RESET}"
else
    echo -e "  ${YELLOW}${BOLD}⏳  VERDICT: Pending — scan not yet complete (run with --wait).${RESET}"
fi

# ── Malicious engine hits ────────────────────────────────────
HITS=$(echo "$ANALYSIS_JSON" | jq -r '
    .[0].results // {}
    | to_entries
    | map(select(.value.category == "malicious"))
    | .[:10][]
    | "  \(.key): \(.value.result)"
' 2>/dev/null || true)

if [[ -n "$HITS" ]]; then
    echo ""
    echo -e "${BOLD}  Malicious Engine Results (top 10):${RESET}"
    while IFS= read -r line; do
        echo -e "  ${RED}${line}${RESET}"
    done <<< "$HITS"
fi

# ── Suspicious engine hits ───────────────────────────────────
SUSP_HITS=$(echo "$ANALYSIS_JSON" | jq -r '
    .[0].results // {}
    | to_entries
    | map(select(.value.category == "suspicious"))
    | .[:5][]
    | "  \(.key): \(.value.result)"
' 2>/dev/null || true)

if [[ -n "$SUSP_HITS" ]]; then
    echo ""
    echo -e "${BOLD}  Suspicious Engine Results (top 5):${RESET}"
    while IFS= read -r line; do
        echo -e "  ${YELLOW}${line}${RESET}"
    done <<< "$SUSP_HITS"
fi

echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"
echo ""

# ── Save JSON ────────────────────────────────────────────────
if [[ -n "$OUTPUT_FILE" ]]; then
    echo "$ANALYSIS_JSON" | jq '.' > "$OUTPUT_FILE"
    success "Full JSON report saved to: $OUTPUT_FILE"
    echo ""
fi

# ── VT link ──────────────────────────────────────────────────
FILE_HASH=$(sha256sum "$FILE" | awk '{print $1}')
echo -e "  ${CYAN}Full report: https://www.virustotal.com/gui/file/${FILE_HASH}${RESET}"
echo ""
