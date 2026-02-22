#!/bin/bash
# ================================================================
# vt_analysis.sh — VirusTotal File & URL Analysis via vt-cli
# ================================================================

# NOTE: We intentionally do NOT use 'set -e' because many vt-cli
# commands return non-zero when a file/url is not found on VT,
# which is a normal condition. We handle all errors manually.
set -uo pipefail

trap 'echo -e "\n${RED}[FATAL]${RESET} Script died unexpectedly at line $LINENO. Command: ${BASH_COMMAND}" >&2' ERR

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m';   MAGENTA='\033[0;35m'
BOLD='\033[1m';      DIM='\033[2m';       RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
section() {
    echo ""
    echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"
    echo -e "${BOLD}  $*${RESET}"
    echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"
}

# ── Cache ─────────────────────────────────────────────────────
CACHE_FILE="${HOME}/.vt_cache.json"

cache_get() {
    local key="$1"
    if [[ -f "$CACHE_FILE" ]]; then
        jq -r --arg k "$key" '.[$k] // empty' "$CACHE_FILE" 2>/dev/null || true
    fi
}

cache_set() {
    local key="$1"
    local data="$2"
    local tmp
    tmp=$(mktemp)
    if [[ -f "$CACHE_FILE" ]]; then
        jq --arg k "$key" --argjson d "$data" '. + {($k): $d}' "$CACHE_FILE" > "$tmp" 2>/dev/null || cp "$CACHE_FILE" "$tmp"
    else
        jq -n --arg k "$key" --argjson d "$data" '{($k): $d}' > "$tmp" 2>/dev/null || true
    fi
    mv "$tmp" "$CACHE_FILE" 2>/dev/null || true
}

# ── Dependencies ──────────────────────────────────────────────
check_deps() {
    local missing=0
    for cmd in vt base64 jq sha256sum; do
        if ! command -v "$cmd" &>/dev/null; then
            error "Required command not found: $cmd"
            [[ "$cmd" == "vt" ]] && echo "  → Install vt-cli: https://github.com/VirusTotal/vt-cli"
            [[ "$cmd" == "jq" ]] && echo "  → Install jq:     sudo apt install jq / brew install jq"
            missing=1
        fi
    done
    for cmd in unzip curl file; do
        command -v "$cmd" &>/dev/null || warn "Optional tool not found: $cmd (some features may be unavailable)"
    done
    [[ "$missing" -eq 1 ]] && exit 1
    return 0
}

# ── Detect if input looks like a URL ──────────────────────────
is_url() {
    [[ "$1" =~ ^https?:// ]] || [[ "$1" =~ ^ftp:// ]]
}

# ── Usage ─────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}Usage:${RESET}"
    echo "  $0 <file|dir|glob|url> [options]"
    echo ""
    echo -e "${BOLD}Scan targets:${RESET}"
    echo "  <file>                   Scan a single file"
    echo "  <dir|glob>               Scan all files in a directory or matching a glob"
    echo "  <url>                    Scan a URL (e.g. https://example.com)"
    echo "  --url <url>              Explicitly scan a URL (useful in scripts)"
    echo ""
    echo -e "${BOLD}Core options:${RESET}"
    echo "  -w, --wait               Poll until scan completes (recommended)"
    echo "  -o, --output <file>      Save raw JSON report to file"
    echo "  -t, --threshold <n>      Exit code 2 if malicious detections >= n (CI/CD)"
    echo ""
    echo -e "${BOLD}Report options:${RESET}"
    echo "  --html <file>            Generate self-contained HTML report"
    echo "  --behaviour              Show sandbox behaviour summary (files only)"
    echo "  --yara                   Show crowdsourced YARA rule matches (files only)"
    echo "  --intel                  Show VT Intelligence enrichment (premium API)"
    echo "  --all                    Enable --behaviour + --yara + --intel"
    echo ""
    echo -e "${BOLD}Other options:${RESET}"
    echo "  --notify <webhook_url>   POST summary to Slack/webhook on completion"
    echo "  --recursive              Unpack archives and scan inner files too"
    echo "  --no-cache               Skip local cache, always re-query VT"
    echo "  --log <file>             Append scan result to markdown log (default: vt_scan_log.md)"
    echo "  --no-log                 Disable markdown logging entirely"
    echo "  -h, --help               Show this help"
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0 suspicious.apk --wait"
    echo "  $0 https://suspicious-site.com --wait"
    echo "  $0 --url https://malware.example.com --wait --html report.html"
    echo "  $0 malware.apk --wait --all --html report.html"
    echo "  $0 *.apk --wait --threshold 1"
    exit 0
}

# ── Argument parsing ──────────────────────────────────────────
FILES=()
URLS=()
OUTPUT_FILE=""
HTML_FILE=""
WAIT_FOR_RESULT=false
THRESHOLD=-1
SHOW_BEHAVIOUR=false
SHOW_YARA=false
SHOW_INTEL=false
NOTIFY_URL=""
RECURSIVE=false
NO_CACHE=false
LOG_FILE="vt_scan_log.md"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)       usage ;;
        -w|--wait)       WAIT_FOR_RESULT=true;  shift ;;
        -o|--output)     OUTPUT_FILE="$2";      shift 2 ;;
        -t|--threshold)  THRESHOLD="$2";        shift 2 ;;
        --html)          HTML_FILE="$2";        shift 2 ;;
        --behaviour)     SHOW_BEHAVIOUR=true;   shift ;;
        --yara)          SHOW_YARA=true;        shift ;;
        --intel)         SHOW_INTEL=true;       shift ;;
        --all)           SHOW_BEHAVIOUR=true; SHOW_YARA=true; SHOW_INTEL=true; shift ;;
        --notify)        NOTIFY_URL="$2";       shift 2 ;;
        --recursive)     RECURSIVE=true;        shift ;;
        --no-cache)      NO_CACHE=true;         shift ;;
        --log)           LOG_FILE="$2";         shift 2 ;;
        --no-log)        LOG_FILE="";           shift ;;
        --url)           URLS+=("$2");          shift 2 ;;
        -*)              error "Unknown option: $1"; usage ;;
        *)
            # Auto-detect URLs passed as positional arguments
            if is_url "$1"; then
                URLS+=("$1")
            else
                FILES+=("$1")
            fi
            shift ;;
    esac
done

if [[ ${#FILES[@]} -eq 0 && ${#URLS[@]} -eq 0 ]]; then
    error "No file or URL specified."
    usage
fi

check_deps

# ── Expand directories/globs into flat file list ──────────────
EXPANDED_FILES=()
for entry in "${FILES[@]}"; do
    if [[ -d "$entry" ]]; then
        while IFS= read -r -d '' f; do
            EXPANDED_FILES+=("$f")
        done < <(find "$entry" -maxdepth 1 -type f -print0 2>/dev/null)
    elif [[ -f "$entry" ]]; then
        EXPANDED_FILES+=("$entry")
    else
        warn "Skipping (not found): $entry"
    fi
done

TOTAL_TARGETS=$(( ${#EXPANDED_FILES[@]} + ${#URLS[@]} ))
BATCH_MODE=false
[[ "$TOTAL_TARGETS" -gt 1 ]] && BATCH_MODE=true

declare -A BATCH_VERDICT
declare -A BATCH_MALICIOUS
declare -A BATCH_NAME
BATCH_EXIT_CODE=0

# ================================================================
#  FUNCTION: write_log
#  Appends one row to the markdown scan log.
#  Args: $1=target_label  $2=cache_key  $3=verdict  $4=malicious
#        $5=suspicious     $6=total      $7=type (file|url)
# ================================================================
write_log() {
    local LABEL="$1" KEY="$2" VERDICT="$3" MALICIOUS="$4"
    local SUSPICIOUS="$5" TOTAL="$6" TARGET_TYPE="$7"
    local SCAN_TIME
    SCAN_TIME=$(date "+%Y-%m-%d %H:%M:%S %Z")
    local LOG="${LOG_FILE}"

    [[ -z "$LOG" ]] && return 0

    # Build the VT report URL differently for files vs URLs
    local VT_URL
    if [[ "$TARGET_TYPE" == "url" ]]; then
        # VT URL report page uses the URL's own identifier
        VT_URL="https://www.virustotal.com/gui/url/${KEY}"
    else
        VT_URL="https://www.virustotal.com/gui/file/${KEY}"
    fi

    # Write header if log file does not exist yet
    if [[ ! -f "$LOG" ]]; then
        cat > "$LOG" << MDHEADER
# VirusTotal Scan Log

> Auto-generated by \`vt_analysis.sh\`. Each entry records a scan result.

| Scanned At | Type | Target | Verdict | Detections | Identifier | Report |
|------------|------|--------|---------|------------|------------|--------|
MDHEADER
    fi

    local BADGE
    case "$VERDICT" in
        MALICIOUS)  BADGE="🔴 MALICIOUS"  ;;
        SUSPICIOUS) BADGE="🟡 SUSPICIOUS" ;;
        CLEAN)      BADGE="🟢 CLEAN"      ;;
        *)          BADGE="⏳ PENDING"    ;;
    esac

    local TYPE_ICON
    [[ "$TARGET_TYPE" == "url" ]] && TYPE_ICON="🌐 URL" || TYPE_ICON="📄 File"

    printf "| %s | %s | \`%s\` | %s | %s / %s | \`%s\` | [View](%s) |\n" \
        "$SCAN_TIME" \
        "$TYPE_ICON" \
        "$LABEL" \
        "$BADGE" \
        "$MALICIOUS" \
        "$TOTAL" \
        "$KEY" \
        "$VT_URL" \
        >> "$LOG"

    success "Scan logged to: $LOG"
}

# ================================================================
#  FUNCTION: scan_single_file
# ================================================================
scan_single_file() {
    local FILE="$1"
    local FILE_HASH
    FILE_HASH=$(sha256sum "$FILE" | awk '{print $1}')

    echo ""
    echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  VirusTotal File Analysis${RESET}"
    echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
    echo ""
    info "Target file : $FILE"
    info "File size   : $(du -sh "$FILE" | cut -f1)"
    info "SHA-256     : $FILE_HASH"
    echo ""

    local ANALYSIS_JSON=""
    local USED_CACHE=false

    # ── 1. Cache check ────────────────────────────────────────
    if [[ "$NO_CACHE" == "false" ]]; then
        local CACHED
        CACHED=$(cache_get "$FILE_HASH")
        if [[ -n "$CACHED" ]]; then
            local CACHED_TIME CACHED_STATUS NOW AGE
            CACHED_TIME=$(echo "$CACHED" | jq -r '.cached_at // 0' 2>/dev/null || echo "0")
            CACHED_STATUS=$(echo "$CACHED" | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")
            NOW=$(date +%s)
            AGE=$(( NOW - CACHED_TIME ))
            if [[ "$CACHED_STATUS" == "completed" && "$AGE" -lt 86400 ]]; then
                success "Cache hit! Using result cached ${AGE}s ago."
                ANALYSIS_JSON="[$CACHED]"
                USED_CACHE=true
            else
                info "Cache entry stale or incomplete — re-querying VT."
            fi
        fi
    fi

    # ── 2. Hash lookup (skip upload if VT already has it) ─────
    if [[ "$USED_CACHE" == "false" ]]; then
        info "Checking if file is already known to VirusTotal..."
        local HASH_JSON
        HASH_JSON=$(vt file "$FILE_HASH" --format json 2>/dev/null || true)

        local HASH_KNOWN=false
        if [[ -n "$HASH_JSON" ]]; then
            local LAST_DATE
            LAST_DATE=$(echo "$HASH_JSON" | jq -r '
                (if type=="array" then .[0] else . end)
                | .last_analysis_date // .attributes.last_analysis_date // 0
            ' 2>/dev/null || echo "0")
            if [[ "$LAST_DATE" != "0" && "$LAST_DATE" != "null" && -n "$LAST_DATE" ]]; then
                HASH_KNOWN=true
                local LD_FMT
                LD_FMT=$(date -d "@${LAST_DATE}" 2>/dev/null || date -r "${LAST_DATE}" 2>/dev/null || echo "$LAST_DATE")
                success "File already known to VT (last analysed: $LD_FMT) — skipping upload."
                ANALYSIS_JSON=$(echo "$HASH_JSON" | jq '
                    (if type=="array" then .[0] else . end) as $f |
                    [{
                        status:  "completed",
                        stats:   ($f.last_analysis_stats   // $f.attributes.last_analysis_stats   // {}),
                        results: ($f.last_analysis_results // $f.attributes.last_analysis_results // {})
                    }]
                ' 2>/dev/null || echo "[]")
            fi
        fi

        # ── 3. Upload if not already known ────────────────────
        if [[ "$HASH_KNOWN" == "false" ]]; then
            info "File not in VT — uploading for scan..."
            local SCAN_OUTPUT
            SCAN_OUTPUT=$(vt scan file "$FILE" 2>&1 || true)

            if [[ -z "$SCAN_OUTPUT" ]]; then
                error "vt scan file returned no output. Check API key: vt config"
                return 1
            fi

            echo -e "  Scan output: ${YELLOW}${SCAN_OUTPUT}${RESET}"
            local ANALYSIS_ID
            ANALYSIS_ID=$(echo "$SCAN_OUTPUT" | awk '{print $NF}')

            if [[ -z "$ANALYSIS_ID" ]]; then
                error "Could not extract analysis ID from scan output."
                return 1
            fi

            success "Analysis ID: $ANALYSIS_ID"

            local DECODED_ID
            DECODED_ID=$(echo "$ANALYSIS_ID" | base64 --decode 2>/dev/null || true)
            if [[ -n "$DECODED_ID" ]]; then
                local HASH_PART TS_PART
                HASH_PART=$(echo "$DECODED_ID" | cut -d':' -f1)
                TS_PART=$(echo "$DECODED_ID"   | cut -d':' -f2)
                [[ -n "$HASH_PART" ]] && echo -e "  Decoded ID : ${HASH_PART}:${TS_PART}"
                [[ -n "$TS_PART"   ]] && echo -e "  Submitted  : $(date -d "@${TS_PART}" 2>/dev/null || date -r "${TS_PART}" 2>/dev/null || echo "$TS_PART")"
            fi
            echo ""

            if [[ "$WAIT_FOR_RESULT" == "true" ]]; then
                info "Polling for completion..."
                local POLL_JSON POLL_STATUS
                while true; do
                    POLL_JSON=$(vt analysis "$ANALYSIS_ID" --format json 2>/dev/null || true)
                    POLL_STATUS=$(echo "$POLL_JSON" | jq -r '.[0].status // "queued"' 2>/dev/null || echo "queued")
                    if [[ "$POLL_STATUS" == "completed" ]]; then
                        success "Analysis completed!"
                        ANALYSIS_JSON="$POLL_JSON"
                        break
                    fi
                    warn "Status: ${POLL_STATUS} — waiting 15 seconds..."
                    sleep 15
                done
            else
                ANALYSIS_JSON=$(vt analysis "$ANALYSIS_ID" --format json 2>/dev/null || true)
                local CUR_STATUS
                CUR_STATUS=$(echo "$ANALYSIS_JSON" | jq -r '.[0].status // "unknown"' 2>/dev/null || echo "unknown")
                if [[ "$CUR_STATUS" == "queued" || "$CUR_STATUS" == "in-progress" ]]; then
                    warn "Scan is '${CUR_STATUS}' — re-run with --wait for final results."
                fi
            fi
        fi

        # ── Cache the completed result ─────────────────────────
        local FINAL_STATUS
        FINAL_STATUS=$(echo "$ANALYSIS_JSON" | jq -r '.[0].status // "unknown"' 2>/dev/null || echo "unknown")
        if [[ "$FINAL_STATUS" == "completed" ]]; then
            local CACHE_ENTRY
            CACHE_ENTRY=$(echo "$ANALYSIS_JSON" | jq ".[0] + {cached_at: $(date +%s)}" 2>/dev/null || true)
            [[ -n "$CACHE_ENTRY" ]] && cache_set "$FILE_HASH" "$CACHE_ENTRY"
        fi
    fi

    if [[ -z "$ANALYSIS_JSON" ]]; then
        error "No analysis data available for $FILE"
        return 1
    fi

    # ── Print results ──────────────────────────────────────────
    local STATUS MALICIOUS SUSPICIOUS HARMLESS UNDETECTED TIMEOUT UNSUPPORTED TOTAL VERDICT
    print_engine_table "$ANALYSIS_JSON"
    parse_stats "$ANALYSIS_JSON"
    print_stats_summary "$STATUS" "$MALICIOUS" "$SUSPICIOUS" "$HARMLESS" "$UNDETECTED" "$TIMEOUT" "$UNSUPPORTED" "$TOTAL"
    determine_verdict "$MALICIOUS" "$SUSPICIOUS" "$STATUS"

    BATCH_VERDICT["$FILE_HASH"]="$VERDICT"
    BATCH_MALICIOUS["$FILE_HASH"]="$MALICIOUS"
    BATCH_NAME["$FILE_HASH"]="$FILE"

    if [[ "$THRESHOLD" -ge 0 ]] 2>/dev/null; then
        [[ "$MALICIOUS" -ge "$THRESHOLD" ]] 2>/dev/null && BATCH_EXIT_CODE=2
    fi

    # ── Behaviour ─────────────────────────────────────────────
    if [[ "$SHOW_BEHAVIOUR" == "true" ]]; then
        section "Behaviour / Sandbox Report"
        info "Fetching sandbox behaviour summary..."
        local BEH_JSON
        BEH_JSON=$(vt file "$FILE_HASH" --include behaviour_summary --format json 2>/dev/null || true)
        print_behaviour "$BEH_JSON"
    fi

    # ── YARA ──────────────────────────────────────────────────
    if [[ "$SHOW_YARA" == "true" ]]; then
        section "YARA Rule Matches"
        info "Fetching crowdsourced YARA rule matches..."
        local YARA_JSON
        YARA_JSON=$(vt file "$FILE_HASH" --include crowdsourced_yara_results --format json 2>/dev/null || true)
        print_yara "$YARA_JSON"
    fi

    # ── Intel ─────────────────────────────────────────────────
    if [[ "$SHOW_INTEL" == "true" ]]; then
        section "VT Intelligence Enrichment (Premium)"
        info "Fetching threat intelligence data..."
        local INTEL_JSON
        INTEL_JSON=$(vt file "$FILE_HASH" --include sigma_analysis_results,crowdsourced_ids_results,threat_severity --format json 2>/dev/null || true)
        print_intel "$INTEL_JSON"
    fi

    # ── Recursive archive ─────────────────────────────────────
    if [[ "$RECURSIVE" == "true" ]]; then
        local MIME_TYPE
        MIME_TYPE=$(file --mime-type -b "$FILE" 2>/dev/null || echo "unknown")
        case "$MIME_TYPE" in
            application/zip|application/java-archive|application/vnd.android.package-archive)
                section "Recursive Archive Scan"
                info "Unpacking $FILE ($MIME_TYPE)..."
                local TMP_DIR
                TMP_DIR=$(mktemp -d)
                if unzip -q "$FILE" -d "$TMP_DIR" 2>/dev/null; then
                    local INNER_FILES=()
                    while IFS= read -r -d '' f; do
                        INNER_FILES+=("$f")
                    done < <(find "$TMP_DIR" -type f -print0 2>/dev/null)
                    info "Found ${#INNER_FILES[@]} inner file(s) to scan."
                    for inner in "${INNER_FILES[@]}"; do
                        echo -e "\n${BOLD}  ── Inner file: ${inner#"$TMP_DIR/"}${RESET}"
                        scan_single_file "$inner" || true
                    done
                else
                    warn "Could not unpack archive."
                fi
                rm -rf "$TMP_DIR"
                ;;
        esac
    fi

    [[ -n "$OUTPUT_FILE" ]]  && { echo "$ANALYSIS_JSON" | jq '.' > "$OUTPUT_FILE" 2>/dev/null || true; success "JSON saved to: $OUTPUT_FILE"; }
    [[ -n "$HTML_FILE" ]]    && { generate_html "$FILE" "$FILE_HASH" "$ANALYSIS_JSON" "$STATUS" "$MALICIOUS" "$SUSPICIOUS" "$HARMLESS" "$UNDETECTED" "$TOTAL" "$VERDICT" > "$HTML_FILE"; success "HTML report saved to: $HTML_FILE"; }
    [[ -n "$NOTIFY_URL" ]]   && send_notification "$FILE" "$FILE_HASH" "$VERDICT" "$MALICIOUS" "$TOTAL"

    write_log "$(basename "$FILE")" "$FILE_HASH" "$VERDICT" "$MALICIOUS" "$SUSPICIOUS" "$TOTAL" "file"

    echo ""
    echo -e "  ${CYAN}Full report: https://www.virustotal.com/gui/file/${FILE_HASH}${RESET}"
    echo ""
}

# ================================================================
#  FUNCTION: scan_single_url
# ================================================================
scan_single_url() {
    local TARGET_URL="$1"

    echo ""
    echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  VirusTotal URL Analysis${RESET}"
    echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
    echo ""
    info "Target URL  : $TARGET_URL"
    echo ""

    local ANALYSIS_JSON=""
    local USED_CACHE=false

    # Derive a stable cache key: base64-encode the URL (url-safe, no padding issues)
    local URL_KEY
    URL_KEY=$(echo -n "$TARGET_URL" | base64 | tr '+/' '-_' | tr -d '=')

    # ── 1. Cache check ────────────────────────────────────────
    if [[ "$NO_CACHE" == "false" ]]; then
        local CACHED
        CACHED=$(cache_get "$URL_KEY")
        if [[ -n "$CACHED" ]]; then
            local CACHED_TIME CACHED_STATUS NOW AGE
            CACHED_TIME=$(echo "$CACHED" | jq -r '.cached_at // 0' 2>/dev/null || echo "0")
            CACHED_STATUS=$(echo "$CACHED" | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")
            NOW=$(date +%s)
            AGE=$(( NOW - CACHED_TIME ))
            if [[ "$CACHED_STATUS" == "completed" && "$AGE" -lt 3600 ]]; then
                # URL cache TTL is 1 hour (URLs change faster than files)
                success "Cache hit! Using result cached ${AGE}s ago."
                ANALYSIS_JSON="[$CACHED]"
                USED_CACHE=true
            else
                info "Cache entry stale or incomplete — re-querying VT."
            fi
        fi
    fi

    # ── 2. Submit URL for scanning ────────────────────────────
    if [[ "$USED_CACHE" == "false" ]]; then
        info "Step 1/2 — Submitting URL to VirusTotal..."
        local SCAN_OUTPUT
        SCAN_OUTPUT=$(vt scan url "$TARGET_URL" 2>&1 || true)

        if [[ -z "$SCAN_OUTPUT" ]]; then
            error "vt scan url returned no output. Check API key: vt config"
            return 1
        fi

        echo -e "  Scan output: ${YELLOW}${SCAN_OUTPUT}${RESET}"

        # Extract the Base64 analysis ID (last token on the line)
        local ANALYSIS_ID
        ANALYSIS_ID=$(echo "$SCAN_OUTPUT" | awk '{print $NF}')

        if [[ -z "$ANALYSIS_ID" ]]; then
            error "Could not extract analysis ID from scan output."
            return 1
        fi

        success "Analysis ID: $ANALYSIS_ID"

        # Decode for display
        local DECODED_ID
        DECODED_ID=$(echo "$ANALYSIS_ID" | base64 --decode 2>/dev/null || true)
        if [[ -n "$DECODED_ID" ]]; then
            local URL_PART TS_PART
            URL_PART=$(echo "$DECODED_ID" | cut -d':' -f1)
            TS_PART=$(echo "$DECODED_ID"  | cut -d':' -f2)
            [[ -n "$URL_PART" ]] && echo -e "  URL ID     : ${URL_PART}"
            [[ -n "$TS_PART"  ]] && echo -e "  Submitted  : $(date -d "@${TS_PART}" 2>/dev/null || date -r "${TS_PART}" 2>/dev/null || echo "$TS_PART")"
        fi
        echo ""

        # ── 3. Poll or fetch once ──────────────────────────────
        info "Step 2/2 — Fetching analysis report..."
        if [[ "$WAIT_FOR_RESULT" == "true" ]]; then
            info "Polling for completion..."
            local POLL_JSON POLL_STATUS
            while true; do
                POLL_JSON=$(vt analysis "$ANALYSIS_ID" --format json 2>/dev/null || true)
                POLL_STATUS=$(echo "$POLL_JSON" | jq -r '.[0].status // "queued"' 2>/dev/null || echo "queued")
                if [[ "$POLL_STATUS" == "completed" ]]; then
                    success "Analysis completed!"
                    ANALYSIS_JSON="$POLL_JSON"
                    break
                fi
                warn "Status: ${POLL_STATUS} — waiting 15 seconds..."
                sleep 15
            done
        else
            ANALYSIS_JSON=$(vt analysis "$ANALYSIS_ID" --format json 2>/dev/null || true)
            local CUR_STATUS
            CUR_STATUS=$(echo "$ANALYSIS_JSON" | jq -r '.[0].status // "unknown"' 2>/dev/null || echo "unknown")
            if [[ "$CUR_STATUS" == "queued" || "$CUR_STATUS" == "in-progress" ]]; then
                warn "Scan is '${CUR_STATUS}' — re-run with --wait for final results."
            fi
        fi

        # ── Cache the completed result ─────────────────────────
        local FINAL_STATUS
        FINAL_STATUS=$(echo "$ANALYSIS_JSON" | jq -r '.[0].status // "unknown"' 2>/dev/null || echo "unknown")
        if [[ "$FINAL_STATUS" == "completed" ]]; then
            local CACHE_ENTRY
            CACHE_ENTRY=$(echo "$ANALYSIS_JSON" | jq ".[0] + {cached_at: $(date +%s)}" 2>/dev/null || true)
            [[ -n "$CACHE_ENTRY" ]] && cache_set "$URL_KEY" "$CACHE_ENTRY"
        fi
    fi

    if [[ -z "$ANALYSIS_JSON" ]]; then
        error "No analysis data available for $TARGET_URL"
        return 1
    fi

    # ── Print results ──────────────────────────────────────────
    local STATUS MALICIOUS SUSPICIOUS HARMLESS UNDETECTED TIMEOUT UNSUPPORTED TOTAL VERDICT
    print_engine_table "$ANALYSIS_JSON"
    parse_stats "$ANALYSIS_JSON"
    print_stats_summary "$STATUS" "$MALICIOUS" "$SUSPICIOUS" "$HARMLESS" "$UNDETECTED" "$TIMEOUT" "$UNSUPPORTED" "$TOTAL"
    determine_verdict "$MALICIOUS" "$SUSPICIOUS" "$STATUS"

    # ── URL-specific enrichment ────────────────────────────────
    section "URL Details"
    echo "$ANALYSIS_JSON" | jq -r '
        .[0] |
        "  Final URL    : \(.url // .meta.url // "N/A")",
        "  HTTP Status  : \(.http_response_code // .meta.http_response_code // "N/A")",
        "  Title        : \(.html_meta.title[0] // "N/A")",
        "  Redirects to : \(.redirection_chain[-1] // "none")"
    ' 2>/dev/null | while IFS= read -r line; do
        echo -e "  $line"
    done

    # ── Intel enrichment for URL ───────────────────────────────
    if [[ "$SHOW_INTEL" == "true" ]]; then
        section "VT Intelligence Enrichment (Premium)"
        info "Fetching threat intelligence data..."
        local INTEL_JSON
        INTEL_JSON=$(vt url "$TARGET_URL" --include threat_severity,categories --format json 2>/dev/null || true)
        print_intel "$INTEL_JSON"

        # Show URL categories if available
        local CATEGORIES
        CATEGORIES=$(echo "$INTEL_JSON" | jq -r '
            (if type=="array" then .[0] else . end)
            | .categories // .attributes.categories // {}
            | to_entries[]
            | "  \(.key): \(.value)"
        ' 2>/dev/null || true)
        if [[ -n "$CATEGORIES" ]]; then
            echo ""
            echo -e "${BOLD}  URL Categories:${RESET}"
            echo "$CATEGORIES"
        fi
    fi

    BATCH_VERDICT["$URL_KEY"]="$VERDICT"
    BATCH_MALICIOUS["$URL_KEY"]="$MALICIOUS"
    BATCH_NAME["$URL_KEY"]="$TARGET_URL"

    if [[ "$THRESHOLD" -ge 0 ]] 2>/dev/null; then
        [[ "$MALICIOUS" -ge "$THRESHOLD" ]] 2>/dev/null && BATCH_EXIT_CODE=2
    fi

    [[ -n "$OUTPUT_FILE" ]] && { echo "$ANALYSIS_JSON" | jq '.' > "$OUTPUT_FILE" 2>/dev/null || true; success "JSON saved to: $OUTPUT_FILE"; }
    [[ -n "$HTML_FILE" ]]   && { generate_html "$TARGET_URL" "$URL_KEY" "$ANALYSIS_JSON" "$STATUS" "$MALICIOUS" "$SUSPICIOUS" "$HARMLESS" "$UNDETECTED" "$TOTAL" "$VERDICT" > "$HTML_FILE"; success "HTML report saved to: $HTML_FILE"; }
    [[ -n "$NOTIFY_URL" ]]  && send_notification "$TARGET_URL" "$URL_KEY" "$VERDICT" "$MALICIOUS" "$TOTAL"

    # VT URL report link uses base64url of the URL itself
    local VT_URL_ID
    VT_URL_ID=$(echo -n "$TARGET_URL" | base64 | tr '+/' '-_' | tr -d '=')
    write_log "$TARGET_URL" "$VT_URL_ID" "$VERDICT" "$MALICIOUS" "$SUSPICIOUS" "$TOTAL" "url"

    echo ""
    echo -e "  ${CYAN}Full report: https://www.virustotal.com/gui/url/${VT_URL_ID}${RESET}"
    echo ""
}

# ================================================================
#  SHARED DISPLAY HELPERS
# ================================================================

# Prints the colour-coded engine results table
print_engine_table() {
    local JSON="$1"
    section "Engine Results"
    local ENGINE_DATA
    ENGINE_DATA=$(echo "$JSON" | jq -r '
        .[0].results // {}
        | to_entries
        | sort_by(.value.category)
        | .[]
        | [.key, (.value.category // "unknown"), (.value.result // "-")]
        | @tsv
    ' 2>/dev/null || true)

    if [[ -n "$ENGINE_DATA" ]]; then
        printf "  ${BOLD}%-32s %-15s %s${RESET}\n" "Engine" "Category" "Result"
        printf "  %-32s %-15s %s\n" "------" "--------" "------"
        while IFS=$'\t' read -r engine category result; do
            case "$category" in
                malicious)   printf "  ${RED}%-32s %-15s %s${RESET}\n"    "$engine" "$category" "$result" ;;
                suspicious)  printf "  ${YELLOW}%-32s %-15s %s${RESET}\n" "$engine" "$category" "$result" ;;
                harmless)    printf "  ${GREEN}%-32s %-15s %s${RESET}\n"  "$engine" "$category" "$result" ;;
                undetected)  printf "  ${DIM}%-32s %-15s %s${RESET}\n"   "$engine" "$category" "$result" ;;
                *)           printf "  %-32s %-15s %s\n"                 "$engine" "$category" "$result" ;;
            esac
        done <<< "$ENGINE_DATA"
    else
        warn "No engine results available yet."
    fi
}

# Parses stats from ANALYSIS_JSON into caller-scoped variables
parse_stats() {
    local JSON="$1"
    STATUS=$(     echo "$JSON" | jq -r '.[0].status                    // "N/A"' 2>/dev/null || echo "N/A")
    MALICIOUS=$(  echo "$JSON" | jq -r '.[0].stats.malicious           // 0'    2>/dev/null || echo "0")
    SUSPICIOUS=$( echo "$JSON" | jq -r '.[0].stats.suspicious          // 0'    2>/dev/null || echo "0")
    HARMLESS=$(   echo "$JSON" | jq -r '.[0].stats.harmless            // 0'    2>/dev/null || echo "0")
    UNDETECTED=$( echo "$JSON" | jq -r '.[0].stats.undetected          // 0'    2>/dev/null || echo "0")
    TIMEOUT=$(    echo "$JSON" | jq -r '.[0].stats.timeout             // 0'    2>/dev/null || echo "0")
    UNSUPPORTED=$(echo "$JSON" | jq -r '.[0].stats["type-unsupported"] // 0'    2>/dev/null || echo "0")
    TOTAL=$(      echo "$JSON" | jq -r '.[0].stats | to_entries | map(.value) | add // 0' 2>/dev/null || echo "0")
}

# Prints the stats table
print_stats_summary() {
    section "Analysis Summary"
    printf "  %-20s %s\n"  "Status:"           "$1"
    printf "  %-20s %s\n"  "Total engines:"    "$8"
    printf "  ${RED}%-20s %s${RESET}\n"    "Malicious:"        "$2"
    printf "  ${YELLOW}%-20s %s${RESET}\n" "Suspicious:"       "$3"
    printf "  ${GREEN}%-20s %s${RESET}\n"  "Harmless:"         "$4"
    printf "  ${DIM}%-20s %s${RESET}\n"   "Undetected:"       "$5"
    printf "  %-20s %s\n"  "Timeout:"          "$6"
    printf "  %-20s %s\n"  "Type-unsupported:" "$7"
}

# Sets VERDICT and prints the verdict banner
determine_verdict() {
    local MAL="$1" SUSP="$2" STAT="$3"
    echo ""
    VERDICT="PENDING"
    if [[ "$MAL" -gt 0 ]] 2>/dev/null; then
        echo -e "  ${RED}${BOLD}⚠  VERDICT: MALICIOUS — ${MAL}/${TOTAL} engine(s) flagged this target!${RESET}"
        VERDICT="MALICIOUS"
    elif [[ "$SUSP" -gt 0 ]] 2>/dev/null; then
        echo -e "  ${YELLOW}${BOLD}⚠  VERDICT: SUSPICIOUS — ${SUSP}/${TOTAL} engine(s) flagged this target.${RESET}"
        VERDICT="SUSPICIOUS"
    elif [[ "$STAT" == "completed" ]]; then
        echo -e "  ${GREEN}${BOLD}✔  VERDICT: CLEAN — No malicious or suspicious detections.${RESET}"
        VERDICT="CLEAN"
    else
        echo -e "  ${YELLOW}${BOLD}⏳  VERDICT: PENDING — Scan not yet complete (run with --wait).${RESET}"
    fi
}

# Prints behaviour summary from fetched JSON
print_behaviour() {
    local BEH_JSON="$1"
    if [[ -n "$BEH_JSON" ]]; then
        local DOMAINS IPS URLS_OUT FILES_DROPPED PERMS
        DOMAINS=$(      echo "$BEH_JSON" | jq -r '(if type=="array" then .[0] else . end) | .behaviour_summary.dns_lookups          // .attributes.behaviour_summary.dns_lookups          // [] | .[:10][] | "  • \(.)"'                           2>/dev/null || true)
        IPS=$(          echo "$BEH_JSON" | jq -r '(if type=="array" then .[0] else . end) | .behaviour_summary.ip_traffic           // .attributes.behaviour_summary.ip_traffic           // [] | .[:10][] | "  • \(.destination_ip // .):\(.destination_port // "")"' 2>/dev/null || true)
        URLS_OUT=$(     echo "$BEH_JSON" | jq -r '(if type=="array" then .[0] else . end) | .behaviour_summary.http_conversations   // .attributes.behaviour_summary.http_conversations   // [] | .[:5][]  | "  • \(.url // .)"'                  2>/dev/null || true)
        FILES_DROPPED=$(echo "$BEH_JSON" | jq -r '(if type=="array" then .[0] else . end) | .behaviour_summary.files_written        // .attributes.behaviour_summary.files_written        // [] | .[:10][] | "  • \(.)"'                           2>/dev/null || true)
        PERMS=$(        echo "$BEH_JSON" | jq -r '(if type=="array" then .[0] else . end) | .behaviour_summary.permissions_requested // .attributes.behaviour_summary.permissions_requested // [] | .[] | "  • \(.)"'                             2>/dev/null || true)

        [[ -n "$DOMAINS"       ]] && { echo -e "${BOLD}  DNS Lookups:${RESET}";           echo "$DOMAINS";       echo ""; }
        [[ -n "$IPS"           ]] && { echo -e "${BOLD}  IP Traffic:${RESET}";            echo "$IPS";           echo ""; }
        [[ -n "$URLS_OUT"      ]] && { echo -e "${BOLD}  HTTP Conversations:${RESET}";    echo "$URLS_OUT";      echo ""; }
        [[ -n "$FILES_DROPPED" ]] && { echo -e "${BOLD}  Files Written/Dropped:${RESET}"; echo "$FILES_DROPPED"; echo ""; }
        [[ -n "$PERMS"         ]] && { echo -e "${BOLD}  Permissions Requested:${RESET}"; echo "$PERMS";         echo ""; }

        if [[ -z "${DOMAINS}${IPS}${URLS_OUT}${FILES_DROPPED}${PERMS}" ]]; then
            warn "No behaviour data available (sandbox may not have run yet)."
        fi
    else
        warn "No behaviour data returned."
    fi
}

# Prints YARA matches
print_yara() {
    local YARA_JSON="$1"
    if [[ -n "$YARA_JSON" ]]; then
        local YARA_HITS
        YARA_HITS=$(echo "$YARA_JSON" | jq -r '
            (if type=="array" then .[0] else . end)
            | .crowdsourced_yara_results // .attributes.crowdsourced_yara_results // []
            | .[]
            | "  \(.rule_name // "unknown")  |  author: \(.author // "unknown")  |  source: \(.source // "unknown")"
        ' 2>/dev/null || true)
        if [[ -n "$YARA_HITS" ]]; then
            echo -e "${BOLD}  Matched Rules:${RESET}"
            while IFS= read -r line; do echo -e "  ${MAGENTA}${line}${RESET}"; done <<< "$YARA_HITS"
        else
            success "No YARA rules matched."
        fi
    else
        warn "No YARA data returned."
    fi
}

# Prints VT Intelligence enrichment
print_intel() {
    local INTEL_JSON="$1"
    if [[ -n "$INTEL_JSON" ]]; then
        local SEVERITY
        SEVERITY=$(echo "$INTEL_JSON" | jq -r '
            (if type=="array" then .[0] else . end)
            | .threat_severity.level_description // .attributes.threat_severity.level_description // "N/A"
        ' 2>/dev/null || echo "N/A")
        echo -e "  ${BOLD}Threat Severity:${RESET} $SEVERITY"

        local SIGMA_HITS
        SIGMA_HITS=$(echo "$INTEL_JSON" | jq -r '
            (if type=="array" then .[0] else . end)
            | .sigma_analysis_results // .attributes.sigma_analysis_results // []
            | .[:5][] | "  \(.rule_title // "unknown") [\(.rule_level // "?")]"
        ' 2>/dev/null || true)
        [[ -n "$SIGMA_HITS" ]] && { echo ""; echo -e "${BOLD}  Sigma Rules:${RESET}"; echo "$SIGMA_HITS"; }

        local IDS_HITS
        IDS_HITS=$(echo "$INTEL_JSON" | jq -r '
            (if type=="array" then .[0] else . end)
            | .crowdsourced_ids_results // .attributes.crowdsourced_ids_results // []
            | .[:5][] | "  \(.rule_msg // "unknown") [severity: \(.alert_severity // "?")]"
        ' 2>/dev/null || true)
        [[ -n "$IDS_HITS" ]] && { echo ""; echo -e "${BOLD}  IDS/IPS Rules:${RESET}"; echo "$IDS_HITS"; }

        if [[ "$SEVERITY" == "N/A" && -z "${SIGMA_HITS:-}" && -z "${IDS_HITS:-}" ]]; then
            warn "No intelligence data — may require a premium VT API key."
        fi
    else
        warn "No intelligence data returned — may require a premium VT API key."
    fi
}

# ================================================================
#  FUNCTION: generate_html
# ================================================================
generate_html() {
    local TARGET="$1" KEY="$2" JSON="$3"
    local STATUS="$4" MALICIOUS="$5" SUSPICIOUS="$6" HARMLESS="$7" UNDETECTED="$8" TOTAL="$9" VERDICT="${10}"

    local VERDICT_COLOR="#2ecc71"
    local VERDICT_ICON="✔"
    [[ "$VERDICT" == "MALICIOUS" ]]  && { VERDICT_COLOR="#c0392b"; VERDICT_ICON="⚠"; }
    [[ "$VERDICT" == "SUSPICIOUS" ]] && { VERDICT_COLOR="#e67e22"; VERDICT_ICON="⚠"; }
    [[ "$VERDICT" == "PENDING" ]]    && { VERDICT_COLOR="#7f8c8d"; VERDICT_ICON="⏳"; }

    local ENGINE_ROWS
    ENGINE_ROWS=$(echo "$JSON" | jq -r '
        .[0].results // {}
        | to_entries | sort_by(.value.category) | .[]
        | "<tr class=\"cat-\(.value.category // "unknown")\"><td>\(.key)</td><td>\(.value.category // "-")</td><td>\(.value.result // "-")</td></tr>"
    ' 2>/dev/null || echo "<tr><td colspan=\"3\">No engine results available</td></tr>")

    # Determine if this is a URL or file report
    local TARGET_LABEL VT_LINK
    if is_url "$TARGET"; then
        TARGET_LABEL="URL"
        VT_LINK="https://www.virustotal.com/gui/url/$KEY"
    else
        TARGET_LABEL="File"
        VT_LINK="https://www.virustotal.com/gui/file/$KEY"
    fi

    cat <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VT Report — $TARGET</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0f1117;color:#e0e0e0;margin:0;padding:24px}
  h1{color:#fff;border-bottom:2px solid #2d2d2d;padding-bottom:10px;margin-bottom:20px}
  h2{color:#aaa;font-size:.85rem;text-transform:uppercase;letter-spacing:1px;margin:28px 0 10px}
  .meta{background:#1a1d26;border-radius:8px;padding:16px;margin-bottom:20px;font-family:monospace;font-size:.85rem;line-height:1.8}
  .meta span{color:#7ecfff}
  .verdict{font-size:1.4rem;font-weight:700;color:${VERDICT_COLOR};padding:14px 20px;background:#1a1d26;border-left:6px solid ${VERDICT_COLOR};border-radius:4px;margin:20px 0}
  .stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
  .stat{background:#1a1d26;border-radius:8px;padding:14px 20px;text-align:center;min-width:90px}
  .stat .num{font-size:2rem;font-weight:700}
  .stat .lbl{font-size:.7rem;color:#888;text-transform:uppercase;margin-top:4px}
  .mal .num{color:#e74c3c} .susp .num{color:#e67e22} .harm .num{color:#2ecc71} .undet .num{color:#95a5a6}
  table{width:100%;border-collapse:collapse;font-size:.83rem}
  th{background:#1e2130;color:#888;text-align:left;padding:9px 12px;position:sticky;top:0}
  td{padding:7px 12px;border-bottom:1px solid #1e2130}
  .cat-malicious  td:nth-child(2){color:#e74c3c;font-weight:700}
  .cat-suspicious td:nth-child(2){color:#e67e22}
  .cat-harmless   td:nth-child(2){color:#2ecc71}
  .cat-undetected td:nth-child(2){color:#555}
  tr:hover{background:#1a1d26}
  a{color:#7ecfff}
  footer{margin-top:40px;font-size:.75rem;color:#555;border-top:1px solid #1e2130;padding-top:12px}
</style>
</head>
<body>
<h1>VirusTotal Analysis Report</h1>
<div class="meta">
  <div><span>${TARGET_LABEL}:</span>    $TARGET</div>
  <div><span>Identifier:</span> $KEY</div>
  <div><span>Status:</span>     $STATUS</div>
  <div><span>Generated:</span>  $(date)</div>
</div>
<div class="verdict">${VERDICT_ICON}&nbsp; $VERDICT</div>
<div class="stats">
  <div class="stat mal">  <div class="num">$MALICIOUS</div>  <div class="lbl">Malicious</div></div>
  <div class="stat susp"> <div class="num">$SUSPICIOUS</div> <div class="lbl">Suspicious</div></div>
  <div class="stat harm"> <div class="num">$HARMLESS</div>   <div class="lbl">Harmless</div></div>
  <div class="stat undet"><div class="num">$UNDETECTED</div> <div class="lbl">Undetected</div></div>
  <div class="stat">      <div class="num">$TOTAL</div>      <div class="lbl">Total</div></div>
</div>
<h2>Engine Results</h2>
<table>
  <tr><th>Engine</th><th>Category</th><th>Result</th></tr>
  $ENGINE_ROWS
</table>
<footer>
  <a href="$VT_LINK" target="_blank">View full report on VirusTotal ↗</a>
  &nbsp;·&nbsp; Generated by vt_analysis.sh
</footer>
</body>
</html>
HTML
}

# ================================================================
#  FUNCTION: send_notification
# ================================================================
send_notification() {
    local TARGET="$1" KEY="$2" VERDICT="$3" MALICIOUS="$4" TOTAL="$5"

    if ! command -v curl &>/dev/null; then
        warn "curl not found — cannot send webhook notification."
        return 0
    fi

    local EMOJI="✅"
    [[ "$VERDICT" == "MALICIOUS" ]]  && EMOJI="🚨"
    [[ "$VERDICT" == "SUSPICIOUS" ]] && EMOJI="⚠️"
    [[ "$VERDICT" == "PENDING" ]]    && EMOJI="⏳"

    local VT_LINK
    if is_url "$TARGET"; then
        VT_LINK="https://www.virustotal.com/gui/url/$KEY"
    else
        VT_LINK="https://www.virustotal.com/gui/file/$KEY"
    fi

    local PAYLOAD
    PAYLOAD=$(jq -n \
        --arg text  "${EMOJI} *VirusTotal Scan Complete*" \
        --arg tgt   "$TARGET" \
        --arg verd  "$VERDICT" \
        --arg mal   "$MALICIOUS" \
        --arg tot   "$TOTAL" \
        --arg key   "$KEY" \
        --arg url   "$VT_LINK" \
        '{text:$text,attachments:[{color:(if $verd=="MALICIOUS" then "danger" elif $verd=="SUSPICIOUS" then "warning" else "good" end),fields:[{title:"Target",value:$tgt,short:false},{title:"Verdict",value:$verd,short:true},{title:"Detections",value:"\($mal)/\($tot)",short:true},{title:"Identifier",value:$key,short:false},{title:"Report",value:$url,short:false}]}]}' \
        2>/dev/null || true)

    if [[ -z "$PAYLOAD" ]]; then
        warn "Could not build webhook payload."
        return 0
    fi

    local HTTP_CODE
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "$PAYLOAD" "$NOTIFY_URL" 2>/dev/null || echo "000")

    if [[ "${HTTP_CODE:0:1}" == "2" ]]; then
        success "Webhook notification sent (HTTP $HTTP_CODE)."
    else
        warn "Webhook notification failed (HTTP $HTTP_CODE)."
    fi
}

# ================================================================
#  MAIN
# ================================================================

# Scan all URLs first, then all files
for TARGET_URL in "${URLS[@]+"${URLS[@]}"}"; do
    scan_single_url "$TARGET_URL" || warn "Scan failed for URL: $TARGET_URL"
done

for TARGET_FILE in "${EXPANDED_FILES[@]+"${EXPANDED_FILES[@]}"}"; do
    scan_single_file "$TARGET_FILE" || warn "Scan failed for file: $TARGET_FILE"
done

# ── Batch summary ─────────────────────────────────────────────
if [[ "$BATCH_MODE" == "true" ]]; then
    echo ""
    echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  Batch Scan Summary${RESET}"
    echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
    printf "\n  ${BOLD}%-45s %-14s %s${RESET}\n" "Target" "Verdict" "Detections"
    printf "  %-45s %-14s %s\n" "------" "-------" "----------"

    for key in "${!BATCH_VERDICT[@]}"; do
        local_verdict="${BATCH_VERDICT[$key]:-UNKNOWN}"
        local_mal="${BATCH_MALICIOUS[$key]:-0}"
        local_name="${BATCH_NAME[$key]:-unknown}"
        # Truncate long URLs/filenames for display
        if [[ ${#local_name} -gt 44 ]]; then
            local_name="${local_name:0:41}..."
        fi
        case "$local_verdict" in
            MALICIOUS)  printf "  ${RED}%-45s %-14s %s${RESET}\n"    "$local_name" "$local_verdict" "$local_mal" ;;
            SUSPICIOUS) printf "  ${YELLOW}%-45s %-14s %s${RESET}\n" "$local_name" "$local_verdict" "$local_mal" ;;
            CLEAN)      printf "  ${GREEN}%-45s %-14s %s${RESET}\n"  "$local_name" "$local_verdict" "$local_mal" ;;
            *)          printf "  %-45s %-14s %s\n"                  "$local_name" "$local_verdict" "$local_mal" ;;
        esac
    done
    echo ""
fi

exit "$BATCH_EXIT_CODE"
