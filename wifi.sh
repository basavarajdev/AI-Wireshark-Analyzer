#!/usr/bin/env bash
# =======================================================================
# wifi.sh  –  Simple WiFi analysis toolkit
#
# USAGE:
#   ./wifi.sh status                         Show interface & channel info
#   ./wifi.sh capture [channel] [seconds]    Capture packets in monitor mode
#   ./wifi.sh analyze <pcap> [mac]           Analyze a pcap file
#   ./wifi.sh monitor on  [channel]          Switch interface to monitor mode
#   ./wifi.sh monitor off                    Restore interface to managed mode
#   ./wifi.sh channels                       List common WiFi channels
#   ./wifi.sh help                           Show this help message
#
# EXAMPLES:
#   ./wifi.sh status
#   ./wifi.sh capture                        # channel 11, run until Ctrl+C
#   ./wifi.sh capture 6                      # capture on channel 6
#   ./wifi.sh capture 48 60                  # channel 48 for 60 seconds
#   ./wifi.sh analyze data/raw/capture.pcap
#   ./wifi.sh analyze data/raw/capture.pcap "AA:BB:CC:DD:EE:FF"
#   ./wifi.sh monitor on 11
#   ./wifi.sh monitor off
# =======================================================================

set -e

# ---- Configuration ---------------------------------------------------
IFACE="${WIFI_IFACE:-wlx503eaaac7bc7}"
DEFAULT_CHANNEL=11
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---- Colour codes ----------------------------------------------------
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()     { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}$*${NC}"; }
divider() { echo -e "${CYAN}─────────────────────────────────────────────${NC}"; }

# ======================================================================
# STATUS — show interface information
# ======================================================================
cmd_status() {
    header "WiFi Interface Status"
    divider

    if ! command -v iw &>/dev/null; then
        err "'iw' not found. Install with: sudo apt install iw"
    fi

    IW_INFO=$(iw dev "$IFACE" info 2>/dev/null) || err "Interface '$IFACE' not found."

    TYPE=$(echo "$IW_INFO"    | awk '/type/{print $2}')
    CHANNEL=$(echo "$IW_INFO" | awk '/channel/{print $2}')
    TXPOW=$(echo "$IW_INFO"   | awk '/txpower/{print $2, $3}')
    ADDR=$(echo "$IW_INFO"    | awk '/addr/{print $2}')

    printf "  %-16s %s\n" "Interface:"   "$IFACE"
    printf "  %-16s %s\n" "MAC address:" "${ADDR:-unknown}"
    printf "  %-16s %s\n" "Mode:"        "${TYPE:-unknown}"
    printf "  %-16s %s\n" "Channel:"     "${CHANNEL:-unknown}"
    printf "  %-16s %s\n" "TX Power:"    "${TXPOW:-unknown}"

    divider
    # Show link quality if in managed mode
    if [[ "$TYPE" == "managed" ]]; then
        SSID=$(iw dev "$IFACE" link 2>/dev/null | awk '/SSID/{print $2}')
        SIGNAL=$(iw dev "$IFACE" link 2>/dev/null | awk '/signal/{print $2, $3}')
        [[ -n "$SSID" ]] && printf "  %-16s %s\n" "Connected SSID:" "$SSID"
        [[ -n "$SIGNAL" ]] && printf "  %-16s %s\n" "Signal:"        "$SIGNAL"
    fi

    echo ""
    # List available pcap files
    PCAP_COUNT=$(find "$SCRIPT_DIR/data/raw" -name "*.pcap" 2>/dev/null | wc -l)
    echo -e "  Captured pcap files in ${BOLD}data/raw/${NC}: ${PCAP_COUNT}"
    if [[ "$PCAP_COUNT" -gt 0 ]]; then
        find "$SCRIPT_DIR/data/raw" -name "*.pcap" -printf "    %f  (%s bytes)\n" 2>/dev/null \
            | sort | tail -10
    fi
    echo ""
}

# ======================================================================
# CAPTURE — monitor mode capture on a given channel
# ======================================================================
cmd_capture() {
    local CHANNEL="${1:-$DEFAULT_CHANNEL}"
    local DURATION="${2:-0}"

    [[ $EUID -ne 0 ]] && err "Capture requires root. Run: sudo ./wifi.sh capture $*"

    TIMESTAMP=$(date +"%Y-%m-%d_%H.%M.%S")
    FINAL_DIR="${SCRIPT_DIR}/data/raw"
    FINAL_FILE="monitor_ch${CHANNEL}_${TIMESTAMP}.pcap"
    TMP_OUTPUT="/tmp/${FINAL_FILE}"
    FINAL_OUTPUT="${FINAL_DIR}/${FINAL_FILE}"

    header "Starting Capture — Channel $CHANNEL"
    divider

    _save_iface_state
    trap '_restore_iface "$TMP_OUTPUT" "$FINAL_OUTPUT" "$FINAL_DIR"' EXIT INT TERM

    _set_monitor_mode "$CHANNEL"

    mkdir -p "$FINAL_DIR"

    # Build tshark command
    local TSHARK_ARGS=( tshark -i "$IFACE" -w "$TMP_OUTPUT" -q )
    if [[ "$DURATION" -gt 0 ]]; then
        TSHARK_ARGS+=( -a "duration:$DURATION" )
        log "Capture duration : ${DURATION}s"
    fi

    _print_banner "$CHANNEL" "$FINAL_OUTPUT"

    "${TSHARK_ARGS[@]}" &
    local TSHARK_PID=$!
    echo "$TSHARK_PID" > /tmp/tshark_mon_pid
    log "tshark PID: $TSHARK_PID  (Ctrl+C to stop)"
    echo ""

    # Live progress counter
    while kill -0 "$TSHARK_PID" 2>/dev/null; do
        sleep 5
        if [[ -f "$TMP_OUTPUT" ]]; then
            local PKT=$(tshark -r "$TMP_OUTPUT" -T fields -e frame.number 2>/dev/null | tail -1 || echo "?")
            local SZ=$(du -sh "$TMP_OUTPUT" 2>/dev/null | cut -f1 || echo "?")
            printf "\r  [%s] Packets: %-8s  Size: %s     " "$(date +%H:%M:%S)" "$PKT" "$SZ"
        fi
    done

    wait "$TSHARK_PID" 2>/dev/null || true
}

# ======================================================================
# ANALYZE — run the Python analysis pipeline on a pcap
# ======================================================================
cmd_analyze() {
    local PCAP="$1"
    local MAC="${2:-}"

    [[ -z "$PCAP" ]] && err "Usage: ./wifi.sh analyze <pcap_file> [mac_filter]"
    [[ ! -f "$PCAP" ]] && err "File not found: $PCAP"

    header "Analyzing: $PCAP"
    divider

    # Activate venv if available
    if [[ -f "${SCRIPT_DIR}/.venv/bin/activate" ]]; then
        source "${SCRIPT_DIR}/.venv/bin/activate"
        log "Python venv activated"
    fi

    # Derive output paths from pcap filename
    local BASENAME
    BASENAME=$(basename "$PCAP" .pcap)
    local JSON_OUT="${SCRIPT_DIR}/results/${BASENAME}.json"
    local HTML_OUT="${SCRIPT_DIR}/results/${BASENAME}_report.html"

    mkdir -p "${SCRIPT_DIR}/results"

    log "Output JSON : $JSON_OUT"
    log "Output HTML : $HTML_OUT"
    [[ -n "$MAC" ]] && log "MAC filter  : $MAC"
    echo ""

    local CMD=( python "${SCRIPT_DIR}/scripts/run_wlan_analysis.py"
                "$PCAP" "$JSON_OUT" "$HTML_OUT" )
    [[ -n "$MAC" ]] && CMD+=( "$MAC" )

    "${CMD[@]}"

    echo ""
    log "Analysis complete!"
    log "Report: $HTML_OUT"
}

# ======================================================================
# MONITOR ON — switch interface to monitor mode on a channel
# ======================================================================
cmd_monitor_on() {
    local CHANNEL="${1:-$DEFAULT_CHANNEL}"
    [[ $EUID -ne 0 ]] && err "Requires root. Run: sudo ./wifi.sh monitor on $CHANNEL"

    header "Switching to Monitor Mode — Channel $CHANNEL"
    divider
    _save_iface_state
    _set_monitor_mode "$CHANNEL"
    log "Done. Interface $IFACE is now in monitor mode on channel $CHANNEL."
    log "To restore: sudo ./wifi.sh monitor off"
    echo ""
}

# ======================================================================
# MONITOR OFF — restore interface to managed mode
# ======================================================================
cmd_monitor_off() {
    [[ $EUID -ne 0 ]] && err "Requires root. Run: sudo ./wifi.sh monitor off"

    header "Restoring Managed Mode"
    divider
    ip link set "$IFACE" down
    iw dev "$IFACE" set type managed
    ip link set "$IFACE" up
    if command -v nmcli &>/dev/null; then
        nmcli dev set "$IFACE" managed yes 2>/dev/null || true
    fi
    log "Interface $IFACE restored to managed mode."
    iw dev "$IFACE" info 2>/dev/null | awk '/type|channel/{printf "  %-12s %s\n", $1":", $2}'
    echo ""
}

# ======================================================================
# CHANNELS — print common WiFi channels reference
# ======================================================================
cmd_channels() {
    header "Common WiFi Channels"
    divider
    echo ""
    echo -e "  ${BOLD}2.4 GHz (802.11b/g/n/ax)${NC}"
    printf "  %-8s %-12s %s\n" "Channel" "Frequency" "Notes"
    printf "  %-8s %-12s %s\n" "-------" "---------" "-----"
    printf "  %-8s %-12s %s\n" "1"   "2412 MHz"  "Non-overlapping"
    printf "  %-8s %-12s %s\n" "6"   "2437 MHz"  "Non-overlapping"
    printf "  %-8s %-12s %s\n" "11"  "2462 MHz"  "Non-overlapping (default in script)"
    printf "  %-8s %-12s %s\n" "2-5,7-10,12-13" "various" "Overlapping channels"
    echo ""
    echo -e "  ${BOLD}5 GHz (802.11a/n/ac/ax)${NC}"
    printf "  %-8s %-12s %s\n" "Channel" "Frequency" "Notes"
    printf "  %-8s %-12s %s\n" "-------" "---------" "-----"
    printf "  %-8s %-12s %s\n" "36"  "5180 MHz"  "UNII-1"
    printf "  %-8s %-12s %s\n" "40"  "5200 MHz"  "UNII-1"
    printf "  %-8s %-12s %s\n" "44"  "5220 MHz"  "UNII-1"
    printf "  %-8s %-12s %s\n" "48"  "5240 MHz"  "UNII-1 (used in previous analysis)"
    printf "  %-8s %-12s %s\n" "52"  "5260 MHz"  "UNII-2 (DFS)"
    printf "  %-8s %-12s %s\n" "100" "5500 MHz"  "UNII-2e (DFS)"
    printf "  %-8s %-12s %s\n" "149" "5745 MHz"  "UNII-3"
    printf "  %-8s %-12s %s\n" "153" "5765 MHz"  "UNII-3"
    printf "  %-8s %-12s %s\n" "157" "5785 MHz"  "UNII-3"
    printf "  %-8s %-12s %s\n" "161" "5805 MHz"  "UNII-3"
    echo ""
    echo -e "  ${BOLD}6 GHz (802.11ax Wi-Fi 6E)${NC}"
    printf "  %-8s %-12s %s\n" "1,5,9..." "5955+ MHz" "20 MHz channels"
    echo ""
}

# ======================================================================
# HELP
# ======================================================================
cmd_help() {
    echo ""
    echo -e "${BOLD}${CYAN}wifi.sh${NC} — WiFi analysis toolkit"
    echo ""
    echo -e "${BOLD}USAGE${NC}"
    echo "  ./wifi.sh <command> [options]"
    echo ""
    echo -e "${BOLD}COMMANDS${NC}"
    printf "  ${GREEN}%-30s${NC} %s\n" "status"                       "Show interface mode, channel, connected SSID"
    printf "  ${GREEN}%-30s${NC} %s\n" "capture [channel] [seconds]"  "Capture in monitor mode (Ctrl+C to stop)"
    printf "  ${GREEN}%-30s${NC} %s\n" "analyze <pcap> [mac]"         "Analyze a pcap file, generate JSON+HTML report"
    printf "  ${GREEN}%-30s${NC} %s\n" "monitor on  [channel]"        "Switch interface to monitor mode"
    printf "  ${GREEN}%-30s${NC} %s\n" "monitor off"                  "Restore interface to managed mode"
    printf "  ${GREEN}%-30s${NC} %s\n" "channels"                     "Show common WiFi channel reference"
    printf "  ${GREEN}%-30s${NC} %s\n" "help"                         "Show this help message"
    echo ""
    echo -e "${BOLD}EXAMPLES${NC}"
    echo "  ./wifi.sh status"
    echo "  sudo ./wifi.sh capture              # channel 11, until Ctrl+C"
    echo "  sudo ./wifi.sh capture 6            # channel 6"
    echo "  sudo ./wifi.sh capture 48 120       # channel 48, for 2 minutes"
    echo "  ./wifi.sh analyze data/raw/my.pcap"
    echo "  ./wifi.sh analyze data/raw/my.pcap \"24:6A:0E:83:41:20\""
    echo "  sudo ./wifi.sh monitor on 11        # monitor mode only (no capture)"
    echo "  sudo ./wifi.sh monitor off          # back to managed"
    echo "  ./wifi.sh channels                  # channel cheat sheet"
    echo ""
    echo -e "${BOLD}OVERRIDE INTERFACE${NC}"
    echo "  WIFI_IFACE=wlan0 ./wifi.sh status   # use a different interface"
    echo ""
}

# ======================================================================
# Internal helpers
# ======================================================================
_ORIG_TYPE=""
_ORIG_CHAN=""

_save_iface_state() {
    _ORIG_TYPE=$(iw dev "$IFACE" info 2>/dev/null | awk '/type/{print $2}')
    _ORIG_CHAN=$(iw dev "$IFACE" info 2>/dev/null | awk '/channel/{print $2}')
    log "Saved state: $IFACE mode=${_ORIG_TYPE:-unknown} channel=${_ORIG_CHAN:-unknown}"
}

_set_monitor_mode() {
    local CHANNEL="$1"

    log "Stopping processes that may block monitor mode..."
    if command -v nmcli &>/dev/null; then
        nmcli dev set "$IFACE" managed no 2>/dev/null || true
    fi
    pkill -f "wpa_supplicant.*$IFACE" 2>/dev/null || true
    sleep 0.5

    log "Bringing $IFACE down..."
    ip link set "$IFACE" down

    log "Setting monitor mode..."
    iw dev "$IFACE" set type monitor

    log "Bringing $IFACE up..."
    ip link set "$IFACE" up

    log "Setting channel $CHANNEL..."
    iw dev "$IFACE" set channel "$CHANNEL" HT20 \
        || warn "Could not set channel $CHANNEL — capturing in passive scan mode"

    local ACTUAL_TYPE
    ACTUAL_TYPE=$(iw dev "$IFACE" info | awk '/type/{print $2}')
    [[ "$ACTUAL_TYPE" != "monitor" ]] && err "Failed to enter monitor mode (got: $ACTUAL_TYPE)"

    local ACTUAL_CHAN
    ACTUAL_CHAN=$(iw dev "$IFACE" info | awk '/channel/{print $2}')
    log "Monitor mode confirmed — channel ${ACTUAL_CHAN}"
}

_restore_iface() {
    local TMP_FILE="$1"
    local FINAL_FILE="$2"
    local FINAL_DIR="$3"

    echo ""
    warn "Stopping capture and restoring $IFACE..."

    local TPID
    TPID=$(cat /tmp/tshark_mon_pid 2>/dev/null || true)
    [[ -n "$TPID" ]] && kill "$TPID" 2>/dev/null || true
    rm -f /tmp/tshark_mon_pid

    ip link set "$IFACE" down          2>/dev/null || true
    iw dev "$IFACE" set type managed   2>/dev/null || true
    ip link set "$IFACE" up            2>/dev/null || true
    if command -v nmcli &>/dev/null; then
        nmcli dev set "$IFACE" managed yes 2>/dev/null || true
    fi
    log "Interface restored to managed mode."

    if [[ -f "$TMP_FILE" && -s "$TMP_FILE" ]]; then
        mkdir -p "$FINAL_DIR"
        mv "$TMP_FILE" "$FINAL_FILE"
        [[ -n "$SUDO_USER" ]] && chown "${SUDO_USER}" "$FINAL_FILE" 2>/dev/null || true
        log "Capture saved : $FINAL_FILE"
        log "File size     : $(du -sh "$FINAL_FILE" 2>/dev/null | cut -f1)"
        echo ""
        echo -e "  ${BOLD}To analyze:${NC}"
        echo -e "  ${CYAN}./wifi.sh analyze ${FINAL_FILE}${NC}"
        echo -e "  ${CYAN}./wifi.sh analyze ${FINAL_FILE} \"AA:BB:CC:DD:EE:FF\"${NC}"
    else
        warn "No packets captured."
    fi
    echo ""
}

_print_banner() {
    local CHANNEL="$1"
    local OUTPUT="$2"
    local BAND

    if   [[ $CHANNEL -le 13 ]];  then BAND="2.4 GHz"
    elif [[ $CHANNEL -le 64 ]];  then BAND="5 GHz UNII-1/2"
    elif [[ $CHANNEL -le 144 ]]; then BAND="5 GHz UNII-2e"
    else BAND="5 GHz UNII-3"; fi

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          Capture in progress                  ║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════════╣${NC}"
    printf  "${GREEN}║${NC}  %-12s %-32s${GREEN}║${NC}\n" "Interface:" "$IFACE"
    printf  "${GREEN}║${NC}  %-12s %-32s${GREEN}║${NC}\n" "Channel:"   "$CHANNEL ($BAND)"
    printf  "${GREEN}║${NC}  %-12s %-32s${GREEN}║${NC}\n" "Output:"    "$(basename "$OUTPUT")"
    echo -e "${GREEN}╠═══════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  Press Ctrl+C to stop                         ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
}

# ======================================================================
# Main dispatcher
# ======================================================================
COMMAND="${1:-help}"
shift 2>/dev/null || true

case "$COMMAND" in
    status)                          cmd_status         "$@" ;;
    capture)                         cmd_capture        "$@" ;;
    analyze|analyse)                 cmd_analyze        "$@" ;;
    monitor)
        SUBCMD="${1:-}"; shift 2>/dev/null || true
        case "$SUBCMD" in
            on|start)   cmd_monitor_on  "$@" ;;
            off|stop)   cmd_monitor_off "$@" ;;
            *)          err "Usage: ./wifi.sh monitor on|off [channel]" ;;
        esac
        ;;
    channels|channel)                cmd_channels       "$@" ;;
    help|--help|-h)                  cmd_help           "$@" ;;
    *)  echo -e "${RED}Unknown command:${NC} $COMMAND"
        cmd_help
        exit 1
        ;;
esac
