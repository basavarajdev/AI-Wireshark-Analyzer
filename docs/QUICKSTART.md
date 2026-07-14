# Quick Start — AI-Wireshark Analyzer

All analysis types run from the GUI or directly from the command line.  
HTML reports are generated automatically and open in your browser.

---

## Platform Launch

### Linux
```bash
./dist/AI-Wireshark-Analyzer/AI-Wireshark-Analyzer
```

### Windows
```powershell
dist\AI-Wireshark-Analyzer\AI-Wireshark-Analyzer.exe
```

### macOS
```bash
./dist/AI-Wireshark-Analyzer/AI-Wireshark-Analyzer
```

If you run from source on any platform:

```bash
python -m app.main
```

---

## GUI Usage

1. Launch the application
2. Click **Browse** → select your `.pcap` or `.pcapng` file
3. Choose a panel from the left sidebar
4. Set optional filters -> click **Run Analysis**

Reports open automatically in your browser and are saved in `results/`.

Tip: Use the **CLI & Workflow** panel in the app for command reference and process flow.

---

## Analysis Commands

### WLAN / Wi-Fi Analysis
```bash
python3 scripts/run_wlan_analysis.py capture.pcapng

# Filter to a single client MAC
python3 scripts/run_wlan_analysis.py capture.pcapng aa:bb:cc:dd:ee:ff

# CLI with display filter
ai-wireshark analyze-wlan -i capture.pcapng -f "wlan.sa==aa:bb:cc:dd:ee:ff"
```
Detects: auth failures (40+ IEEE codes), WPA2/WPA3 handshake issues, beacon loss, retry rate, signal problems, connection delays, scan cycles.

---

### Channel Monitor
```bash
python3 scripts/run_channel_monitor.py --pcap capture.pcapng --channel 6

# Station spotlight (per-client deep-dive)
python3 scripts/run_channel_monitor.py --pcap capture.pcapng --station aa:bb:cc:dd:ee:ff

# Live capture
python3 scripts/run_channel_monitor.py --iface wlan0 --channel 6
```
Metrics: channel utilization, throughput, RTS/CTS overhead %, hidden-node detection, per-BSSID stats, client activity breakdown (actively connected >50 frames / medium 6-50 / low ≤5).

GUI channel selector behavior:
- All Channels: analyzes every detected channel in capture
- Specific channel selection: 2.4 GHz channels 1-14 and 5 GHz channels 36-165
- Reference list for all bands shown in panel help text:
  - 2.4 GHz: 1-14
  - 5 GHz: 36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165
  - 6 GHz: 1,5,9,...,233

---

### Client/Network Map & Combined Report
```bash
# Client map — device clusters, multi-channel SSIDs, cross-channel clients
python3 scripts/build_client_map_report.py results/survey/client_network_map.json --output-dir results/

# Combined RF + client map with channel health scores
python3 scripts/build_combined_report.py results/survey/client_network_map.json \
  --channel-jsons-dir results/survey/ --output-dir results/
```

---

### WPA/WPA2/WPA3 Decryption

**Via GUI:** Sidebar → **WPA Decrypt** → select PCAP → enter key info → Run Analysis.

**Key types:**
- `wpa-pwd` — enter SSID + password (home/office WiFi)
- `wpa-psk` — enter 64-char hex PMK directly (advanced)

**Requirement:** Capture must include the full handshake:
- WPA/WPA2: 4 EAPOL-Key messages
- WPA3-SAE: SAE Commit/Confirm + EAPOL 4-way

Report includes: DNS queries, HTTP requests, IP endpoints, port summary, handshake status, security observations.

**Troubleshooting WPA decrypt:**
- SSID is case-sensitive
- Confirm capture includes EAPOL handshake (use WLAN panel to check)
- SAE decryption requires Wireshark ≥ 3.4

---

### TCP/UDP Application Traffic
```bash
python3 scripts/analyze_tcp_udp.py capture.pcapng results/tcp_udp_report.html
```
Detects: zero-window events, retransmissions, RST storms, UDP floods, QUIC streams, broadcast/multicast floods. Ideal for diagnosing print jobs, file transfers, stalled applications.

---

### IPv6 Analysis
```bash
python3 scripts/run_ipv6_analysis.py capture.pcap 2408:8a04:e001::1
```
Covers: TCP/UDP flows, ICMPv6/NDP patterns, SNMP community analysis, per-address traffic breakdown.

**NEW (v1.6.1) Statistical Reports:**
- **Inter-Packet Interval (IPI) Statistics:** Mean, median, std dev, jitter, CV, burstiness classification (constant/regular/bursty/highly-bursty)
- **Packet Size Distribution:** Buckets (min, <128B, 128-512B, 512B+), percentiles (P50, P95, P99)
- **Hourly Traffic Analysis:** Min/max/avg packets per hour, active hours count, peak hour timing
- **TX/RX Ratios:** Both packet % and byte % ratios for traffic directionality
- **SNMP Polling Interval:** Estimated interval, median/std consistency, requests/hour, error/unanswered rates
- **Protocol & Peer Share:** Percentage breakdowns for all protocols and source IPs
- **Interactive HTML Report:** Embedded charts with Statistics card, IPI table, size distribution graph

---

### Protocol Analysis & Anomaly Detection

```bash
# Full multi-protocol analysis
ai-wireshark analyze -i traffic.pcap -p all

# Single protocol with IP filter
ai-wireshark analyze -i traffic.pcap -p tcp -f "ip.addr==192.168.1.100"

# CLI help
ai-wireshark --help
```

Anomaly detection uses Isolation Forest or Autoencoder models — select model in the GUI Anomaly panel.

---

## Build Commands (by platform)

```bash
# Linux/macOS
python3 -m PyInstaller installer/ai_wireshark.spec --noconfirm --clean
```

```cmd
:: Windows
python installer\build_installer.bat
```

---

## Filter Reference

| Panel | Filter | Example |
|-------|--------|---------|
| WLAN | MAC address | `aa:bb:cc:dd:ee:ff` |
| WPA Decrypt | Client MAC (optional) | `aa:bb:cc:dd:ee:ff` |
| IPv6 | IPv6 address | `2408:8a04:e001::1` |
| Channel Monitor | Channel / BSSID / Station MAC | `6` / `aa:bb:cc` |
| Protocol | Wireshark display filter | `tcp.port==443` |

---

## Report Output

All reports are self-contained HTML files (no external CSS/JS):
- Colour-coded severity badges (Critical / High / Medium / Low)
- **Connection failures always surface above RF statistics** in the Threat Overview (v1.7.1)
- **Dynamic Root Cause Analysis** boxes with capture-specific IPs, rates, and remediation steps (v1.7.1)
- Embedded charts and timeline visualisations
- Saved as `<name>.json` + `<name>_report.html` in `results/`

```bash
# Open reports manually
xdg-open results/my_report.html   # Linux
open results/my_report.html       # macOS
start results\my_report.html      # Windows
```

---

## Common Scenarios

| Problem | Panel to use |
|---------|-------------|
| Wi-Fi won't connect / wrong password | WLAN |
| WPA3-SAE authentication rejected | WLAN (connection_failures shows IEEE status codes + frame-level evidence) |
| Decrypt captured Wi-Fi traffic | WPA Decrypt |
| Slow / stalled print jobs or transfers | TCP/UDP |
| Channel congestion or interference | Channel Monitor |
| High Wi-Fi retry rate | WLAN (high_retry_rate with per-AP/channel breakdown) |
| IPv6 connectivity issues | IPv6 |
| DNS, HTTP, ICMP deep-dive | Protocol Analyzers |
| Detecting unusual traffic | Anomaly |
