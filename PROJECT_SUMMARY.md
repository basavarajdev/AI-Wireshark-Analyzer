# Project Summary — AI-Wireshark Analyzer

Comprehensive Python platform for analyzing Wireshark/tshark packet captures.  
Combines rule-based protocol analysis, machine learning, and a desktop GUI (PyQt6).

**Current Version: 1.7.1** (July 14, 2026)

---

## Current Packaging Status

| Platform | Status |
|----------|--------|
| Linux x86_64 | Built and validated \u2713 (v1.7.1) |
| Windows x64 | Build on native Windows host |
| macOS | Build on native macOS host |

---

## v1.7.x Summary of Changes

| Release | Key Changes |
|---------|-------------|
| v1.7.0 | HTTP/HTTPS analyzers consolidated into TCP with port-based detection; TCP/UDP report fully dynamic |
| v1.7.1 | Dynamic RCA for 25+ threat types; smart threat ordering (connection before RF stats); WPA3 SAE advisory suppression; per-BSSID/channel retry breakdown; TShark crash resilience across all analyzers |

---

## Analysis Capabilities

### WLAN / Wi-Fi Analysis
- 802.11 connection failure detection (40+ IEEE reason/status codes)
- WPA2/WPA3/SAE authentication issues — wrong-password loops, anti-clogging, EC group mismatch
- Beacon loss, probe failures, weak signal detection
- High retry rate and power-save scan pattern analysis
- Connection delay: probe-response → auth timing
- Scan cycle detection (>3 s gaps between probe bursts)
- Unprotected (non-encrypted) data frame detection
- **NEW (v1.6.2) Connection Lifecycle Analysis:**
  - Association attempts tracking with status/reason code mapping (65+ codes)
  - Authentication timing: probe-to-auth → auth-to-assoc delays
  - WPA3-SAE diagnostics: commit/confirm rounds, anti-clogging token detection
  - Deauthentication/disassociation tracking with connection duration
  - Failure diagnosis and per-code remediation advice
- **NEW (v1.6.2) Protocol Detection:**
  - DPP (Wi-Fi Easy Connect) provisioning frames (45-80 frames per exchange)
  - WPS configuration method detection (PBC, PIN, NFC)
  - Wi-Fi Direct / P2P group formation with participant tracking
  - Printer scan cycle analysis with interval calculation
- **NEW (v1.6.2) DHCP Analysis (Framework):**
  - IP address assignment tracking
  - DHCP server identification
  - Handshake timing and failure detection
- **NEW (v1.6.2) Data Transfer Quality:**
  - TCP/UDP throughput estimation (Mbps per session)
  - Link quality assessment (Good/Fair/Poor) based on retry rate + signal strength
  - Signal strength monitoring: average RSSI, min RSSI, SNR margin
  - Data rate distribution and rate downgrade indicators
  - TX/RX frame counts and frame rate analysis

### RF Channel Monitor
- Channel utilization % and throughput (Mbps per window)
- RTS/CTS overhead % — frame-count-based; ≥30% = High, ≥20% = Medium (hidden-node indicator)
- CTS reply rate — fraction of RTS frames that received a CTS reply
- Maximum NAV duration & abuse detection (>32 ms threshold)
- Per-BSSID and per-client frame counts
- **Client activity breakdown** (OUI-assigned MACs only):
  - Actively connected: >50 frames
  - Medium activity: 6–50 frames
  - Low activity / probe-only: ≤5 frames
- Accurate connected-client count — filters randomised/locally-administered MACs
- Station spotlight: TX/RX throughput, retry vs. channel average, roaming events, PHY modes

### WPA/WPA2/WPA3 Decryption
- Decrypt encrypted 802.11 captures using `wpa-pwd` (SSID + password) or `wpa-psk` (PMK)
- Supports WPA2 (4-way EAPOL) and WPA3-SAE (Commit/Confirm + EAPOL)
- Post-decryption inner analysis: DNS queries, HTTP requests, IP endpoints, port summary
- Handshake validation and security observations

### TCP/UDP Application Traffic
- Zero-window / buffer exhaustion events with timeline chart
- Retransmissions, duplicate ACKs, lost segments, RST catalogues
- UDP flood and amplification detection
- QUIC detection and broadcast/multicast UDP analysis
- Root-cause diagnosis and prioritised remediation

### IPv6 Analysis
- Per-address: TCP connections, UDP flows, ICMPv6/NDP patterns
- SNMP community analysis with polling interval estimation
- Router Solicitation/Neighbor Discovery breakdown
- **NEW (v1.6.1) Statistical Analysis:**
  - **IPI Statistics:** Mean, median, std dev, jitter, coefficient of variation, burstiness classification
  - **Packet Size Distribution:** Min/max/mean/median/std/P95/P99, bucket breakdown with percentages
  - **Hourly Traffic Metrics:** Min/max/avg packets/hour, active hours, peak hour offset
  - **TX/RX Ratios:** Packet % and byte % ratios
  - **SNMP Polling Analysis:** Interval estimation, regularity scoring, requests/hour, error rates
  - **Protocol & Peer Share:** Percentage distributions for all traffic sources

### Protocol Analysis
- TCP/UDP/DNS/ICMP/DHCP dedicated analyzers (HTTP/HTTPS covered via TCP port filter)
- **v1.7.1 Dynamic Report Engine:** `_build_threat_rca_html()` generates capture-specific root cause analysis for 25+ threat types:
  - **TCP:** SYN flood (top targets + rate), RST storm (affected ports + sources), port scanning (scanner IPs), retransmissions (affected path), zero-window (slow consumer IPs), connection resets, data transmission gaps
  - **UDP:** UDP flood, amplification (abused services + victim IPs), fragmentation
  - **DNS:** Tunneling (sample high-entropy domains), DGA domains, NXDOMAIN excess, amplification
  - **ICMP:** Flood, Ping of Death (source IPs + max size), Smurf (victim IP), tunneling (endpoints), network scanning
  - **DHCP:** Starvation (unique MACs), rogue DHCP server (server IPs), rapid requests
  - **HTTP/HTTPS:** SQL injection, XSS, directory traversal (attacker IPs + sample URIs), suspicious user agents, HTTP flood
- Severity-rated issues with IEEE specification references and frame-level evidence

### WPA3-SAE Root Cause Analysis (v1.6.1)
- **24 IEEE 802.11-2020 Error Codes:** 12 SAE status codes (1, 15, 30, 37, 46, 53, 72-78) with explanations
- **12 Reason Codes:** 2, 3, 6, 7, 14, 15, 22, 23, 36, 45, 47, 50 with forensic interpretation
- **Stale Association Deadlock Detection:** Status 30 rejection + PMF SA Query with stale PTK (CCMP PN > 1)
- **Forensic Timeline:** Frame-level event sequencing with signal strength and timing analysis
- **CCMP PN Evidence:** Proof of PTK reuse and cross-mode confusion in Transition Mode networks
- **Automatic Report Generation:** Purple-themed standalone HTML when WPA3 failure detected
- **Remediation Guidance:** Per-code recommendations, AP/STA handshake recovery steps

### ML Anomaly Detection
- Isolation Forest and Autoencoder models
- Unsupervised threat detection on captured traffic

---

## Report System

All analyses produce self-contained HTML reports (no external CSS/JS):
- Executive summary with overall severity (Critical/High/Medium/Low)
- **Smart threat ordering (v1.7.1):** Connection failures always before RF statistics within same severity tier
- **Dynamic Root Cause Analysis (v1.7.1):** Capture-specific IPs, rates, and targeted remediation
- Colour-coded issue list with evidence and remediation steps
- Embedded charts (retry trends, signal history, throughput windows)
- Companion JSON output for programmatic use

---

## Project Structure

```
app/                    Desktop GUI (PyQt6)
  panels/               Analysis panels (Home, WLAN, WPA Decrypt, Channel & Network Map, TCP/UDP, IPv6, Protocol, Anomaly, CLI & Workflow)
  widgets/              Reusable UI components

src/                    Core analysis library
  protocols/            Protocol analyzers (tcp, udp, dns, http, icmp, dhcp, wlan, wlan_rf_monitor, wlan_decryptor)
  parsers/              PCAP/PCAPNG parsing (PyShark)
  core/                 ML models (Isolation Forest, Autoencoder, Random Forest)
  reports/              HTML report engine
  api/                  REST API (FastAPI) and CLI (Click)

scripts/                Standalone analysis runners
  run_wlan_analysis.py
  run_channel_monitor.py
  build_client_map_report.py
  build_combined_report.py
  analyze_tcp_udp.py
  run_ipv6_analysis.py

config/                 default.yaml, dev.yaml (thresholds, model params)
installer/              PyInstaller spec, build scripts, Inno Setup config
results/                Generated JSON + HTML reports
docs/                   architecture.md, api.md
```

---

## Threat Detection Summary

| Layer | Threats Detected |
|-------|-----------------|
| WLAN | Auth failures, handshake stalls, beacon loss, high retry, weak signal, unencrypted data |
| WPA | Wrong passphrase, PMK mismatch, SAE failures, anti-clogging token abuse |
| TCP | SYN floods, retransmission storms, RST attacks, zero-window stalls |
| UDP | Floods, DNS/NTP amplification, fragmentation abuse |
| DNS | Tunneling, cache poisoning, excessive NXDOMAIN |
| IPv6 | RA spoofing, NDP exhaustion, SNMP exposure |

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| GUI | PyQt6 6.11 |
| Packet parsing | tshark (subprocess), PyShark |
| Data processing | pandas, numpy |
| ML models | scikit-learn, (optional deep learning) |
| Reports | Custom HTML generator (zero external deps) |
| Build | PyInstaller 6.x |
