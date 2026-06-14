# Project Summary — AI-Wireshark Analyzer

Comprehensive Python platform for analyzing Wireshark/tshark packet captures.  
Combines rule-based protocol analysis, machine learning, and a desktop GUI (PyQt6).

---

## Current Packaging Status

| Platform | Status |
|----------|--------|
| Linux x86_64 | Built and validated from current source |
| Windows x64 | Build on native Windows host |
| macOS | Build on native macOS host |

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
- SNMP community analysis
- Router Solicitation/Neighbor Discovery breakdown

### Protocol Analysis
- Dedicated TCP, UDP, HTTP, DNS, ICMP analyzers
- Severity-rated issues with evidence and remediation

### ML Anomaly Detection
- Isolation Forest and Autoencoder models
- Unsupervised threat detection on captured traffic

---

## Report System

All analyses produce self-contained HTML reports (no external CSS/JS):
- Executive summary with overall severity (Critical/High/Medium/Low)
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
