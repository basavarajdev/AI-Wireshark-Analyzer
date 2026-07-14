# Release Notes — AI-Wireshark Analyzer

---

## v1.7.1 — July 13, 2026

### Improvements

**WLAN Report: Connection Failures Now Prioritised Over RF Statistics**

The Threat Overview table in HTML reports now orders threats by type within each severity tier:
1. Connection/authentication failures (`connection_failures`, `beacon_loss`, `wpa3_sae_failures`, `connection_delays`, `ip_connectivity_failure`) appear **first**
2. RF-statistical findings (`high_retry_rate`, `control_frame_issues`, `power_save_issues`, `scan_failures`, `weak_signal_coverage`) appear **after**

This ensures the most actionable connection-blocking issues are always visible at the top.

**Dynamic Recommendations — No More Generic Repeated Text**

- All WLAN-specific threat blocks now suppress the generic static `REMEDIATION_GUIDE` text and instead show only the per-finding dynamic recommendations derived from the actual capture data.
- `high_retry_rate` now shows **severity-tiered recommendations** based on the actual retry percentage (critical >50%, high >30%, elevated <30%), plus per-AP and per-channel retry breakdown tables.
- `connection_delays` now renders full per-client delay analysis with: channel scan activity table, per-delay-reason cards (multi-band scanning, weak signal hesitation, passive scan periods, multiple scan cycles, etc.), each with a specific IEEE 802.11-derived recommendation.
- All existing WLAN blocks (`control_frame_issues`, `power_save_issues`, `action_frame_issues`, `beacon_loss`, `scan_failures`, `unprotected_traffic`, `ip_connectivity_failure`, `wpa3_sae_failures`) were already dynamic — static guide duplication is now removed across all of them.

**`detect_high_retry()` Enhanced**

`WLANRFMonitor.detect_high_retry()` now returns:
- `high_retry_bssids`: per-AP (BSSID) retry rate, retry count, and total frames for all APs above threshold
- `high_retry_channels`: per-channel retry breakdown for targeted channel-switching recommendations
- `threshold_pct`: the configured threshold (default 15%) for display in reports

### Bug Fixes

- `_skip_static_remediation` flag added to all WLAN threat handlers — previously the generic static `Recommended Remediation` box from `REMEDIATION_GUIDE` appeared redundantly after the already-detailed dynamic WLAN analysis blocks

---

## v1.7.0 — July 9, 2026

### Breaking Changes

**Removed standalone HTTP and HTTPS analyzers.**
`http_analyzer.py` and `https_analyzer.py` are no longer available as separate protocol choices.
HTTP/HTTPS analysis is now fully covered by the TCP analyzer with port filtering.

### New Features

**Port-Based Application-Layer Protocol Coverage in TCP/UDP Analyzers**

| Analyzer | Coverage added |
|---|---|
| `tcp_analyzer.py` | HTTP threat detection (SQL injection, XSS, directory traversal, suspicious user agents, HTTP flood) auto-triggered when port 80/8080 traffic is present; TLS/HTTPS threat detection (downgrade, handshake failures, flood) auto-triggered on port 443/8443; full `TCP_PORT_MAP` (20+ well-known ports) |
| `udp_analyzer.py` | `UDP_PORT_MAP` (15+ well-known ports: DNS/53, DHCP/67-68, NTP/123, QUIC/443, SSDP/1900, mDNS/5353, etc.); `app_layer_protocols` field in every result |

**Usage — analyzing HTTP or HTTPS traffic:**
```bash
# HTTP: select TCP protocol and set port filter to 80 (or 8080)
ai-wireshark analyze -i capture.pcap --protocol tcp --filter "tcp.port==80"

# HTTPS: select TCP protocol and set port filter to 443
ai-wireshark analyze -i capture.pcap --protocol tcp --filter "tcp.port==443"
```

In the GUI Protocol Analyzer panel: select **TCP**, enter `80` (or `443`) in the Port field.
All HTTP/HTTPS threat detections are included automatically in the TCP results.

### Improvements

- Protocol selector in GUI updated: HTTP and HTTPS removed; remaining options are TCP, UDP, DNS, ICMP, DHCP, WLAN
- Protocol panel subtitle updated to reflect port-based HTTP/HTTPS coverage
- `app_layer_protocols` dict included in TCP and UDP analysis results identifying observed protocols by port
- All 5 active protocol analyzers updated to return `{"status": "empty"}` instead of bare errors for no-packet results

### Bug Fixes

- **Fixed critical TShark crash (retcode 255) in DNS, DHCP, and WLAN analyzers** by:
  - Removing `use_json=True` / `include_raw=True` from pyshark `FileCapture` in `src/protocols/dhcp_analyzer.py`
  - Adding `keep_packets=False` to all direct `FileCapture` instantiations in DHCP and WLAN analyzers
  - Wrapping packet iteration loops in try/except to gracefully handle TShark mid-iteration crashes
  - Implementing proper `capture.close()` cleanup with nested exception handling
  - Updating `src/parsers/packet_parser.py` to catch and log TShark iteration errors instead of propagating
- **All protocol analyzers now resilient to malformed/problematic PCAP packets** — continuation with partial results instead of complete failure
- Removed `use_json=True` / `include_raw=True` which caused TShark crash (retcode 255)
- `matplotlib` / `seaborn` / `plotly` now lazy-loaded; app startup no longer fails when visualization dependencies are missing
- All protocol analyzers wrapped in try/except to return structured error dicts instead of propagating exceptions

### Build

- PyInstaller spec updated: `http_analyzer` and `https_analyzer` hidden imports removed
- Distribution size reduced slightly

---

## v1.6.1 — July 3, 2026

### New Features

**1. IPv6 Statistical Analysis Framework**

Enhanced `scripts/run_ipv6_analysis.py` with comprehensive statistical metrics (2362 lines total):

| Feature | Metrics |
|---------|----------|
| **IPI Statistics** | Mean, median, std dev, jitter, CV, burstiness classification (constant/regular/bursty/highly-bursty) |
| **Packet Size Distribution** | Min, max, mean, median, std, P95, P99; 4-bucket breakdown (min, <128B, 128-512B, 512B+) with % share |
| **Hourly Traffic** | Min/max/avg packets/hour, active hours count, peak hour offset |
| **TX/RX Ratios** | Both packet % and byte % ratios |
| **SNMP Polling** | Interval estimation, median/std consistency, requests/hour, error/unanswered rates |
| **Protocol/Peer Share** | Percentage distributions for all protocols and source IPs |
| **HTML Report** | New Statistics card with IPI table, packet size bucket chart, hourly metrics grid, SNMP subsection |

**Technical Details:**
- `analyse_statistics()` function extracts 8+ metric categories
- Integrates with pandas DataFrames for aggregation
- Generates embedded SVG charts in HTML reports
- Per-protocol and per-peer percentage annotations

**2. WPA3-SAE Root Cause Analysis Framework**

New standalone forensic analysis system for WPA3 failures (`scripts/run_wlan_analysis.py` extended to 921 lines):

| Aspect | Details |
|--------|----------|
| **Status Codes** | 12 codes with remediation: 1, 15, 30, 37, 46, 53, 72-78 (per IEEE 802.11-2020) |
| **Reason Codes** | 12 codes: 2, 3, 6, 7, 14, 15, 22, 23, 36, 45, 47, 50 |
| **Deadlock Detection** | Status 30 + PMF SA Query with stale PTK (CCMP PN > 1) |
| **Forensic Timeline** | Frame-level event sequencing with signal, timing, EAPOL tracking |
| **CCMP PN Evidence** | Proof of PTK reuse and cross-mode confusion |
| **Report Generator** | `generate_wpa3_rca_html()` creates purple-themed standalone report |
| **Auto-Generation** | Triggers when WPA3 failure detected during WLAN analysis |
| **Output** | `results/<stem>_wpa3_rca.html` with complete reference tables |

**3. Build System Updates**

- Removed unused TensorFlow/PyTorch from requirements (saves 4.1 GB disk space)
- Updated PyInstaller spec file: `installer/ai_wireshark.spec`
- Linux build now completes successfully with streamlined dependencies
- All tests pass (9/9): IPv6 stats, WPA3 codes, syntax validation verified

### Bug Fixes
- Resolved TensorFlow 2.13.0 unavailability on PyPI (updated to 2.20.0)
- Freed 4.1 GB disk space by removing unused ML frameworks
- Fixed PyInstaller spec paths for proper dependency bundling

### Build Artifacts (Linux)
```
Binary:     dist/AI-Wireshark-Analyzer/AI-Wireshark-Analyzer (17 MB, executable)
App Dir:    dist/AI-Wireshark-Analyzer/ (231 MB)
Distro:     AI-Wireshark-Analyzer-Linux-x64.zip (1.1 GB)
Checksum:   a4be37eddd713af8e73918ae6c397431cd04cb5b446ed48370f80103840698df
```

### Testing Status
✅ All 9 pytest tests passed:
- IPv6 statistical analysis functions validated
- WPA3 reference tables verified (24 error codes, explanations, remediation)
- Syntax errors: 0
- Protocol calculations: verified
- Address classification: verified

### Known Limitations
- Windows/macOS builds must be created on native OS (cross-compilation not supported)
- WPA3 RCA report generates only when WPA3 failure pattern detected
- IPv6 analysis requires valid IPv6 address parameter

### Dependencies (Updated)
```
Core: pyshark==0.6, scapy==2.5.0
Data: pandas==2.1.3, numpy>=1.24.3, scipy==1.11.4
ML: scikit-learn==1.3.2
GUI: PyQt6==6.11.0, PyQt6-WebEngine==6.11.0
Build: PyInstaller==6.21.0
```

### Next Steps
1. Test IPv6 analysis on PCAP with IPv6 traffic
2. Test WPA3 RCA report generation on WPA3-SAE failure captures
3. Build Windows and macOS distributions
4. Create GitHub release with all platforms

---

## v1.6.0 — July 2026

### Bug Fixes & Enhancements

**1. TensorFlow/CUDA Segmentation Fault Fix**
- Disabled CUDA/GPU initialization in `src/core/model.py` to prevent segfaults on systems without GPU support
- Added environment variables: `CUDA_VISIBLE_DEVICES=-1` and `TF_CPP_MIN_LOG_LEVEL=3`
- Graceful exception handling for TensorFlow initialization failures
- Application now runs in CPU-only mode without crashing

**2. Enhanced IP & Port Filtering for Protocol & TCP/UDP Analysis**
- **New UI Controls:**
  - TCP/UDP panel: Added IP address and TCP/UDP port filter inputs
  - Protocol panel: Added IP address and TCP/UDP port filter inputs
  - Input validation for IP format (x.x.x.x) and port ranges (1-65535)
  - Support for comma-separated ports (e.g., `80,443,8080`)
  
- **Backend Updates:**
  - Updated all protocol analyzers (TCP, UDP, HTTP, HTTPS, DNS, ICMP, DHCP) to accept `ip_filter` and `port_filter` parameters
  - Dynamic Wireshark filter expression construction for combined filtering
  - Filters work for both source and destination addresses/ports
  - Applied to: `analyze_tcp_udp.py`, all protocol analyzer classes, and CLI interface

**3. UI Improvements**
- Removed redundant "Report Output HTML" path fields from TCP/UDP and Protocol panels
- Reports now auto-generate in `results/` directory with sensible defaults
- Cleaner, more focused UI with essential filters only

---

## v1.5.2 — June 2026


### WPA3-SAE Authentication Failure Analysis

**AP State Machine Deadlock Detection (Status 30 / REFUSED_TEMPORARILY)**

Identified and implemented detection of a critical WPA3-SAE connection failure pattern
observed in real-world captures involving TP-Link APs (and other vendors) running in
WPA3 Transition Mode. The full forensic analysis is described below.

**Root Cause:** The AP holds a stale association entry from a prior session. When the
STA sends a fresh SAE Commit, the AP returns Status 30 (REFUSED_TEMPORARILY) instead
of accepting the new handshake. The AP then transmits 5 PMF-encrypted SA Query
Request frames (IEEE 802.11w §11.3.5) directed at the STA using the PTK from the
*prior* session — which the STA can no longer decrypt. All SA Queries time out. Per
IEEE 802.11-2020 §11.3.5.5 the AP **must** then send a Disassociation frame to clear
the stale entry; firmware that omits this step creates a permanent deadlock.

**CCMP PN Forensics:** The first SA Query frame carries a CCMP Packet Number (PN)
significantly greater than 1 (e.g. PN=67 in the analysed capture). This is definitive
proof of stale-PTK reuse and is now surfaced as a distinct finding.

**Changes:**

| Component | Change |
|-----------|--------|
| `src/protocols/wlan_analyzer.py` | Added Status 30 to `_sae_status_root_cause()` and `_sae_remediation()` with full §11.3.5.5 remediation guidance |
| `src/protocols/wlan_analyzer.py` | New detection block in `_detect_wpa3_sae_failures()`: AP State Machine Deadlock — Status 30 + post-rejection PMF Action frames with stale PTK |
| `src/protocols/wlan_analyzer.py` | Extended `_detect_action_frame_issues()` SA Query section: detects stale PTK via CCMP PN analysis (first PN >> 1) |
| `scripts/run_wlan_analysis.py` | Added `wlan.ccmp.extiv` tshark field → `ccmp_pn` column for per-frame CCMP Packet Number extraction |

**New findings surfaced by the WLAN panel:**

- `wpa3_sae_failures.stale_association_deadlock` — per-session detail including:
  - SAE Commit rejection frame number and timestamp
  - Count of PMF Action frames sent post-rejection (SA Query evidence)
  - Whether AP sent cleanup Deauthentication (§11.3.5.5 compliance flag)
  - WPA3 Transition Mode cross-PTK confusion note
- `action_frame_issues` SA Query category — new sub-finding:
  - `SA Query uses stale PTK — CCMP PN continuity breach`
  - Reports first observed PN, frame count, and recovery steps

**Remediation guidance added for:**
1. STA: send Deauthentication (Reason 3) before retrying SAE Commit
2. AP: firmware fix required — issue Disassociation after `dot11AssociationSAQueryMaximumTimeout`
3. WPA3 Transition Mode: prevent WPA2 PTK reuse on the SAE/PMF path
4. PMKSA cache: disable on STA to avoid stale-cache fast-reconnect attempts

---

## v1.5.1 — June 2026

### Documentation and Platform Updates

- Updated installation and usage guides for Linux, Windows, and macOS
- Added explicit native-build guidance for each platform
- Aligned README, Getting Started, Quickstart, and Build Guide with current panels:
  - Home
  - WLAN / Wi-Fi
  - WPA Decrypt
  - Channel & Network Map
  - TCP/UDP Diagnostics
  - IPv6 Analysis
  - Protocol Analyzers
  - ML Anomaly
  - CLI & Workflow

### Packaging Status

| Platform | Package | Status |
|----------|---------|--------|
| Linux x86_64 | `dist/AI-Wireshark-Analyzer/` | Built and validated |
| Windows x64 | EXE/installer | Build on Windows host |
| macOS | App/DMG | Build on macOS host |

### Build Validation (Linux)

- PyInstaller: 6.20.0
- Python: 3.12.3
- Build output: `dist/AI-Wireshark-Analyzer/`
- Build completed successfully from current source

---

## v1.0.0 — June 2026

### New Features

**Client Activity Breakdown (Channel Monitor)**
- Accurately counts real connected clients by distinguishing:
  - Actively connected (>50 frames) — devices actively exchanging data
  - Medium activity (6–50 frames) — periodic traffic, background sync
  - Low activity / probe-only (≤5 frames) — passing devices, random probes
- Filters randomised/locally-administered MACs — eliminates phantom clients
- Example: 87 raw unique MACs → 53 actively connected + 12 medium + 22 low

**WPA/WPA2/WPA3 Decryption**
- Decrypt encrypted 802.11 captures using SSID+password or 64-hex PMK
- Supports WPA3-SAE (Wireshark ≥ 3.4 required for SAE)
- Post-decryption inner analysis: DNS, HTTP, IP endpoints, ports, security flags

**Enhanced Channel Monitor Metrics**
- RTS/CTS overhead % with severity thresholds (≥30% = High, ≥20% = Medium)
- CTS reply rate (hidden-node indicator)
- Maximum NAV duration and abuse detection (>32 ms)
- Connection delay measurement (probe-response → auth timing)
- Scan cycle detection (>3 s gaps between probe bursts)

**Standalone Binary Distribution**
- Pre-built Linux x86_64 binary (no Python or venv needed)
- All dependencies bundled — only tshark required externally
- Source code compiled to bytecode — not exposed in distribution

### Documentation Consolidated
- README, QUICKSTART, PROJECT_SUMMARY, GETTING_STARTED, BUILD_GUIDE, RELEASE_NOTES
- Removed all duplicate installation content
- Single source of truth for each topic

---

## Available Packages

| Platform | Package | Status |
|----------|---------|--------|
| Linux x86_64 | `AI-Wireshark-Analyzer-Linux-x64.zip` (1.1 GB) | Ready |
| Windows x86_64 | `AI-Wireshark-Analyzer-Setup-x64.exe` | Build on Windows |
| macOS Universal | `AI-Wireshark-Analyzer-macOS-universal.dmg` | Build on macOS |

### Linux Build Details
```
PyInstaller:  6.20.0
PyQt6:        6.11.0
Python:       3.12.3
Build size:   701 MB (compressed: 1.1 GB)
Source exposed: None (0 .py files from project)
Integrity:    Verified (unzip -t)
```

---

## Analysis Types

| Tool | What it analyses |
|------|-----------------|
| WLAN Analyzer | Auth failures, signal, beacon loss, retry, connection delay |
| Channel Monitor | RF metrics, RTS/CTS, client activity breakdown, station spotlight |
| WPA Decrypt | Decrypt WPA/WPA2/WPA3; inner DNS/HTTP/IP/port analysis |
| TCP/UDP | Retransmissions, zero-window, RST storms, UDP amplification |
| IPv6 | Per-address ICMPv6, NDP, SNMP, TCP/UDP flows |
| Protocol | TCP, UDP, HTTP, DNS, ICMP deep-dive |
| Anomaly | ML anomaly detection (Isolation Forest, Autoencoder) |

---

## Next Steps

- Build Windows installer on a Windows machine: `installer\build_installer.bat`
- Build macOS DMG on a macOS machine: `./installer/build.sh`
- Create GitHub Release and upload ZIP packages
- See [BUILD_GUIDE.md](BUILD_GUIDE.md) for full build instructions
