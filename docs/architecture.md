# Architecture Overview

## System Design

AI-Wireshark-Analyzer is a modular analysis platform for network packet captures. The architecture follows a pipeline design with clear separation of concerns, supporting both tshark-native bulk extraction (for WLAN and TCP/UDP scripts) and PyShark-based structured parsing (for protocol analyzers and the ML pipeline).

```
┌─────────────────────────────────────────────────────────┐
│  PCAP / PCAPNG Input                                    │
└────────┬───────────────────────────────┬────────────────┘
         │                               │
         ▼ (PyShark path)                ▼ (tshark-native path)
┌─────────────────┐             ┌────────────────────────┐
│ Packet Parser   │             │ run_wlan_analysis.py   │
│ packet_parser.py│             │ analyze_tcp_udp.py     │
└────────┬────────┘             │ run_ipv6_analysis.py   │
         │                      └──────────┬─────────────┘
         │                                 │
         ▼                                 ▼
┌─────────────────┐             ┌────────────────────────┐
│ Data Cleaning   │             │ WLANAnalyzer /         │
│ Feature Eng.    │             │ TCP/UDP Analyser        │
└────────┬────────┘             └──────────┬─────────────┘
         │                                 │
         ├──────────────────────┐          │
         ▼                      ▼          ▼
┌────────────────┐   ┌──────────────┐  ┌─────────────────┐
│   Protocol     │   │   Anomaly    │  │  HTML Generator │
│   Analyzers    │   │  Detection   │  │  (inline/shared)│
│  TCP, UDP,     │   │  Isolation   │  └─────────────────┘
│  DNS, HTTP,    │   │  Forest /    │
│  HTTPS, ICMP,  │   │  Autoencoder │
│  DHCP, WLAN    │   └──────┬───────┘
└───────┬────────┘          │
        └──────────┬─────────┘
                   ▼
          ┌─────────────────┐
          │ Results & Viz   │
          └─────────────────┘
          ▼         ▼       ▼
        REST       CLI    HTML
         API      Tool   Report
```

## Components

### 1. Data Ingestion Layer

#### PacketParser (`src/parsers/packet_parser.py`)
- Reads PCAP/PCAPNG files using PyShark
- Extracts per-packet fields into a pandas DataFrame
- Supports protocol filtering and flow aggregation
- Used by the ML pipeline and `src/protocols/` analyzers

#### tshark Bulk Extraction (scripts)
- `scripts/run_wlan_analysis.py` — extracts 32 WLAN fields per packet directly via tshark subprocess
- `scripts/analyze_tcp_udp.py` — extracts TCP/UDP analysis fields via targeted tshark display filters
- `scripts/run_ipv6_analysis.py` — per-address IPv6 traffic analysis via targeted tshark queries
- No PyShark overhead; suitable for large captures

### 2. Data Processing Layer

#### DataCleaner (`src/preprocessing/cleaning.py`)
- Removes duplicates
- Handles missing / malformed values
- Validates numeric ranges
- Filters by protocol or time range

#### FeatureEngineer (`src/preprocessing/feature_engineering.py`)
- IP-based features (private/public, subnets)
- Port-based features (privileged/ephemeral)
- Protocol features (TCP flag decomposition, ICMP types)
- Statistical features (sizes, rates)
- Time-based features (business hours, inter-arrival times)
- DNS-specific features (entropy, subdomain depth)
- HTTP-specific features (URI analysis, suspicious patterns)

### 3. Analysis Layer

#### Protocol Analyzers (`src/protocols/`)

Each analyzer exposes `analyze(pcap_file) -> dict` with `total_packets`, `critical_issues`, `statistics`, and `threats`.

**TCP Analyzer** (`tcp_analyzer.py`):
- SYN flood detection (rate-based; guard logic corrected)
- RST storm identification
- Port scanning detection (port diversity)
- Excessive retransmissions
- Connection hijacking (sequence number anomalies)
- Zero-window / window-full stall detection
- Data transmission gap detection

**UDP Analyzer** (`udp_analyzer.py`):
- Flood attack detection (packet rate)
- Amplification attack detection (service abuse)
- Port scanning
- Fragmentation attacks

**WLAN Analyzer** (`wlan_analyzer.py`):
- 802.11 connection failure detection with per-reason evidence (all 40+ IEEE reason/status codes)
- EAPOL 4-way handshake stall detection (WPA2)
- WPA3/SAE authentication failures: wrong-password loops, anti-clogging token, EC group mismatch, SAE Commit/Confirm tracking
- WPA3-OWE detection
- Beacon loss / AP disappearance detection
- Probe request failures (no probe response)
- Weak signal detection (RSSI/SNR)
- Unprotected data frame detection (no encryption)
- IP connectivity failure (multicast-only client pattern)
- High retry rate (data frames only)
- Power-save scan pattern detection
- Per-client connection flow reconstruction + diagnosis

**DHCP Analyzer** (`dhcp_analyzer.py`):
- DHCP starvation / exhaustion
- Rogue DHCP server detection
- Lease anomaly detection

**DNS Analyzer** (`dns_analyzer.py`):
- Tunneling detection (entropy, subdomain depth)
- DGA detection (algorithmic domain patterns)
- Cache poisoning indicators
- Excessive NXDOMAIN rates, amplification attacks

**HTTP Analyzer** (`http_analyzer.py`):
- SQL injection, XSS detection
- Suspicious user agent identification
- HTTP flood, directory traversal

**HTTPS Analyzer** (`https_analyzer.py`):
- TLS downgrade detection
- Certificate anomalies
- Connection rate analysis

**ICMP Analyzer** (`icmp_analyzer.py`):
- ICMP flood, Ping of Death, Smurf attack detection
- ICMP tunneling (payload analysis)
- Network scanning

#### ML Models (`src/core/model.py`)

**Isolation Forest (Unsupervised Anomaly Detection):**
- No labeled data required; contamination-based scoring
- Fast training and inference

**Autoencoder (Deep Learning Anomaly Detection):**
- Neural network reconstruction error
- TensorFlow/Keras (gracefully disabled if not installed)

**Random Forest Classifier (Supervised):**
- Multi-class attack type classification
- Feature importance analysis
- Requires labeled training data

### 4. Analysis Scripts (`scripts/`)

**`run_wlan_analysis.py`**:
- Orchestrates tshark bulk extraction → `WLANAnalyzer` → `html_generator.py`
- Outputs JSON results and self-contained HTML report
- Optional MAC filter (2nd positional arg) restricts to a single client — matches SA, DA, TA, RA, BSSID
- Usage: `python3 scripts/run_wlan_analysis.py <pcap> [mac]`

**`analyze_tcp_udp.py`**:
- Pure tshark subprocess analysis; no PyShark or pandas
- Auto-detects application stream (port 9100/631/515)
- Zero-window stall timeline, RST catalogue with burst detection, UDP flow analysis, QUIC detection
- Generates self-contained HTML with embedded bar charts
- Usage: `python3 scripts/analyze_tcp_udp.py <pcap> [out.html]`

**`run_ipv6_analysis.py`**:
- Per-address IPv6 traffic analysis via targeted tshark queries
- TCP connections, retransmissions, zero-window, RST events, port probes
- UDP flows, SNMP community analysis, ICMPv6/NDP patterns
- Generates JSON results + self-contained HTML report
- Usage: `python3 scripts/run_ipv6_analysis.py <pcap> <ipv6_address>`

### 5. Evaluation Layer

#### Metrics (`src/evaluation/metrics.py`)
- Accuracy, Precision, Recall, F1, Confusion matrix, ROC-AUC

#### Visualization (`src/evaluation/visualization.py`)
- Protocol distribution, traffic timeline, anomaly score distributions
- Confusion matrices, feature importance, packet size distributions

### 6. Reporting Layer (`src/reports/html_generator.py`)

- Self-contained HTML reports (no external CSS/JS)
- Severity badges: Critical / High / Medium / Low / Info
- Embedded Base64 chart images
- Remediation guidance (`REMEDIATION_GUIDE`) keyed by threat name
- Used by all `src/protocols/` analyzers and `run_wlan_analysis.py`
- `analyze_tcp_udp.py` contains its own inline HTML generator with timeline bar charts

### 7. Interface Layer

#### REST API (`src/api/rest.py`)
- FastAPI + Uvicorn
- Endpoints: `/analyze`, `/detect-anomalies`, `/health`, `/models`, `/protocols`
- File upload via multipart/form-data; temp file cleanup via BackgroundTasks
- OpenAPI docs at `/docs` (Swagger) and `/redoc`

#### CLI (`src/api/cli.py`)
- Click + Rich terminal formatting
- Commands: `analyze`, `analyze-wlan`, `detect-anomalies`, `visualize`, `info`
- `analyze` supports `-f` for Wireshark display filters (e.g. `ip.addr==`, `ip.src==`, `tcp.port==`)
- `analyze-wlan` supports `-f` for WLAN display filters (e.g. `wlan.addr==`, `wlan.sa==`)

## Data Flow

### Analysis Pipeline (PyShark / ML path)

1. PCAP file → `PacketParser.parse_pcap()` → raw DataFrame
2. `DataCleaner.clean()` → cleaned DataFrame
3. `FeatureEngineer.engineer_features()` → 50+ feature DataFrame
4. `ProtocolAnalyzer.analyze()` → rule-based threat dict
5. `IsolationForestModel.predict()` / `AutoencoderModel.detect_anomalies()` → anomaly scores
6. Results → JSON / HTML report / API response

### WLAN Analysis Pipeline (tshark-native)

1. PCAP file + optional MAC filter → tshark bulk extraction (32 fields) → list of packet dicts
2. MAC filter applied as tshark display filter: `wlan.sa == MAC || wlan.da == MAC || wlan.ta == MAC || wlan.ra == MAC || wlan.bssid == MAC`
3. `WLANAnalyzer.analyze()` → connection flows + threat detection dicts
4. `html_generator.py` → self-contained HTML report + JSON output

### TCP/UDP Direct Analysis Pipeline (tshark-native)

1. PCAP file → targeted tshark display-filter queries → metric dicts
2. `generate_html()` (inline) → self-contained HTML with timeline charts

### IPv6 Analysis Pipeline (tshark-native)

1. PCAP file + IPv6 address → targeted tshark queries for TCP, UDP, ICMPv6, SNMP
2. Per-protocol analysis: connections, retransmissions, RST events, port probes, NDP patterns
3. Inline HTML generator renders report with charts
4. JSON results + HTML report written to `results/`

## Configuration

All tunables in YAML files under `config/`:
- `default.yaml` — production settings (thresholds, model params, visualization, API)
- `dev.yaml` — development overrides

## Storage

```
data/
├── raw/          # PCAP/PCAPNG files
├── processed/    # Feature CSVs
└── external/     # Third-party datasets
models/           # Trained ML models (.pkl, .h5)
results/          # Analysis HTML reports and JSON outputs
logs/             # Application logs
```

## Security Considerations

1. **File Upload:** Size limits enforced, file type validation, temporary file cleanup

2. **Model Security:** Models validated before loading, input sanitization, resource limits

3. **Data Privacy:** No PII extraction from packets; local processing only; configurable data retention

## Scalability

### Performance

- Streaming packet parsing (memory efficient)
- tshark bulk extraction for large captures (WLAN/TCP-UDP scripts)
- Async API endpoints + background cleanup
- Configurable packet limits and batch prediction

### Resource Requirements

**Minimum:** 2 cores, 4 GB RAM, 10 GB storage  
**Recommended:** 4+ cores, 8 GB+ RAM, 50 GB+ storage

## Extension Points

1. **New Protocol Analyzer:** add `src/protocols/<name>_analyzer.py`, implement `analyze()`, register in CLI/API.
2. **New ML Model:** add class in `src/core/model.py` with `train()` / `predict()` interface; update config.
3. **New Script:** follow `run_wlan_analysis.py` pattern — tshark extraction → analysis class → `html_generator.py`.

## Dependencies

| Category      | Library                         |
|---------------|----------------------------------|
| Ingestion     | tshark (system), PyShark        |
| Data          | Pandas, NumPy                    |
| ML            | Scikit-learn, TensorFlow/Keras  |
| API           | FastAPI, Uvicorn                 |
| CLI           | Click, Rich                      |
| Visualization | Matplotlib, Seaborn              |
| Logging       | Loguru                           |
| Config        | PyYAML                           |
| Testing       | PyTest                           |
