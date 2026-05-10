# AI-Wireshark-Analyzer — Design Document

**Version:** 1.2.0  
**Date:** May 8, 2026  
**Status:** Active

---

## 1. Executive Summary

AI-Wireshark-Analyzer is a Python-based network traffic analysis platform that combines traditional protocol inspection with Machine Learning and Deep Learning to detect anomalies, classify attacks, and provide actionable security insights from Wireshark packet captures (PCAP/PCAPNG files). It exposes its capabilities through a REST API (FastAPI), a CLI (Click + Rich), standalone analysis scripts, and self-contained HTML reports.

Since v1.0, the platform has been extended with a full 802.11 WLAN analyzer (WPA2/WPA3/SAE, connection flows, scan patterns), a DHCP analyzer, a dedicated TCP/UDP application traffic analyser (`analyze_tcp_udp.py`) for diagnosing flow-control and session-level problems (zero-window stalls, retransmissions, RST events), and an IPv6 traffic analysis script (`run_ipv6_analysis.py`) for per-address TCP, UDP, ICMPv6, and SNMP diagnostics. The codebase has also been audited and cleaned — 17 unused imports, 1 dead function, 1 dead branch, and 1 inverted logic bug removed.

---

## 2. Goals and Non-Goals

### Goals

- Parse PCAP/PCAPNG files and extract protocol-level features automatically.
- Detect critical network threats (SYN floods, DNS tunneling, port scans, SQL injection, WLAN connection failures, WPA3/SAE issues, etc.) using rule-based protocol analyzers.
- Provide unsupervised anomaly detection (Isolation Forest, Autoencoder) that requires no labeled data.
- Support supervised attack classification (Random Forest) when labeled datasets are available.
- Analyse 802.11 WLAN traffic in depth — WPA2, WPA3/SAE, connection flows, beacon loss, scan patterns, IP connectivity.
- Analyse IPv6 traffic per-address — TCP connections, UDP flows, ICMPv6, SNMP, retransmissions, port probes.
- Diagnose application-level TCP/UDP issues — zero-window stalls, retransmissions, RST events, UDP flow analysis.
- Generate professional, self-contained HTML reports with embedded charts, severity badges, and remediation guidance.
- Offer a REST API, a CLI, and standalone scripts for flexible integration.

### Non-Goals

- Real-time / live capture analysis (the system operates on saved PCAP files).
- Replacement for a full IDS/IPS (the tool is an analysis aid, not inline prevention).
- Distributed or cloud-scale processing of multi-gigabyte captures.

---

## 3. System Architecture

### 3.1 High-Level Pipeline

Two parallel pipelines coexist:

**PyShark / ML Pipeline** (protocol analyzers, CLI, REST API):
```
PCAP File
    │
    ▼
┌──────────────────┐
│  Packet Parser   │   PyShark (tshark backend)
└────────┬─────────┘
         │  pd.DataFrame
         ▼
┌──────────────────┐
│  Data Cleaning   │   Dedup, missing value handling, range validation
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Feature Engineer │   50+ ML-ready features (IP, port, protocol,
└────────┬─────────┘   time, statistical, DNS/HTTP-specific)
         │
         ├────────────────────┬──────────────────────┐
         ▼                    ▼                      ▼
┌────────────────┐  ┌─────────────────┐  ┌──────────────────┐
│   Protocol     │  │    Anomaly      │  │     Attack       │
│   Analyzers    │  │   Detection     │  │  Classification  │
│                │  │                 │  │                  │
│  TCP, UDP,     │  │ Isolation Forest│  │  Random Forest   │
│  DNS, HTTP,    │  │ Autoencoder     │  │  (supervised)    │
│  HTTPS, ICMP,  │  │ (unsupervised)  │  │                  │
│  DHCP, WLAN    │  │                 │  │                  │
└───────┬────────┘  └────────┬────────┘  └────────┬─────────┘
        │                    │                     │
        └────────────────────┴─────────────────────┘
                             │
                             ▼
                   ┌──────────────────┐
                   │  Results & Viz   │
                   └──────────────────┘
                   ▼         ▼         ▼
                 REST       CLI      HTML
                  API      Tool     Report
```

**tshark-Native Scripts Pipeline** (zero PyShark/pandas overhead):
```
PCAP File
    │
    ├──► run_wlan_analysis.py ──► tshark (32 WLAN fields) ──► WLANAnalyzer ──► HTML + JSON
    │
    ├──► analyze_tcp_udp.py ──► tshark (targeted display filters) ──► HTML report
    │
    └──► run_ipv6_analysis.py ──► tshark (per-address IPv6 queries) ──► HTML + JSON
```

### 3.2 Layer Breakdown

| Layer               | Responsibility                         | Key Modules                                                      |
|---------------------|----------------------------------------|------------------------------------------------------------------|
| Data Ingestion      | Read PCAP, extract raw packet features | `src/parsers/packet_parser.py`                                   |
| Data Processing     | Clean, validate, engineer features     | `src/preprocessing/cleaning.py`, `feature_engineering.py`       |
| Analysis – Rules    | Protocol-specific threat detection     | `src/protocols/tcp_analyzer.py` … `wlan_analyzer.py`            |
| Analysis – Scripts  | tshark-native bulk extraction + report | `scripts/run_wlan_analysis.py`, `scripts/analyze_tcp_udp.py`, `scripts/run_ipv6_analysis.py` |
| Analysis – ML       | Unsupervised anomaly scoring           | `src/core/model.py` (IsolationForest, Autoencoder)               |
| Analysis – ML       | Supervised attack classification       | `src/core/model.py` (RandomForest)                               |
| Evaluation          | Metrics, ROC, confusion matrices       | `src/evaluation/metrics.py`                                      |
| Visualization       | Charts (matplotlib, seaborn)           | `src/evaluation/visualization.py`                                |
| Reporting           | Self-contained HTML reports            | `src/reports/html_generator.py`                                  |
| Interface – API     | RESTful endpoints                      | `src/api/rest.py`                                                |
| Interface – CLI     | Terminal commands                      | `src/api/cli.py`                                                 |

---

## 4. Component Design

### 4.1 Packet Parser (`src/parsers/packet_parser.py`)

- **Input:** PCAP / PCAPNG file path, optional Wireshark display filter.
- **Processing:** Uses **PyShark** (a Python wrapper around `tshark`) to iterate packets. Extracts per-packet fields: `protocol`, `length`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `tcp_flags`, `timestamp`, `ttl`, `window_size`.
- **Output:** A `pandas.DataFrame` where each row is one packet.
- **Configuration:** Maximum packet limit (`max_packets`) and flow aggregation window (`flow_window`) controlled via `config/default.yaml`.

### 4.2 Data Cleaning (`src/preprocessing/cleaning.py`)

- Removes duplicate packets.
- Fills or drops missing / malformed values.
- Validates numeric ranges (e.g., port ∈ [0, 65535]).
- Optionally filters by protocol or time range.

### 4.3 Feature Engineering (`src/preprocessing/feature_engineering.py`)

Produces 50+ features grouped into categories:

| Category     | Examples                                                  |
|--------------|-----------------------------------------------------------|
| IP-based     | Private/public flag, subnet grouping, `ip_to_int`        |
| Port-based   | Privileged (< 1024), ephemeral, well-known service flags |
| Protocol     | TCP flag bitmask decomposition, ICMP type codes           |
| Statistical  | Packet size mean/std/min/max, byte-rate, packet-rate      |
| Time-based   | Hour of day, business-hours flag, inter-arrival times     |
| DNS-specific | Query entropy, subdomain depth, label length stats        |
| HTTP-specific| URI length, parameter count, suspicious pattern flags     |

### 4.4 Protocol Analyzers (`src/protocols/`)

Eight dedicated analyzers, each detecting protocol-specific threats using configurable thresholds from `config/default.yaml`:

| Analyzer    | Threats Detected                                                                                         |
|-------------|----------------------------------------------------------------------------------------------------------|
| **TCP**     | SYN flood, RST storms, port scanning, excessive retransmissions, connection hijacking, zero-window stalls, data gaps |
| **UDP**     | UDP flood, amplification attacks, port scanning, fragmentation attacks                                   |
| **WLAN**    | 802.11 connection failures (40+ reason/status codes), EAPOL stall, WPA3/SAE failures, beacon loss, probe failures, weak signal, unprotected traffic, IP connectivity failure, high retry rate, power-save scanning |
| **DHCP**    | DHCP starvation, rogue server, lease anomalies                                                           |
| **DNS**     | DNS tunneling, DGA domains, cache poisoning, NXDOMAIN floods, amplification                             |
| **HTTP**    | SQL injection, XSS, suspicious user agents, HTTP floods, directory traversal                            |
| **HTTPS**   | TLS downgrade, certificate anomalies, HTTPS floods                                                       |
| **ICMP**    | ICMP flood, Ping of Death, Smurf attacks, ICMP tunneling, network scanning                              |

Each analyzer returns a structured dict with `total_packets`, `critical_issues`, `statistics`, and `threats`.

#### WLAN Analyzer Detail (`src/protocols/wlan_analyzer.py`)

`WLANAnalyzer` is the most complex analyzer. It uses tshark to extract 32 per-packet WLAN fields, then applies:

| Method | Detects |
|--------|---------|
| `_detect_connection_failures` | Per-reason-code evidence-based validation for all 40+ IEEE 802.11 reason/status codes; per-client connection flow reconstruction and diagnosis |
| `_build_connection_flows` | Ordered step-by-step 802.11 auth/assoc/EAPOL flow per client MAC |
| `_diagnose_connection_session` | Root-cause analysis: which step failed, which frames are evidence |
| `_detect_wpa3_sae_failures` | SAE Commit/Confirm tracking, wrong-password loop counter, anti-clogging token, EC group mismatch, post-SAE EAPOL stall, OWE |
| `_detect_beacon_losses` | AP disappearance / beacon gap detection |
| `_detect_probe_failures` | Unanswered probe requests |
| `_detect_weak_signal` | RSSI/SNR threshold violations |
| `_detect_unprotected_traffic` | Non-encrypted data frames |
| `_detect_ip_connectivity_failure` | Multicast-only client pattern (no unicast after association) |
| `_detect_high_retry` | Data-frame-only retry rate (management frames excluded) |
| `_detect_scan_failures` | Power-save bit set during scan (`wlan.fc.pwrmgt`) |

### 4.5 Analysis Scripts (`scripts/`)

Two standalone scripts provide tshark-native analysis without the PyShark/pandas overhead, making them suitable for large captures and automation.

#### `scripts/run_wlan_analysis.py`

Orchestrates full WLAN analysis:
1. Bulk tshark extraction — 32 WLAN fields per packet via single subprocess call.
2. Passes results to `WLANAnalyzer.analyze()`.
3. Writes JSON results and generates self-contained HTML report via `html_generator.py`.
4. Optional MAC filter restricts analysis to a single client (matches SA, DA, TA, RA, and BSSID).

```bash
# All WLAN frames — reports auto-generated in results/
python3 scripts/run_wlan_analysis.py <pcap>

# Filter to a single client MAC
python3 scripts/run_wlan_analysis.py <pcap> [mac_filter]
```

#### `scripts/analyze_tcp_udp.py`

Direct TCP/UDP application traffic diagnostics:
1. Auto-detects dominant application stream (port 9100/631/515 for printing).
2. Runs targeted tshark display-filter queries to extract: zero-window events, retransmissions, RSTs, window updates, duplicate ACKs, lost segments, data volume, UDP top flows, QUIC, broadcast UDP.
3. Generates self-contained HTML with a per-30-second zero-window timeline chart, RST detail table, UDP flow table, and severity-ranked remediation recommendations.

```bash
python3 scripts/analyze_tcp_udp.py <pcap> [out.html]
```

Output dict keys: `total_packets`, `duration_s`, `tcp_count`, `udp_count`, `print_hosts`, `rst_total`, `zero_window`, `window_updates`, `retransmissions_print`, `dup_acks_print`, `lost_segments`, `data_sent_mb`, `print_connections`, `zw_timeline`, `rst_detail`, `rst_bursts`, `udp_top_flows`, `broadcast_udp`, `quic_count`.

#### `scripts/run_ipv6_analysis.py`

IPv6 per-address traffic analysis:
1. Accepts a pcap file and an IPv6 address.
2. Runs targeted tshark queries for TCP, UDP, ICMPv6, and SNMP traffic involving the address.
3. Detects retransmissions, zero-window events, RST events, port probes, NDP patterns, and SNMP community analysis.
4. Generates JSON results + self-contained HTML report with charts.
5. Output auto-generated as `results/ipv6_{addr_slug}.json` and `results/ipv6_{addr_slug}_report.html`.

```bash
python3 scripts/run_ipv6_analysis.py <pcap> <ipv6_address>
```

---

### 4.6 Machine Learning Models (`src/core/model.py`)

#### Isolation Forest (Unsupervised)
- **Use case:** Anomaly detection without labeled data.
- **Parameters:** `n_estimators=100`, `contamination=0.1` (configurable).
- **Output:** Per-sample labels (1 = normal, −1 = anomaly) and continuous anomaly scores.

#### Autoencoder (Deep Learning, Unsupervised)
- **Use case:** Detecting subtle anomalies via reconstruction error.
- **Architecture:** Encoder → bottleneck (`encoding_dim=32`) → Decoder.
- **Framework:** TensorFlow/Keras (gracefully disabled if not installed).
- **Output:** Reconstruction error per sample; threshold determines anomaly flag.

#### Random Forest Classifier (Supervised)
- **Use case:** Multi-class attack classification (DoS, port scan, DNS tunneling, etc.).
- **Parameters:** `n_estimators=200`, `max_depth=20`.
- **Prerequisite:** Labeled training data.
- **Output:** Class labels + prediction probabilities + feature importance rankings.

All models use `StandardScaler` for feature normalization and support `save()` / `load()` via `joblib`.

### 4.7 Evaluation (`src/evaluation/metrics.py`)

Computes: accuracy, precision, recall, F1-score, confusion matrix, false-positive/negative rates, and ROC-AUC (when scores are available). Supports both anomaly-detection (binary) and multi-class metrics.

### 4.8 Visualization (`src/evaluation/visualization.py`)

`NetworkVisualizer` produces:
- Protocol distribution (bar + pie)
- Traffic timeline (time-series)
- Anomaly score distributions (histogram)
- Confusion matrices (heatmap)
- Feature importance (horizontal bar)
- Packet size distributions
- IP traffic analysis

All plots use Seaborn/Matplotlib, configurable via `visualization` section in YAML.

### 4.9 HTML Report Generator (`src/reports/html_generator.py`)

Generates self-contained HTML files with:
- Executive summary (packet count, risk level)
- Critical issues table with severity badges (Critical / High / Medium / Low / Info)
- Threat analysis details with evidence
- Embedded Base64 chart images
- Remediation guidance (`REMEDIATION_GUIDE`) keyed by threat name
- Responsive layout

Used by all `src/protocols/` analyzers and `scripts/run_wlan_analysis.py`.

> `scripts/analyze_tcp_udp.py` contains its own inline `generate_html()` function with a zero-window timeline bar chart; it does not depend on `html_generator.py`.

### 4.10 REST API (`src/api/rest.py`)

Built with **FastAPI** + **Uvicorn**.

| Endpoint              | Method | Description                         |
|-----------------------|--------|-------------------------------------|
| `/health`             | GET    | Health check                        |
| `/models`             | GET    | List available ML models            |
| `/analyze`            | POST   | Upload PCAP + run full analysis     |
| `/detect-anomalies`   | POST   | Upload PCAP + ML anomaly detection  |
| `/protocols`          | GET    | List supported protocols            |

- File uploads via `multipart/form-data`.
- Temporary files cleaned up via `BackgroundTasks`.
- Auto-generated OpenAPI docs at `/docs` (Swagger) and `/redoc`.

### 4.11 CLI (`src/api/cli.py`)

Built with **Click** + **Rich** for formatted terminal output.

| Command             | Description                                  |
|---------------------|----------------------------------------------|
| `analyze`           | Parse PCAP, run protocol analysis, output JSON / HTML. Supports `-f` for Wireshark display filter (e.g. `ip.addr==`, `tcp.port==`) |
| `analyze-wlan`      | WLAN/WiFi analysis with `-f` for MAC/display filter (e.g. `wlan.addr==aa:bb:cc:dd:ee:ff`) |
| `detect-anomalies`  | Run ML-based anomaly detection               |
| `visualize`         | Generate chart images                        |
| `info`              | Display system and configuration info        |

---

## 5. Data Flow

### PyShark / ML Pipeline

```
1.  User provides PCAP file  ──►  CLI  or  REST API  or  direct script
2.  PacketParser.parse_pcap()  ──►  raw DataFrame
3.  DataCleaner.clean()        ──►  cleaned DataFrame
4.  FeatureEngineer.engineer_features()  ──►  feature DataFrame (50+ cols)
5a. ProtocolAnalyzer.analyze()  ──►  rule-based threat dict
5b. IsolationForestModel.predict()  ──►  anomaly labels + scores
5c. AutoencoderModel.detect_anomalies()  ──►  reconstruction errors
5d. RandomForestModel.predict()  ──►  attack class labels
6.  Results merged  ──►  JSON / HTML report / API response
```

### WLAN Analysis Pipeline (tshark-native)

```
1.  run_wlan_analysis.py receives PCAP + optional MAC filter
2.  tshark subprocess: 29 WLAN fields extracted for all frames
3.  WLANAnalyzer.analyze() runs all detection methods
4.  html_generator.py renders self-contained HTML
5.  JSON results + HTML report written to disk
```

### TCP/UDP Application Pipeline (tshark-native)

```
1.  analyze_tcp_udp.py receives PCAP
2.  Series of targeted tshark display-filter queries extract metrics
3.  Auto-detects print/application stream (port 9100/631/515)
4.  generate_html() (inline) renders HTML with timeline charts
5.  HTML report written to disk
```

### IPv6 Analysis Pipeline (tshark-native)

```
1.  run_ipv6_analysis.py receives PCAP + IPv6 address
2.  Targeted tshark queries extract TCP, UDP, ICMPv6, SNMP metrics
3.  Inline HTML generator renders report with charts
4.  JSON results + HTML report written to results/
```

---

## 6. Configuration

All tunables live in YAML files under `config/`:

- **`default.yaml`** — Production settings.
- **`dev.yaml`** — Development overrides.

Key configuration sections:

| Section            | Controls                                                               |
|--------------------|------------------------------------------------------------------------|
| `app`              | Name, version, debug flag                                              |
| `api`              | Host, port, workers, max upload size (default 100 MB)                  |
| `features`         | Packet features list, flow aggregation window, max packet limit        |
| `models`           | Hyperparameters for Isolation Forest, Autoencoder, Random Forest       |
| `anomaly_detection`| Score threshold, minimum packet count                                  |
| `protocols`        | Per-protocol thresholds (SYN rate, query rate, suspicious UAs, etc.)   |
| `visualization`    | Figure size, Seaborn style, DPI, color palette                         |

---

## 7. Technology Stack

| Category           | Technology                                              |
|--------------------|---------------------------------------------------------|
| Language           | Python 3.10+ (3.12 recommended)                         |
| Packet Parsing     | PyShark 0.6, Scapy 2.5                                  |
| ML / Statistics    | scikit-learn 1.3, TensorFlow 2.13, PyTorch 2.1          |
| Data Processing    | pandas 2.1, NumPy 1.24, SciPy 1.11                     |
| Visualization      | Matplotlib 3.8, Seaborn 0.13, Plotly 5.18               |
| API                | FastAPI 0.104, Uvicorn 0.24, Pydantic 2.5               |
| CLI                | Click 8.1, Rich 13.7, tqdm 4.66                         |
| Serialization      | joblib (model persistence), YAML (config), JSON (output)|
| Testing            | pytest                                                  |
| External Dependency| Wireshark / tshark (system install)                     |

---

## 8. Directory Structure

```
AI_wireshark/
├── config/                   # YAML configuration files
│   ├── default.yaml
│   └── dev.yaml
├── data/
│   ├── raw/                  # Input PCAP files
│   ├── processed/            # Extracted feature CSVs
│   └── external/             # Third-party datasets
├── docs/                     # Documentation
├── logs/                     # Application logs (loguru)
├── models/                   # Saved ML model artifacts (.pkl, .h5)
├── results/                  # Analysis output (JSON, HTML reports)
├── scripts/                  # Standalone utility scripts
│   ├── run_wlan_analysis.py  # WLAN runner (tshark + WLANAnalyzer)
│   ├── analyze_tcp_udp.py    # TCP/UDP application traffic analyser
│   ├── run_ipv6_analysis.py  # IPv6 per-address traffic analysis
│   ├── monitor_capture.sh    # Monitor-mode capture helper (stub)
│   ├── train_model.py
│   ├── evaluate_model.py
│   └── download_data.py
├── src/
│   ├── parsers/              # PCAP ingestion
│   ├── preprocessing/        # Cleaning + feature engineering
│   ├── core/                 # ML model definitions + utilities
│   ├── protocols/            # Rule-based protocol analyzers
│   ├── evaluation/           # Metrics + visualization
│   ├── reports/              # HTML report generation
│   └── api/                  # REST API + CLI
├── tests/                    # Unit tests (pytest)
├── requirements.txt
├── setup.py
└── README.md
```

---

## 9. Key Design Decisions

| Decision                                | Rationale                                                                                      |
|-----------------------------------------|------------------------------------------------------------------------------------------------|
| PyShark over raw Scapy for parsing      | Leverages Wireshark's mature dissectors; Scapy still available for low-level tasks.             |
| Separate protocol analyzer classes      | Each protocol has unique threat signatures; isolation simplifies maintenance and extension.     |
| Unsupervised-first ML approach          | Network traffic is rarely labeled; Isolation Forest and Autoencoder work without labels.        |
| Optional TensorFlow dependency          | Graceful fallback when GPU/TF is unavailable; Isolation Forest alone provides baseline.        |
| YAML-based configuration                | Human-readable, supports per-environment overrides, easy to version-control.                   |
| FastAPI for REST                        | Async support, automatic OpenAPI docs, Pydantic validation, high performance.                  |
| Self-contained HTML reports             | No external hosting needed; Base64-embedded charts make reports portable and shareable.         |
| `loguru` for logging                    | Zero-config structured logging with rotation; simpler than stdlib `logging`.                   |

---

## 10. Security Considerations

- **Input validation:** PCAP file paths are checked for existence before processing. The REST API constrains upload size (`max_upload_size: 100 MB`).
- **Temporary file cleanup:** Uploaded files are removed via FastAPI `BackgroundTasks` after analysis.
- **No credential storage:** The system does not store or transmit credentials.
- **Threat signatures:** HTTP analyzer checks for SQL injection and XSS patterns in captured traffic—these are detection rules, not attack vectors.
- **Dependency pinning:** All dependencies are version-pinned in `requirements.txt` to avoid supply-chain drift.

---

## 11. Extension Points

| Extension                   | How to Add                                                                         |
|-----------------------------|------------------------------------------------------------------------------------|
| New protocol analyzer       | Create `src/protocols/<proto>_analyzer.py` following existing class pattern.        |
| New ML model                | Add class in `src/core/model.py` with `train()`, `predict()`, `save()`, `load()`. |
| New feature category        | Add `_add_<category>_features()` method to `FeatureEngineer`.                     |
| Custom thresholds           | Edit `config/default.yaml` under `protocols` or `models`.                          |
| Additional API endpoints    | Add route handlers in `src/api/rest.py`.                                           |
| New visualization types     | Add plot method to `NetworkVisualizer`.                                             |

---

## 12. Typical Usage Workflows

### Workflow A — Quick Protocol Analysis (CLI)

```bash
python3 src/protocols/tcp_analyzer.py --input capture.pcap --html-report results/tcp.html
```

### Workflow B — Full Multi-Protocol Analysis with Filter (CLI)

```bash
# Analyze all protocols (reports auto-generated in results/)
python3 src/api/cli.py analyze -i capture.pcap -p all -v

# Filter to a specific IP
python3 src/api/cli.py analyze -i capture.pcap -p tcp -f "ip.addr==192.168.1.100"
```

### Workflow C — WLAN Analysis with MAC Filter

```bash
# Using the WLAN script (MAC as 2nd arg; reports auto-generated in results/)
python3 scripts/run_wlan_analysis.py capture.pcapng aa:bb:cc:dd:ee:ff

# Using the CLI with Wireshark display filter
python3 src/api/cli.py analyze-wlan -i capture.pcapng -f "wlan.addr==aa:bb:cc:dd:ee:ff"
```

### Workflow C2 — IPv6 Traffic Analysis

```bash
# Analyse all traffic for a specific IPv6 address — reports auto-generated in results/
python3 scripts/run_ipv6_analysis.py capture.pcapng 2408:8a04:e001:0:faed:fcff:fefe:10c1
```

### Workflow D — API-Driven Analysis

```bash
# Start server
python3 src/api/rest.py

# Upload and analyze
curl -X POST http://localhost:8000/analyze -F "file=@capture.pcap" -F "protocol=tcp"
```

### Workflow E — Model Training & Evaluation

```bash
python3 scripts/train_model.py --data data/processed/features.csv --model-type isolation_forest
python3 scripts/evaluate_model.py --model models/isolation_forest.pkl --data data/processed/test.csv
```

---

*End of Design Document*
