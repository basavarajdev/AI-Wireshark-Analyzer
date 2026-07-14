# Architecture Overview

## System Design

AI-Wireshark-Analyzer is a modular network analysis platform built in Python 3.12. It supports two parallel ingestion paths — **tshark-native** (high-performance subprocess extraction used by all GUI panels and CLI scripts) and **PyShark-based** structured parsing (used by the ML pipeline and protocol analyzers). All analysis is local; no data leaves the machine.

**Version:** 1.7.1  
**Stack:** Python 3.12 · PyQt6 · tshark · scikit-learn · TensorFlow (optional) · FastAPI · pandas · loguru · PyYAML

```
┌──────────────────────────────────────────────────────────────────────┐
│                        PCAP / PCAPNG Input                           │
└──────────────┬───────────────────────────────────┬───────────────────┘
               │                                   │
               ▼  PyShark path                     ▼  tshark-native path
   ┌───────────────────────┐           ┌───────────────────────────────┐
   │   PacketParser        │           │  Analysis Scripts             │
   │   packet_parser.py    │           │  ─────────────────────────    │
   │   ─ PyShark parsing   │           │  run_wlan_analysis.py         │
   │   ─ pandas DataFrame  │           │  analyze_tcp_udp.py           │
   └───────────┬───────────┘           │  run_ipv6_analysis.py         │
               │                       │  run_channel_monitor.py       │
               ▼                       │  build_client_map_report.py   │
   ┌───────────────────────┐           │  build_combined_report.py     │
   │   DataCleaner         │           └───────────────┬───────────────┘
   │   FeatureEngineer     │                           │
   │   (50+ features)      │                           ▼
   └───────────┬───────────┘           ┌───────────────────────────────┐
               │                       │  Protocol / RF Analyzers      │
               ├──────────┐            │  ─────────────────────────    │
               ▼          ▼            │  WLANAnalyzer                 │
   ┌──────────────┐  ┌──────────────┐  │  TCP/UDP Analyzer             │
   │  Protocol    │  │  ML Models   │  │  IPv6 Analyzer                │
   │  Analyzers   │  │  ──────────  │  └───────────────┬───────────────┘
   │  TCP, UDP    │  │  Isolation   │                  │
   │  DNS, HTTP   │  │  Forest      │                  │
   │  HTTPS, ICMP │  │  Autoencoder │                  │
   │  DHCP, WLAN  │  │  (optional)  │                  │
   └──────┬───────┘  └──────┬───────┘                  │
          └────────┬─────────┘                          │
                   ▼                                    ▼
         ┌─────────────────────┐          ┌─────────────────────────┐
         │  HTMLReportGenerator│          │  Inline HTML generators  │
         │  html_generator.py  │          │  (analyze_tcp_udp.py,   │
         │  - severity badges  │          │   run_channel_monitor)  │
         │  - remediation tips │          └─────────────────────────┘
         │  - Base64 charts    │
         └──────────┬──────────┘
                    │
        ┌───────────┴───────────────┐
        ▼           ▼               ▼
  ┌──────────┐ ┌─────────┐  ┌────────────┐
  │ REST API │ │   CLI   │  │ Desktop GUI│
  │ FastAPI  │ │ Click + │  │  PyQt6     │
  │ /analyze │ │ Rich    │  │  9 panels  │
  └──────────┘ └─────────┘  └────────────┘
        │           │               │
        └───────────┴───────────────┘
                    ▼
              results/   (HTML + JSON)
```

---

## Layer-by-Layer Breakdown

### 1. Ingestion Layer

Two parallel paths feed data into the system. The choice of path depends on the analysis type:

| Path | Used by | Why |
|---|---|---|
| **tshark-native** | All GUI panels, all CLI scripts | Zero PyShark overhead; supports large captures; bulk field extraction via subprocess |
| **PyShark** | ML pipeline, `src/protocols/` analyzers, REST API | Structured per-packet object model; integrates with pandas for feature engineering |

#### PacketParser (`src/parsers/packet_parser.py`)

```python
parser = PacketParser()
df = parser.parse_pcap('capture.pcap')            # → raw DataFrame
flow_df = parser.extract_flow_features(df, window=60)  # → flow-aggregated DataFrame
```

- Reads PCAP/PCAPNG via PyShark
- Extracts: protocol, length, src/dst IP, src/dst port, TCP flags, TTL, window size, timestamp, ICMP type
- Produces a pandas DataFrame used by `DataCleaner` → `FeatureEngineer` → ML models

#### tshark Bulk Extraction (scripts path)

Each script calls tshark via subprocess with a specific `-T fields` field list and optional display filter:

| Script | tshark fields extracted | Purpose |
|---|---|---|
| `run_wlan_analysis.py` | 33 WLAN fields (frame type, subtype, SA, DA, TA, RA, BSSID, reason/status codes, RSSI, retry bit, EAPOL fields, SAE fields, CCMP PN (wlan.ccmp.extiv) …) | Full 802.11 diagnostics |
| `analyze_tcp_udp.py` | TCP flags, seq/ack, window size, delta time, stream index | TCP/UDP health metrics |
| `run_ipv6_analysis.py` | IPv6 src/dst, next header, ICMPv6 type, TCP/UDP ports | Per-address IPv6 analysis |
| `run_channel_monitor.py` | 19 radio + WLAN fields (channel, data rate, signal dBm, retry bit, frame type, duration, RTS/CTS, BSSID, SA, DA) | RF channel metrics |

---

### 2. Data Processing Layer

Only used in the PyShark / ML path.

#### DataCleaner (`src/preprocessing/cleaning.py`)

```python
cleaner = DataCleaner()
df = cleaner.clean(df)
```

- Drops duplicate packets
- Fills or drops missing/malformed values
- Validates numeric ranges (ports 0–65535, TTL 0–255, etc.)
- Supports optional time-range and protocol filtering

#### FeatureEngineer (`src/preprocessing/feature_engineering.py`)

```python
engineer = FeatureEngineer()
df_features = engineer.engineer_features(df)   # → 50+ feature columns
X = engineer.get_ml_features(df_features)       # → numeric-only ML matrix
```

Feature categories produced:

| Category | Examples |
|---|---|
| IP-based | `is_private_src`, `same_subnet`, `ip_class` |
| Port-based | `is_privileged_src`, `is_ephemeral_dst`, `port_ratio` |
| Protocol | TCP flag decomposition (`syn`, `ack`, `fin`, `rst`), ICMP type/code |
| Statistical | `packet_size_zscore`, `bytes_per_second`, `inter_arrival_mean` |
| Time-based | `is_business_hours`, `hour_of_day`, `day_of_week` |
| DNS-specific | `domain_entropy`, `subdomain_depth`, `query_length` |
| HTTP-specific | `has_sql_keywords`, `uri_depth`, `suspicious_ua` |

---

### 3. Analysis Layer

#### Protocol Analyzers (`src/protocols/`)

Uniform interface across all analyzers:

```python
analyzer = TCPAnalyzer()
results = analyzer.analyze(pcap_file, display_filter=None)
# Returns: {total_packets, critical_issues, statistics, threats: [{type, severity, evidence, count}]}
```

| Analyzer | Key detections |
|---|---|
| `tcp_analyzer.py` | SYN flood, RST storm, port scan, excessive retransmissions, connection hijacking (seq anomalies), zero-window stalls, data gaps; **port-based app-layer detection**: HTTP threats (SQL injection, XSS, directory traversal, suspicious user agents, HTTP flood) on ports 80/8080, TLS threats (downgrade, handshake failures, HTTPS flood) on ports 443/8443 |
| `udp_analyzer.py` | UDP flood, amplification (response/request size ratio), port scan, fragmentation attacks; **port-based protocol identification**: DNS/53, DHCP/67-68, NTP/123, QUIC/443, SSDP/1900, and more |
| `wlan_analyzer.py` | 40+ IEEE 802.11 reason/status codes, EAPOL stalls, WPA3/SAE failures (anti-clogging, EC group mismatch, Status 30 AP state machine deadlock, stale PTK CCMP PN detection), beacon loss, high retry rate, power-save scans, unprotected data frames, RTS/CTS overhead, NAV abuse |
| `dns_analyzer.py` | Tunneling (entropy + subdomain depth), DGA patterns, cache poisoning, NXDOMAIN flood, amplification |
| `icmp_analyzer.py` | ICMP flood, Ping of Death, Smurf, tunneling (payload analysis), network scanning |
| `dhcp_analyzer.py` | Starvation/exhaustion, rogue DHCP server, lease anomalies |

#### WPA Decryptor (`src/protocols/wlan_decryptor.py`)

- Calls tshark with `-o wlan.enable_decryption:TRUE -o uat:80211_keys:"wpa-pwd,SSID:PASSWORD"` (or `wpa-psk:PMK`)
- Supports WPA2 (4-way EAPOL) and WPA3-SAE (Commit/Confirm + EAPOL)
- Post-decryption inner analysis: DNS queries, HTTP requests, IP endpoints, port summary
- Validates handshake presence; reports security observations

#### RF Channel Monitor (`src/protocols/wlan_rf_monitor.py`)

Core logic behind `run_channel_monitor.py`:

- Extracts 19 radio+WLAN fields per frame into a pandas DataFrame
- Computes per-rolling-window (default 10 s) metrics:
  - `channel_utilization_pct` = active_time / window_duration × 100
  - `throughput_mbps` = data_bytes × 8 / window_duration / 1e6
  - `retry_rate_pct` = retry_frames / total_frames × 100
  - `rts_cts_overhead_pct` = (RTS + CTS) / total_frames × 100
  - `cts_reply_rate` = CTS_count / RTS_count (hidden-node indicator)
- Station spotlight (`--station MAC`) adds:
  - TX/RX throughput, per-window trend charts (Chart.js)
  - Retry rate vs. channel average
  - PHY mode distribution (802.11n/ac/ax)
  - Roaming event detection (BSSID changes)
  - `connection_delay_seconds` — time from first probe-response to first auth frame
  - `scan_cycles` — probe-request groups separated by >3 s gaps
  - `max_nav_us` — max NAV/Duration field (abuse flag if >32 000 µs)
  - `connected_clients_oui_only` — real devices only (IEEE bit 1 = 0)
  - `randomised_macs_filtered` — count of locally-administered MACs excluded

#### ML Models (`src/core/model.py`)

```python
# Isolation Forest (always available)
detector = IsolationForestModel('config/default.yaml')
detector.train(X)                        # or load from models/isolation_forest.pkl
predictions = detector.predict(X)        # 1 = normal, -1 = anomaly
scores = detector.score_samples(X)       # lower = more anomalous

# Autoencoder (requires TensorFlow)
ae = AutoencoderModel('config/default.yaml')
ae.train(X)
recon_errors = ae.detect_anomalies(X)    # reconstruction error per sample
ae.save('models/autoencoder.h5')
```

Model configuration from `config/default.yaml`:

```yaml
models:
  isolation_forest:
    n_estimators: 100
    contamination: 0.1    # expected anomaly fraction
    random_state: 42

  autoencoder:
    encoding_dim: 32
    epochs: 100
    batch_size: 256
    learning_rate: 0.001
```

---

### 4. Reporting Layer

#### HTMLReportGenerator (`src/reports/html_generator.py`)

Used by all `src/protocols/` analyzers and `run_wlan_analysis.py`:

```python
generator = HTMLReportGenerator()
path = generator.generate_report(
    results=results,         # dict from analyzer.analyze()
    pcap_file='capture.pcap',
    output_file='results/report.html',
    protocol='TCP',
)
```

- Fully self-contained HTML (no external CDN/CSS)
- Severity colour coding: `Critical` (red) / `High` (orange) / `Medium` (yellow) / `Low` (blue) / `Info` (grey)
- Embedded Base64 matplotlib/seaborn charts
- `REMEDIATION_GUIDE` — per-threat remediation steps keyed by threat name (covers 20+ threat types)

Inline HTML generators (used by tshark-native scripts):
- `analyze_tcp_udp.py` — self-contained HTML with embedded SVG/bar timeline charts
- `run_channel_monitor.py` — self-contained HTML with Chart.js trend graphs (inline JS, no CDN)

---

### 5. Interface Layer

#### Desktop GUI (`app/`)

```
app/
├── main.py              Entry point; preflight checks (tshark, display, libxcb-cursor0)
├── main_window.py       QMainWindow; sidebar + QStackedWidget panel router
├── styles.py            Dark theme stylesheet (DARK_STYLESHEET constant)
├── resources.py         get_resource_path() — resolves paths in dev + PyInstaller bundle
├── workers.py           AnalysisWorker(QThread) — background task dispatcher
└── panels/
    ├── base_panel.py    BaseAnalysisPanel — common layout; calls AnalysisWorker
    ├── wlan_panel.py    task="wlan"            → scripts.run_wlan_analysis.run()
    ├── decrypt_panel.py task="decrypt"         → src.protocols.wlan_decryptor
    ├── channel_panel.py task="channel_monitor" → scripts.run_channel_monitor.run()
    │                    task="client_map"      → scripts.build_client_map_report.run()
    │                    task="combined_report" → scripts.build_combined_report.run()
    ├── tcp_udp_panel.py task="tcp_udp"         → scripts.analyze_tcp_udp.run()
    ├── ipv6_panel.py    task="ipv6"            → scripts.run_ipv6_analysis.run()
    ├── protocol_panel.py task="protocol"       → src.api.cli._run_protocol_analysis()
    ├── anomaly_panel.py  task="anomaly"        → PacketParser → FeatureEngineer → IsolationForest/Autoencoder
    ├── home_panel.py    Clickable feature cards; navigates sidebar
    └── cli_info_panel.py In-app CLI command reference
```

**AnalysisWorker dispatch (`app/workers.py`):**

```python
worker = AnalysisWorker(task="wlan", params={"pcap": "/path/to/capture.pcap", "mac": None})
worker.progress.connect(status_bar.showMessage)
worker.finished.connect(panel.on_results)
worker.error.connect(panel.on_error)
worker.start()
```

Signal contract:
- `progress(str)` — status message updates
- `finished(dict)` — results dict containing `html_path`, `json_data`, `stdout`, `stderr`
- `error(str)` — exception traceback as string

#### REST API (`src/api/rest.py`)

```bash
python src/api/rest.py        # starts on http://localhost:8000
```

Endpoints:

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Health check |
| `GET` | `/health` | Health check with version |
| `GET` | `/models` | List available ML models |
| `GET` | `/protocols` | List supported protocols |
| `POST` | `/analyze` | Upload PCAP + run protocol analysis |
| `POST` | `/detect-anomalies` | Upload PCAP + run ML anomaly detection |

Interactive docs: `http://localhost:8000/docs` (Swagger UI) · `http://localhost:8000/redoc`

#### CLI (`src/api/cli.py`)

```bash
python -m src.api.cli [COMMAND] [OPTIONS]
```

| Command | Key options |
|---|---|
| `analyze` | `-i FILE` `-p PROTOCOL` `-f DISPLAY_FILTER` `-v` `--output-dir` |
| `analyze-wlan` | `-i FILE` `-f WLAN_FILTER` |
| `detect-anomalies` | `-i FILE` `-m MODEL` `-o OUTPUT_JSON` |
| `visualize` | `-i FILE` `-o OUTPUT_DIR` |
| `info` | (no options) — lists protocols and models |

---

## Complete Data Flow Diagrams

### GUI Panel → Analysis → Result

```
User selects file + clicks Run
        │
        ▼
BaseAnalysisPanel._validate() + _get_params()
        │
        ▼
AnalysisWorker(task, params).start()     ← QThread (non-blocking)
        │
        ├── task="wlan"          → scripts.run_wlan_analysis.run(pcap, mac_filter)
        │                              └─ tshark subprocess (32 fields)
        │                              └─ WLANAnalyzer.analyze()
        │                              └─ HTMLReportGenerator.generate_report()
        │                              └─ returns {html_path, json_path}
        │
        ├── task="decrypt"       → wlan_decryptor.decrypt_and_analyze(pcap, key_type, key, ssid, mac)
        │                              └─ tshark -o wlan.enable_decryption:TRUE ...
        │                              └─ inner traffic analysis (DNS, HTTP, endpoints)
        │
        ├── task="channel_monitor" → run_channel_monitor.run(pcap, channel, bssid, mac, station, interval)
        │                              └─ tshark (19 fields) → pandas → rolling windows
        │                              └─ station spotlight (if --station)
        │                              └─ Chart.js HTML + JSON
        │
        ├── task="tcp_udp"       → analyze_tcp_udp.run(pcap, output_html)
        │                              └─ tshark targeted queries → metric dicts
        │                              └─ inline HTML with timeline bar charts
        │
        ├── task="ipv6"          → run_ipv6_analysis.run(pcap, ipv6_address)
        │                              └─ tshark per-protocol queries
        │                              └─ ICMPv6/NDP/TCP/UDP/SNMP breakdown
        │
        ├── task="protocol"      → cli._run_protocol_analysis(pcap, protocol, display_filter)
        │                              └─ ProtocolAnalyzer().analyze(pcap, display_filter)
        │                              └─ HTMLReportGenerator → HTML + JSON
        │
        └── task="anomaly"       → PacketParser → DataCleaner → FeatureEngineer
                                       └─ IsolationForestModel or AutoencoderModel
                                       └─ anomaly scores per packet
                                       └─ returns {json_data: {scores, anomalies, stats}}
        │
        ▼
AnalysisWorker.finished.emit({html_path, json_data})
        │
        ▼
BaseAnalysisPanel.on_results() → renders HTML in QWebEngineView or shows JSON summary
```

### ML Anomaly Detection Pipeline (detail)

```
PCAP
  │
  ▼
PacketParser.parse_pcap()
  → protocol, length, src_ip, dst_ip, src_port, dst_port,
    tcp_flags, ttl, window_size, timestamp  [raw DataFrame]
  │
  ▼
DataCleaner.clean()
  → deduplicate, fill missing, validate ranges  [cleaned DataFrame]
  │
  ▼
FeatureEngineer.engineer_features()
  → 50+ engineered columns
  │
FeatureEngineer.get_ml_features()
  → numeric-only matrix X  [shape: n_packets × n_features]
  │
  ├─ IsolationForestModel
  │    train(X) or load('models/isolation_forest.pkl')
  │    predict(X)       → [-1, 1, 1, -1, …]   (-1 = anomaly)
  │    score_samples(X) → [-0.3, 0.1, …]       (lower = more anomalous)
  │
  └─ AutoencoderModel  (requires TensorFlow)
       train(X)
       detect_anomalies(X) → reconstruction error per sample
       threshold = mean + 2×std of training errors
  │
  ▼
results/{pcap_stem}_anomaly.json
  → {total_packets, anomalies_detected, anomaly_rate,
     model_type, scores: {min, max, mean, std}, top_anomalies: […]}
```

### tshark-native Channel Survey Pipeline (detail)

```
PCAP + optional args (channel, bssid, mac, station, interval)
  │
  ▼
tshark subprocess: -T fields -e wlan.fc.type -e wlan_radio.channel
                   -e wlan_radio.signal_dbm -e wlan.sa -e wlan.da
                   -e wlan.bssid -e wlan.fc.retry -e frame.len
                   -e frame.time_epoch -e wlan.duration ... (19 fields)
  │
  ▼
pandas DataFrame → filter by channel/bssid/mac if supplied
  │
  ▼
Per-rolling-window (default 10 s) computation:
  ├── channel_utilization_pct
  ├── throughput_mbps
  ├── retry_rate_pct
  ├── rts_cts_overhead_pct   = (RTS + CTS) / total_frames × 100
  ├── cts_reply_rate         = CTS_count / RTS_count
  ├── per-BSSID frame counts
  └── per-client frame counts  (OUI-assigned MACs only)
  │
  ├── [if --station MAC]
  │     compute_station_profile()
  │       → TX/RX throughput, retry vs avg, airtime share
  │       → roaming events (BSSID changes)
  │       → PHY mode distribution
  │     compute_station_windows()
  │       → per-window trend data for Chart.js
  │     enhanced metrics:
  │       → connection_delay_seconds
  │       → scan_cycles
  │       → max_nav_us + abuse_flag
  │       → connected_clients_oui_only
  │       → randomised_macs_filtered
  │
  ▼
JSON output → results/{prefix}_channel_monitor.json
HTML output → results/{prefix}_channel_monitor.html  (self-contained, Chart.js inline)
  │
  ▼ [optional report builders]
build_client_map_report.py(client_network_map.json)
  → BSSID cluster detection (same OUI, seq MACs ≤ 8 apart)
  → multi-channel SSID mapping
  → client_network_map.html

build_combined_report.py(client_network_map.json, --channel-jsons-dir)
  → channel health score (0–100) per channel
  → spark bars + issue badges
  → comprehensive_network_report.html
```

---

## Directory Reference

```
AI-Wireshark-Analyzer/
├── app/                     Desktop GUI (PyQt6)
│   ├── main.py              Entry point + Linux preflight checks
│   ├── main_window.py       Sidebar navigation + panel stack
│   ├── workers.py           AnalysisWorker(QThread) — all task dispatch
│   ├── styles.py            Dark stylesheet constant
│   ├── resources.py         Bundle-safe path resolution
│   ├── panels/              Nine analysis panels
│   └── widgets/             FileSelector, MacAddressInput, ResultsView
│
├── src/                     Analysis engine
│   ├── parsers/
│   │   └── packet_parser.py PyShark-based ingestion → DataFrame
│   ├── preprocessing/
│   │   ├── cleaning.py      Dedup, validate, filter
│   │   └── feature_engineering.py  50+ ML features
│   ├── protocols/
│   │   ├── wlan_analyzer.py         802.11 diagnostics
│   │   ├── wlan_decryptor.py        WPA2/WPA3 decryption
│   │   ├── wlan_rf_monitor.py       Channel RF metrics
│   │   ├── tcp_analyzer.py          TCP + HTTP/HTTPS port-based app-layer analysis
│   │   ├── udp_analyzer.py          UDP + DNS/NTP/DHCP/QUIC port identification
│   │   ├── dns_analyzer.py
│   │   ├── icmp_analyzer.py
│   │   └── dhcp_analyzer.py
│   ├── core/
│   │   ├── model.py         IsolationForest, Autoencoder, RandomForest
│   │   └── utils.py
│   ├── preprocessing/
│   ├── evaluation/
│   │   ├── metrics.py       Accuracy, F1, ROC-AUC, confusion matrix
│   │   └── visualization.py matplotlib/seaborn charts
│   ├── reports/
│   │   └── html_generator.py  Shared HTML report engine
│   └── api/
│       ├── rest.py          FastAPI server
│       └── cli.py           Click + Rich CLI
│
├── scripts/                 tshark-native analysis scripts
│   ├── run_wlan_analysis.py
│   ├── run_channel_monitor.py
│   ├── analyze_tcp_udp.py
│   ├── run_ipv6_analysis.py
│   ├── build_client_map_report.py
│   ├── build_combined_report.py
│   ├── train_model.py
│   └── evaluate_model.py
│
├── config/
│   ├── default.yaml         Model params, API settings, feature config
│   └── dev.yaml             Development overrides
│
├── installer/
│   ├── ai_wireshark_linux.spec   PyInstaller spec (Linux x86_64)
│   ├── ai_wireshark.spec         PyInstaller spec (Windows/generic)
│   ├── build.sh                  Linux build script
│   └── app_icon.png / .ico
│
├── tests/
│   ├── test_models.py
│   ├── test_parser.py
│   └── test_preprocessing.py
│
├── results/                 Generated HTML + JSON reports (runtime)
├── data/raw/                PCAP capture files (not committed)
└── models/                  Saved ML models — .pkl, .h5 (not committed)
```

---

## Security Design

| Concern | Implementation |
|---|---|
| File input validation | Extension check (`.pcap`, `.pcapng`); max upload size 100 MB in REST API |
| Temp file cleanup | `BackgroundTasks.add_task(os.unlink, tmp_path)` after every API request |
| No credential storage | WPA passwords are passed directly to tshark subprocess; never written to disk or logs |
| Local-only processing | No telemetry; no network calls during analysis; all results written to `results/` only |
| Input sanitization | Display filters passed to tshark as arguments, not shell-interpolated |
| ML model loading | `joblib.load()` with path validation; no arbitrary deserialization |

---

## Runtime Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| CPU cores | 2 | 4+ |
| RAM | 4 GB | 8 GB+ |
| Disk | 10 GB | 50 GB+ |
| Python | 3.10+ | 3.12 |
| tshark | 3.x | 4.2+ |
| OS (binary) | Linux x86_64 Ubuntu 20.04+ | same |

---

## v1.7.x Architecture Changes

### Dynamic Report Engine (`src/reports/html_generator.py`)

**v1.7.1** replaced all static `REMEDIATION_GUIDE` fallbacks with a new `_build_threat_rca_html()` helper method. For 25+ threat types it extracts actual IPs, rates, and counts from the threat dict and produces a two-part dynamic block:

1. **Root Cause Analysis box** (blue) — specific findings from the capture (e.g., scanner IPs, SYN rate)
2. **Specific Recommendations box** (green) — numbered remediation steps referencing actual IPs/rates

Threat ordering now uses a two-key sort `(severity, type_order)` where connection-related threats (type_order=0) always precede RF-statistical findings (type_order=2) within the same severity tier.

### WLANRFMonitor (`src/protocols/wlan_rf_monitor.py`)

`detect_high_retry()` now returns per-AP (`high_retry_bssids`) and per-channel (`high_retry_channels`) breakdowns in addition to the overall rate. This feeds the dynamic report to show which specific AP or channel is the source of the retry problem.

### Threat Gating

WPA3-SAE advisory notices (successful handshake confirmations) are no longer surfaced as threats. `_detect_wpa3_sae_failures()` now only sets `detected=True` when `failure_counts` or `sae_sessions` are non-empty — purely informational advisory notices are retained in `wpa3_network_detected` metadata but excluded from the Threat Overview.

### TShark Crash Resilience

All direct `pyshark.FileCapture` usages (DHCP, WLAN analyzers) now wrap packet iteration in try/except, use `keep_packets=False`, and avoid `use_json=True`/`include_raw=True`. The `PacketParser.parse_pcap()` method also catches mid-iteration TShark process exits (retcode 255) and continues with whatever packets were successfully parsed.


---

## Extension Points

1. **Add a protocol analyzer** — create `src/protocols/<name>_analyzer.py` implementing `analyze(pcap_file, display_filter=None) -> dict`; register in `cli.py` `analyzers` dict and REST `/analyze` handler.

2. **Add an ML model** — add class in `src/core/model.py` with `train(X)` / `predict(X)` / `save()` / `load()` interface; add config keys to `config/default.yaml`; wire up in `AnomalyPanel` and `workers.py`.

3. **Add a GUI panel** — subclass `BaseAnalysisPanel`; implement `_build_inputs()`, `_validate()`, `_get_params()`; add a new task handler in `AnalysisWorker.run()`; register in `main_window.py` nav_items list.

4. **Add a CLI script** — follow `run_wlan_analysis.py` pattern: tshark extraction → analysis → `html_generator.py`; expose a `run(pcap, ..., output_dir) -> dict` function for GUI worker integration.

---

## Dependencies

| Category | Library | Version |
|---|---|---|
| GUI | PyQt6, PyQt6-WebEngine | 6.x |
| Packet parsing | PyShark | 0.6 |
| Data | pandas, numpy, scipy | latest |
| ML | scikit-learn | 1.3+ |
| ML (optional) | TensorFlow/Keras | 2.13+ |
| API | FastAPI, uvicorn | latest |
| CLI | Click, Rich | 8.x |
| Visualization | matplotlib, seaborn | latest |
| Logging | loguru | latest |
| Config | PyYAML | latest |
| Build | PyInstaller | 6.x |
| Testing | pytest | latest |
