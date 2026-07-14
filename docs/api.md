# API Reference

This document covers all programmatic interfaces: REST API, CLI, analysis scripts, and the Python module API.

---

## REST API

### Start the Server

```bash
python src/api/rest.py
# Starts on http://localhost:8000
```

Interactive docs:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

### Endpoints

#### `GET /health` — Health check

```bash
curl http://localhost:8000/health
```

```json
{ "status": "healthy", "version": "1.0.0" }
```

---

#### `GET /models` — List available ML models

```bash
curl http://localhost:8000/models
```

```json
[
  { "name": "isolation_forest", "type": "anomaly_detection", "available": true },
  { "name": "autoencoder",      "type": "anomaly_detection", "available": true }
]
```

Saved models (`.pkl`, `.h5`) in the `models/` directory are also listed dynamically.

---

#### `GET /protocols` — List supported protocols

```bash
curl http://localhost:8000/protocols
```

```json
{
  "protocols": ["tcp", "udp", "dns", "http", "https", "icmp", "dhcp"],
  "description": "Supported protocols for analysis"
}
```

---

#### `POST /analyze` — Analyze a PCAP file

```bash
curl -X POST http://localhost:8000/analyze \
  -F "file=@capture.pcap" \
  -F "protocol=tcp" \
  -F "display_filter=ip.addr==192.168.1.1"
```

**Form fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `file` | multipart | yes | `.pcap` or `.pcapng` file |
| `protocol` | string | no | One of: `tcp`, `udp`, `dns`, `http`, `https`, `icmp`, `dhcp` |
| `display_filter` | string | no | Wireshark display filter (e.g. `ip.addr==10.0.0.1`, `tcp.port==443`) |

**Response:**

```json
{
  "filename": "capture.pcap",
  "total_packets": 12543,
  "protocols": {
    "TCP": 9800,
    "UDP": 2100,
    "ICMP": 643
  },
  "protocol_analysis": {
    "total_packets": 9800,
    "critical_issues": 2,
    "statistics": { "syn_count": 450, "rst_count": 12, "retransmission_rate": 0.04 },
    "threats": [
      {
        "type": "syn_flood",
        "severity": "Critical",
        "count": 320,
        "evidence": "SYN rate 320/s from 10.0.0.5 exceeds threshold"
      }
    ]
  }
}
```

Error responses:
- `400` — invalid file type or no packets found
- `500` — analysis error (message included in `detail`)

---

#### `POST /detect-anomalies` — ML anomaly detection

```bash
curl -X POST http://localhost:8000/detect-anomalies \
  -F "file=@capture.pcap" \
  -F "model_type=isolation_forest"
```

**Form fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `file` | multipart | yes | `.pcap` or `.pcapng` file |
| `model_type` | string | no | `isolation_forest` (default) or `autoencoder` |

**Pipeline executed:**
1. `PacketParser.parse_pcap()` → DataFrame
2. `DataCleaner.clean()` → cleaned DataFrame
3. `FeatureEngineer.engineer_features()` → 50+ feature matrix
4. Model `.train(X)` (or `.load()` if `models/<name>.pkl` exists) → `.predict(X)` + `.score_samples(X)`

**Response:**

```json
{
  "filename": "capture.pcap",
  "total_packets": 12543,
  "anomalies_detected": 187,
  "anomaly_rate": 0.015,
  "model_type": "isolation_forest",
  "anomaly_scores": {
    "min": -0.62,
    "max": 0.41,
    "mean": 0.09,
    "std": 0.18
  }
}
```

---

## CLI

### Install (editable / source mode)

```bash
pip install -e .
```

### Entry point

```bash
python -m src.api.cli [COMMAND] [OPTIONS]
# or after pip install -e .:
ai-wireshark [COMMAND] [OPTIONS]
```

---

### `analyze` — Protocol analysis

```bash
ai-wireshark analyze -i capture.pcap [OPTIONS]
```

| Option | Short | Default | Description |
|---|---|---|---|
| `--input` | `-i` | required | Input PCAP/PCAPNG file |
| `--protocol` | `-p` | `all` | `tcp`, `udp`, `dns`, `http`, `https`, `icmp`, `dhcp`, or `all` |
| `--filter` | `-f` | none | Wireshark display filter |
| `--visualize` | `-v` | off | Generate matplotlib charts |
| `--output-dir` | | `results` | Output directory |

Output files (auto-named from pcap stem):
- `results/<stem>.json` — full results JSON
- `results/<stem>_report.html` — self-contained HTML report

**Examples:**

```bash
# Analyze all protocols
ai-wireshark analyze -i capture.pcap

# TCP-only with IP filter
ai-wireshark analyze -i capture.pcap -p tcp -f "ip.addr==192.168.1.1"

# UDP with source filter + visualizations
ai-wireshark analyze -i capture.pcap -p udp -f "ip.src==10.0.0.5" -v

# DNS analysis
ai-wireshark analyze -i capture.pcap -p dns
```

---

### `analyze-wlan` — WLAN analysis

```bash
ai-wireshark analyze-wlan -i capture.pcapng [OPTIONS]
```

| Option | Short | Description |
|---|---|---|
| `--input` | `-i` | Input PCAP/PCAPNG file (required) |
| `--filter` | `-f` | WLAN display filter (e.g. `wlan.addr==aa:bb:cc:dd:ee:ff`) |

Output: `results/<stem>_wlan.json` + `results/<stem>_wlan.html`

```bash
# Full WLAN analysis
ai-wireshark analyze-wlan -i wifi_capture.pcapng

# Scoped to one device
ai-wireshark analyze-wlan -i wifi_capture.pcapng -f "wlan.sa==c8:5a:cf:66:2e:1e"
```

---

### `detect-anomalies` — ML anomaly detection

```bash
ai-wireshark detect-anomalies -i capture.pcap [OPTIONS]
```

| Option | Short | Default | Description |
|---|---|---|---|
| `--input` | `-i` | required | Input PCAP/PCAPNG file |
| `--model` | `-m` | `isolation_forest` | `isolation_forest` or `autoencoder` |
| `--output` | `-o` | auto | Output JSON file path |

```bash
ai-wireshark detect-anomalies -i capture.pcap -m isolation_forest
ai-wireshark detect-anomalies -i capture.pcap -m autoencoder -o results/anomalies.json
```

---

### `visualize` — Generate charts

```bash
ai-wireshark visualize -i capture.pcap [-o OUTPUT_DIR]
```

Produces: protocol distribution, traffic timeline, packet size distribution, anomaly score histogram.

---

### `info` — System information

```bash
ai-wireshark info
```

Prints supported protocols and available ML models.

---

## Analysis Scripts (tshark-native)

These scripts bypass PyShark entirely — they call tshark via subprocess for maximum performance on large captures. Each exposes a `run(..., output_dir) -> dict` function used by the GUI workers.

### `scripts/run_wlan_analysis.py`

```bash
python3 scripts/run_wlan_analysis.py <pcap_file> [mac_filter]
```

| Argument | Description |
|---|---|
| `pcap_file` | `.pcap` / `.pcapng` input (required) |
| `mac_filter` | Optional client MAC — matches SA, DA, TA, RA, BSSID |

**What it extracts (32 tshark fields):**
frame type/subtype, SA, DA, TA, RA, BSSID, reason code, status code, RSSI, retry bit, EAPOL type/key flags, SAE group/commit/confirm, duration, seq number, signal, data rate, timestamp.

**Output:** `results/<stem>_wlan.json` + `results/<stem>_wlan.html`

```bash
python3 scripts/run_wlan_analysis.py capture.pcapng
python3 scripts/run_wlan_analysis.py capture.pcapng c8:5a:cf:66:2e:1e
```

---

### `scripts/analyze_tcp_udp.py`

```bash
python3 scripts/analyze_tcp_udp.py <pcap_file> [output_html]
```

- Pure tshark analysis; no PyShark, no pandas
- Auto-detects application stream on ports 9100, 631, 515
- Generates timeline bar charts for zero-window events and RST bursts
- Detects QUIC traffic

**Output:** `results/<stem>_tcp_udp.html`

```bash
python3 scripts/analyze_tcp_udp.py capture.pcap
python3 scripts/analyze_tcp_udp.py capture.pcap results/my_report.html
```

---

### `scripts/run_ipv6_analysis.py`

```bash
python3 scripts/run_ipv6_analysis.py <pcap_file> <ipv6_address>
```

- Per-address analysis: TCP connections, retransmissions, RST events, port probes
- UDP flows, SNMP community strings, ICMPv6 types, NDP messages
- Generates self-contained HTML with charts

**Output:** `results/<stem>_ipv6_<addr>.json` + `results/<stem>_ipv6_<addr>.html`

```bash
python3 scripts/run_ipv6_analysis.py capture.pcapng 2001:db8::1
```

---

### `scripts/run_channel_monitor.py`

```bash
python3 scripts/run_channel_monitor.py --pcap <file> [OPTIONS]
```

| Option | Short | Default | Description |
|---|---|---|---|
| `--pcap` | `-r` | required* | Input PCAP/PCAPNG file |
| `--iface` | `-i` | — | Live monitor-mode interface (e.g. `wlan0mon`) |
| `--channel` | `-c` | all | Channel number (1–165) |
| `--bssid` | `-b` | all | BSSID filter |
| `--mac` | `-m` | all | Client MAC filter |
| `--station` | `-s` | — | Station MAC for spotlight profile |
| `--out` | `-o` | `results/channel_monitor` | Output file prefix |
| `--interval` | | 10 | Rolling window size (seconds) |
| `--quiet` | `-q` | off | Suppress terminal output |
| `--duration` | `-d` | 300 | Live capture duration (seconds) |

*Either `--pcap` or `--iface` is required.

**Core output metrics (JSON + HTML):**

| Metric | Description |
|---|---|
| `channel_utilization_pct` | % of window time the channel was active |
| `throughput_mbps` | Data throughput in Mbps per window |
| `retry_rate_pct` | % of data frames with retry bit set |
| `rts_cts_overhead_pct` | `(RTS+CTS) / total_frames × 100` — control overhead |
| `cts_reply_rate` | `CTS / RTS` — hidden-node indicator (<1.0 = issue) |
| `max_nav_us` | Max Duration/NAV field in µs; abuse flag if >32 000 |
| `connected_clients_oui_only` | Real device count (OUI-assigned MACs only) |
| `randomised_macs_filtered` | Excluded locally-administered MACs |

**Station spotlight additional metrics (`--station MAC`):**

| Metric | Description |
|---|---|
| `connection_delay_seconds` | Time: first probe-response → first auth frame |
| `scan_cycles` | Probe-request groups separated by >3 s gaps |
| `tx_throughput_mbps` | Station TX throughput per window |
| `rx_throughput_mbps` | Station RX throughput per window |
| `retry_vs_channel_avg` | Station retry rate vs. channel average |
| `phy_modes` | Distribution of 802.11n/ac/ax frames |
| `roaming_events` | BSSID change count |

```bash
# File analysis, all channels
python3 scripts/run_channel_monitor.py --pcap capture.pcapng

# Channel 6 with station spotlight
python3 scripts/run_channel_monitor.py \
  --pcap capture.pcapng --channel 6 \
  --station f8:ed:fc:7d:97:6f \
  --out results/ch6_station

# Live capture on wlan0mon, 120 seconds
python3 scripts/run_channel_monitor.py --iface wlan0mon --channel 11 --duration 120
```

**Output:** `<prefix>_channel_monitor.json` + `<prefix>_channel_monitor.html`

---

### `scripts/build_client_map_report.py`

```bash
python3 scripts/build_client_map_report.py <client_network_map.json> [--output-dir DIR]
```

- Reads per-channel JSON survey data
- Detects virtual BSSID clusters (same OUI, sequential MACs ≤ 8 apart)
- Maps multi-channel SSIDs and cross-channel client roaming
- Generates per-channel AP and client tables

**Output:** `<output-dir>/client_network_map.html`

---

### `scripts/build_combined_report.py`

```bash
python3 scripts/build_combined_report.py <client_network_map.json> \
  [--channel-jsons-dir DIR] \
  [--output-dir DIR]
```

- Merges RF metrics from per-channel monitor JSONs with client map data
- Channel health scoring (0–100) with spark bars and issue badges
- Per-channel metric cards, AP table, client table

**Output:** `<output-dir>/comprehensive_network_report.html`

---

## Python Module API

### PacketParser

```python
from src.parsers.packet_parser import PacketParser

parser = PacketParser()
df = parser.parse_pcap('capture.pcap')           # → raw DataFrame
flow_df = parser.extract_flow_features(df, window=60)  # → flow-aggregated DataFrame
```

Fields in raw DataFrame: `timestamp`, `protocol`, `length`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `tcp_flags`, `ttl`, `window_size`, `icmp_type`, `icmp_code`

---

### DataCleaner

```python
from src.preprocessing.cleaning import DataCleaner

cleaner = DataCleaner()
df_clean = cleaner.clean(df)
# Drops duplicates, fills/drops malformed values, validates numeric ranges
```

---

### FeatureEngineer

```python
from src.preprocessing.feature_engineering import FeatureEngineer

engineer = FeatureEngineer()
df_features = engineer.engineer_features(df_clean)  # → 50+ feature columns
X = engineer.get_ml_features(df_features)            # → numeric-only matrix
```

---

### IsolationForestModel

```python
from src.core.model import IsolationForestModel

model = IsolationForestModel('config/default.yaml')

# Train on new data
model.train(X)

# Or load previously saved model
model.load('models/isolation_forest.pkl')

# Predict: 1 = normal, -1 = anomaly
predictions = model.predict(X)

# Anomaly scores: lower value = more anomalous
scores = model.score_samples(X)

# Persist
model.save('models/isolation_forest.pkl')
```

Config keys (`config/default.yaml`):
```yaml
models:
  isolation_forest:
    n_estimators: 100
    contamination: 0.1
    random_state: 42
```

---

### AutoencoderModel

```python
from src.core.model import AutoencoderModel  # requires TensorFlow

ae = AutoencoderModel('config/default.yaml')
ae.train(X)                         # builds and trains encoder-decoder network
errors = ae.detect_anomalies(X)     # reconstruction error per sample (float array)
# threshold = mean + 2×std of training errors
ae.save('models/autoencoder.h5')
ae.load('models/autoencoder.h5')
```

Config keys:
```yaml
models:
  autoencoder:
    encoding_dim: 32
    epochs: 100
    batch_size: 256
    learning_rate: 0.001
```

---

### Protocol Analyzers

```python
from src.protocols.tcp_analyzer import TCPAnalyzer
from src.protocols.wlan_analyzer import WLANAnalyzer
# ... same pattern for all analyzers

analyzer = TCPAnalyzer()
results = analyzer.analyze('capture.pcap', display_filter='ip.addr==10.0.0.1')
```

**Return schema:**

```json
{
  "total_packets": 9800,
  "critical_issues": 2,
  "statistics": {
    "syn_count": 450,
    "rst_count": 12,
    "retransmission_rate": 0.04
  },
  "threats": [
    {
      "type": "syn_flood",
      "severity": "Critical",
      "count": 320,
      "evidence": "SYN rate 320/s from 10.0.0.5 exceeds threshold of 100/s"
    }
  ]
}
```

Severity levels: `Critical` · `High` · `Medium` · `Low` · `Info`

---

### HTMLReportGenerator

```python
from src.reports.html_generator import HTMLReportGenerator

generator = HTMLReportGenerator()
output_path = generator.generate_report(
    results=results,              # dict from analyzer.analyze()
    pcap_file='capture.pcap',
    output_file='results/report.html',
    protocol='TCP',
)
```

Reports are fully self-contained HTML (no CDN, no external JS/CSS). Charts are embedded as Base64 PNG. Each threat type has a corresponding remediation section from `REMEDIATION_GUIDE`.

Covered threat types in remediation guide:
`syn_flood`, `rst_storm`, `port_scanning`, `excessive_retransmissions`, `connection_hijacking`, `udp_flood`, `dns_tunneling`, `http_injection`, `icmp_flood`, `tls_downgrade`, `dhcp_starvation`, and more (20+ total).

---

### NetworkVisualizer

```python
from src.evaluation.visualization import NetworkVisualizer

viz = NetworkVisualizer()
viz.plot_protocol_distribution(df, save_path='results/protocols.png')
viz.plot_traffic_timeline(df, save_path='results/timeline.png')
viz.plot_anomaly_scores(scores, save_path='results/anomalies.png')
viz.create_analysis_report(df, output_dir='results/')
```

---

### AnalysisWorker (GUI background thread)

```python
from app.workers import AnalysisWorker

worker = AnalysisWorker(
    task='wlan',
    params={'pcap': '/path/to/capture.pcap', 'mac': None}
)
worker.progress.connect(lambda msg: print(msg))
worker.finished.connect(lambda result: print(result['html_path']))
worker.error.connect(lambda err: print(err))
worker.start()
```

**Supported task names and required params:**

| Task | Required params | Optional params |
|---|---|---|
| `wlan` | `pcap` | `mac` |
| `decrypt` | `pcap`, `key_type`, `key` | `ssid`, `mac` |
| `tcp_udp` | `pcap` | `output` |
| `ipv6` | `pcap`, `ipv6_address` | — |
| `channel_monitor` | `pcap` | `channel`, `bssid`, `mac`, `station`, `interval`, `output` |
| `client_map` | `json_path` | `output_dir` |
| `combined_report` | `json_path` | `channel_jsons_dir`, `output_dir` |
| `protocol` | `pcap`, `protocol` | `filter`, `html_output` |
| `anomaly` | `pcap` | `model_type` (`isolation_forest` or `autoencoder`) |

**Signal contract:**

| Signal | Payload | Description |
|---|---|---|
| `progress(str)` | Status message | Emitted during analysis for status bar updates |
| `finished(dict)` | `{html_path, json_data, stdout, stderr}` | Emitted on successful completion |
| `error(str)` | Exception traceback | Emitted on any unhandled exception |

**Example:**
```bash
curl -X POST "http://localhost:8000/analyze" \
  -F "file=@traffic.pcap" \
  -F "protocol=tcp"
```

**Response:**
```json
{
  "filename": "traffic.pcap",
  "total_packets": 5000,
  "protocols": {
    "TCP": 3000,
    "UDP": 1500,
    "ICMP": 500
  },
  "protocol_analysis": {
    "statistics": {...},
    "threats": {...}
  }
}
```

#### Detect Anomalies

```http
POST /detect-anomalies
```

**Parameters:**
- `file` (multipart/form-data): PCAP file to analyze
- `model_type` (optional): Model to use (`isolation_forest` or `autoencoder`)

**Example:**
```bash
curl -X POST "http://localhost:8000/detect-anomalies" \
  -F "file=@traffic.pcap" \
  -F "model_type=isolation_forest"
```

**Response:**
```json
{
  "filename": "traffic.pcap",
  "total_packets": 5000,
  "anomalies_detected": 150,
  "anomaly_rate": 0.03,
  "model_type": "isolation_forest",
  "anomaly_scores": {
    "min": -0.5,
    "max": 0.8,
    "mean": 0.12,
    "std": 0.23
  }
}
```

#### List Supported Protocols

```http
GET /protocols
```

**Response:**
```json
{
  "protocols": ["tcp", "udp", "dns", "http", "https", "icmp"],
  "description": "Supported protocols for analysis"
}
```

## CLI Reference

### Installation

```bash
pip install -e .
```

### Commands

#### Analyze PCAP File

```bash
ai-wireshark analyze --input traffic.pcap [OPTIONS]
```

**Options:**
- `--input, -i`: Input PCAP file (required)
- `--protocol, -p`: Protocol to analyze (tcp, udp, dns, http, https, icmp, all)
- `--filter, -f`: Wireshark display filter (e.g. `ip.addr==192.168.1.1`, `ip.src==10.0.0.5`, `tcp.port==443`)
- `--visualize, -v`: Generate visualizations
- `--output-dir`: Output directory for results (default: results)

JSON and HTML reports are always generated automatically in `--output-dir` with filenames derived from the pcap name.

**Examples:**
```bash
# Basic analysis (reports auto-generated in results/)
ai-wireshark analyze -i traffic.pcap -p tcp -v

# With IP filter
ai-wireshark analyze -i traffic.pcap -p tcp -f "ip.addr==192.168.1.1"

# Filter by source IP
ai-wireshark analyze -i traffic.pcap -f "ip.src==10.0.0.5"
```

#### Detect Anomalies

```bash
ai-wireshark detect-anomalies --input traffic.pcap [OPTIONS]
```

**Options:**
- `--input, -i`: Input PCAP file (required)
- `--model, -m`: Model type (isolation_forest, autoencoder)
- `--output, -o`: Output JSON file (optional)

**Example:**
```bash
ai-wireshark detect-anomalies -i traffic.pcap -m isolation_forest -o anomalies.json
```

#### Generate Visualizations

```bash
ai-wireshark visualize --input traffic.pcap [OPTIONS]
```

**Options:**
- `--input, -i`: Input PCAP file (required)
- `--output-dir, -o`: Output directory (default: results/visualizations)

**Example:**
```bash
ai-wireshark visualize -i traffic.pcap -o my_visualizations/
```

#### System Information

```bash
ai-wireshark info
```

Displays supported protocols and available models.

#### Analyze WLAN/WiFi Traffic

```bash
ai-wireshark analyze-wlan --input capture.pcapng [OPTIONS]
```

**Options:**
- `--input, -i`: Input PCAP/PCAPNG file (required)
- `--filter, -f`: Wireshark display filter for WLAN (e.g. `wlan.addr==aa:bb:cc:dd:ee:ff`, `wlan.sa==aa:bb:cc:dd:ee:ff`)

JSON and HTML reports are always generated automatically in `results/`.

**Examples:**
```bash
# Full WLAN analysis
ai-wireshark analyze-wlan -i capture.pcapng

# Filter to a specific MAC address
ai-wireshark analyze-wlan -i capture.pcapng -f "wlan.addr==aa:bb:cc:dd:ee:ff"

# Filter by source MAC
ai-wireshark analyze-wlan -i capture.pcapng -f "wlan.sa==aa:bb:cc:dd:ee:ff"
```

#### WLAN Analysis Script (Alternative)

```bash
python3 scripts/run_wlan_analysis.py <pcap_file> [mac_filter]
```

**Positional Arguments:**
- `pcap_file`: Input PCAP/PCAPNG file (required)
- `mac_filter`: Optional MAC address to filter (e.g. `aa:bb:cc:dd:ee:ff`). Matches SA, DA, TA, RA, and BSSID fields.

JSON and HTML reports are always generated in `results/` with filenames derived from the pcap name and MAC filter.

**Examples:**
```bash
# All WLAN frames
python3 scripts/run_wlan_analysis.py capture.pcapng

# Filter to a single client MAC
python3 scripts/run_wlan_analysis.py capture.pcapng c8:5a:cf:66:2e:1e
```

#### WLAN Channel Monitor (NEW Enhanced Metrics)

```bash
python3 scripts/run_channel_monitor.py --pcap <pcap_file> [OPTIONS]
```

**Options:**
- `--pcap, -r`: Input PCAP/PCAPNG file (required for file mode)
- `--iface, -i`: Live capture interface in monitor mode (e.g. `wlan0mon`)
- `--channel, -c`: Channel number to monitor (1–165)
- `--station, -s`: Station MAC address for spotlight profile (NEW: includes RTS/CTS overhead, connection delay, scan cycles, accurate client count)
- `--bssid, -b`: BSSID to filter (optional)
- `--mac, -m`: Client MAC to filter (optional)
- `--out, -o`: Output prefix for JSON/HTML files (default: `results/channel_monitor`)
- `--quiet, -q`: Suppress terminal output
- `--duration, -d`: Live capture duration in seconds (default: 300)

**Examples:**
```bash
# Analyze a pcap file on channel 9
python3 scripts/run_channel_monitor.py --pcap capture.pcapng --channel 9

# Station spotlight with all enhanced metrics
python3 scripts/run_channel_monitor.py \
  --pcap capture.pcapng --channel 9 \
  --station f8:ed:fc:7d:97:6f \
  --out results/station_profile

# Live capture on wlan0mon for 120 seconds, channel 6
python3 scripts/run_channel_monitor.py --iface wlan0mon --channel 6 --duration 120
```

**NEW Output Metrics** (in JSON + HTML report):
- `rts_cts_overhead_pct`: RTS+CTS frames as % of total channel traffic
- `cts_reply_rate`: CTS_count / RTS_count (hidden-node indicator)
- `connection_delay_seconds`: Time from first probe-response to first auth frame
- `scan_cycles`: Number of contiguous probe-request groups (separated by >3s gaps)
- `max_nav_us`: Maximum NAV/Duration field value in microseconds
- `connected_clients_oui_only`: Real devices (filters randomised MACs to OUI-assigned devices)
- `randomised_macs_filtered`: Count of locally-administered (virtual) MACs excluded from client count

## Protocol Analyzers

Each protocol has a dedicated analyzer that can be run standalone:

### TCP Analyzer

```bash
python src/protocols/tcp_analyzer.py --input traffic.pcap
```

**Detects:**
- SYN flood attacks
- RST storms
- Port scanning
- Excessive retransmissions
- Connection hijacking

### UDP Analyzer

```bash
python src/protocols/udp_analyzer.py --input traffic.pcap
```

**Detects:**
- UDP flood attacks
- Amplification attacks
- Port scanning
- Fragmentation attacks

### DNS Analyzer

```bash
python src/protocols/dns_analyzer.py --input traffic.pcap
```

**Detects:**
- DNS tunneling
- DGA (Domain Generation Algorithms)
- Cache poisoning
- Excessive NXDOMAIN responses
- DNS amplification

### HTTP / HTTPS Analysis (via TCP Analyzer + Port Filter)

HTTP and HTTPS are analyzed through the TCP analyzer using port-based filtering.
This consolidates application-layer threat detection without requiring a separate dissector pass.

```bash
# Analyze HTTP traffic (port 80)
python src/protocols/tcp_analyzer.py --input traffic.pcap  # then filter on port 80 via CLI/GUI port filter

# Via CLI
ai-wireshark analyze -i traffic.pcap --protocol tcp --filter "tcp.port==80"
ai-wireshark analyze -i traffic.pcap --protocol tcp --filter "tcp.port==443"
```

**HTTP threats detected (automatically when port 80/8080 traffic is present):**
- SQL injection attempts (URI pattern matching)
- XSS (Cross-Site Scripting) patterns
- Directory traversal attempts
- Suspicious scanning user agents (sqlmap, nikto, nmap, masscan)
- HTTP flood / high request rate

**HTTPS/TLS threats detected (automatically when port 443/8443 traffic is present):**
- TLS downgrade / negotiation failures
- TLS handshake failures (RST pattern analysis)
- HTTPS flood / high connection rate

**Port-based protocol identification is included in every TCP/UDP result under `app_layer_protocols`.**

### ICMP Analyzer

```bash
python src/protocols/icmp_analyzer.py --input traffic.pcap
```

**Detects:**
- ICMP flood
- Ping of Death
- Smurf attacks
- ICMP tunneling
- Network scanning

## Python API

### PacketParser

```python
from src.parsers.packet_parser import PacketParser

parser = PacketParser()
df = parser.parse_pcap('traffic.pcap')
flow_df = parser.extract_flow_features(df, window=60)
```

### Data Cleaning

```python
from src.preprocessing.cleaning import DataCleaner

cleaner = DataCleaner()
clean_df = cleaner.clean(df)
```

### Feature Engineering

```python
from src.preprocessing.feature_engineering import FeatureEngineer

engineer = FeatureEngineer()
features_df = engineer.engineer_features(df)
ml_features = engineer.get_ml_features(features_df)
```

### Anomaly Detection

```python
from src.core.model import IsolationForestModel

model = IsolationForestModel()
model.train(X_train)
predictions = model.predict(X_test)
scores = model.score_samples(X_test)
```

### Visualization

```python
from src.evaluation.visualization import NetworkVisualizer

viz = NetworkVisualizer()
viz.plot_protocol_distribution(df, save_path='protocol_dist.png')
viz.plot_traffic_timeline(df, save_path='timeline.png')
viz.create_analysis_report(df, output_dir='results/')
```
