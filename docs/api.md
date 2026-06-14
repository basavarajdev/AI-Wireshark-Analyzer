# API Reference

## REST API

The AI-Wireshark-Analyzer provides a RESTful API built with FastAPI.

### Starting the API Server

```bash
python src/api/rest.py
```

The API will be available at `http://localhost:8000`

### API Documentation

Interactive API documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Endpoints

#### Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

#### List Available Models

```http
GET /models
```

**Response:**
```json
[
  {
    "name": "isolation_forest",
    "type": "anomaly_detection",
    "available": true
  },
  {
    "name": "autoencoder",
    "type": "anomaly_detection",
    "available": true
  }
]
```

#### Analyze PCAP File

```http
POST /analyze
```

**Parameters:**
- `file` (multipart/form-data): PCAP file to analyze
- `protocol` (optional): Specific protocol to analyze (`tcp`, `udp`, `dns`, `http`, `https`, `icmp`)

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

### HTTP Analyzer

```bash
python src/protocols/http_analyzer.py --input traffic.pcap
```

**Detects:**
- SQL injection attempts
- XSS (Cross-Site Scripting)
- Suspicious user agents
- HTTP flood (DoS)
- Directory traversal

### HTTPS Analyzer

```bash
python src/protocols/https_analyzer.py --input traffic.pcap
```

**Detects:**
- SSL/TLS downgrade attacks
- Certificate issues
- HTTPS flood

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
