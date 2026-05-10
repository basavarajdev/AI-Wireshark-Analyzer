# AI-Wireshark-Analyzer - Project Summary

## Project Status: Active

A comprehensive Python platform for analyzing Wireshark/tshark packet captures using rule-based protocol analysis, Machine Learning, and Deep Learning for network security and diagnostics.

## Project Structure

```
AI_wireshark/
├── README.md                    # Main documentation
├── QUICKSTART.md               # Quick start guide
├── WEB_REPORTS_GUIDE.md        # HTML report generation guide
├── PROJECT_SUMMARY.md          # This file
├── requirements.txt            # Python dependencies
├── setup.py                    # Package installation
│
├── config/                     # Configuration files
│   ├── default.yaml           # Production config
│   └── dev.yaml               # Development config
│
├── data/                      # Data storage
│   ├── raw/                   # PCAP/PCAPNG files
│   ├── processed/             # Feature CSVs
│   └── external/              # External datasets
│
├── models/                    # Trained ML models
│
├── docs/                      # Documentation
│   ├── api.md                # API reference
│   ├── architecture.md       # System design
│   ├── DESIGN_DOCUMENT.md    # Detailed design doc
│   └── html_reports.md       # HTML report docs
│
├── src/                       # Main source code
│   ├── parsers/
│   │   └── packet_parser.py  # PCAP parsing (PyShark)
│   ├── preprocessing/
│   │   ├── cleaning.py
│   │   └── feature_engineering.py
│   ├── core/
│   │   ├── model.py          # ML models (Isolation Forest, Autoencoder, RF)
│   │   └── utils.py
│   ├── protocols/
│   │   ├── tcp_analyzer.py   # TCP threats + zero-window/data-gap analysis
│   │   ├── udp_analyzer.py   # UDP flood / amplification detection
│   │   ├── dns_analyzer.py
│   │   ├── http_analyzer.py
│   │   ├── https_analyzer.py
│   │   ├── icmp_analyzer.py
│   │   ├── dhcp_analyzer.py  # DHCP analysis
│   │   └── wlan_analyzer.py  # Full 802.11/WLAN analysis
│   ├── evaluation/
│   │   ├── metrics.py
│   │   └── visualization.py
│   ├── reports/
│   │   └── html_generator.py # HTML report engine
│   └── api/
│       ├── rest.py           # FastAPI REST endpoints
│       └── cli.py            # Click CLI
│
├── tests/
│   ├── test_parser.py
│   ├── test_preprocessing.py
│   └── test_models.py
│
├── scripts/
│   ├── run_wlan_analysis.py  # WLAN runner (tshark + WLANAnalyzer)
│   ├── analyze_tcp_udp.py    # TCP/UDP direct tshark analyser
│   ├── run_ipv6_analysis.py  # IPv6 per-address traffic analysis
│   ├── monitor_capture.sh    # Monitor-mode capture helper (stub)
│   ├── train_model.py
│   ├── evaluate_model.py
│   └── download_data.py
│
├── logs/
└── results/                   # Generated reports and JSON outputs
```

## Key Features Implemented

### 1. Protocol Analyzers (`src/protocols/`)

**TCP Analyzer** (`tcp_analyzer.py`):
- SYN flood detection (rate-based, corrected guard logic)
- RST storm identification
- Port scanning detection
- Excessive retransmissions
- Connection hijacking attempts (sequence anomalies)
- Zero-window / window-full stall detection
- Data transmission gap detection

**UDP Analyzer** (`udp_analyzer.py`):
- UDP flood attacks
- Amplification attacks (DNS/NTP/SSDP service abuse)
- Port scanning
- Fragmentation attacks

**WLAN Analyzer** (`wlan_analyzer.py`):
- 802.11 connection failure detection (all 40+ IEEE reason/status codes)
- EAPOL 4-way handshake stall detection (WPA2)
- WPA3/SAE authentication failures: wrong-password loops, anti-clogging token, EC group mismatch, SAE Commit/Confirm tracking
- WPA3-OWE detection
- Beacon loss / AP disappearance
- Probe request failures
- Weak signal detection (RSSI/SNR)
- Unprotected (non-encrypted) data frame detection
- IP connectivity failure (multicast-only pattern)
- High retry rate (data frames only)
- Power-save scan pattern detection
- Per-client connection flow reconstruction with diagnosis

**DHCP Analyzer** (`dhcp_analyzer.py`):
- DHCP starvation / exhaustion
- Rogue DHCP server detection
- Lease anomaly detection

**DNS Analyzer** (`dns_analyzer.py`):
- DNS tunneling (entropy + subdomain analysis)
- DGA domain patterns
- Cache poisoning indicators
- NXDOMAIN floods, amplification attacks

**HTTP Analyzer** (`http_analyzer.py`):
- SQL injection, XSS detection
- Suspicious user agents
- HTTP floods, directory traversal

**HTTPS Analyzer** (`https_analyzer.py`):
- TLS downgrade detection
- Certificate anomalies
- HTTPS floods

**ICMP Analyzer** (`icmp_analyzer.py`):
- ICMP flood, Ping of Death, Smurf attacks
- ICMP tunneling, network scanning

---

### 2. Analysis Scripts (`scripts/`)

**WLAN Analysis Runner** (`run_wlan_analysis.py`):
- Bulk tshark field extraction (29 WLAN fields per packet)
- Feeds `WLANAnalyzer` for full 802.11 threat detection
- Outputs JSON results + self-contained HTML report
- Optional MAC filter for single-client analysis (4th positional arg)
- Usage: `python3 scripts/run_wlan_analysis.py <pcap> [mac]`

**TCP/UDP Direct Analyser** (`analyze_tcp_udp.py`):
- Pure tshark extraction, no PyShark/DataFrame overhead
- Auto-detects print/application stream (port 9100, 631, 515)
- Detects zero-window stalls, retransmissions, RST events, UDP flows, QUIC, broadcasts
- Per-30-second zero-window timeline bar chart
- RST burst detection (≥3 resets within 2 seconds)
- Detailed HTML report with severity assessment and remediation
- Usage: `python3 scripts/analyze_tcp_udp.py <pcap> [out.html]`

**IPv6 Analysis Runner** (`run_ipv6_analysis.py`):
- Per-address IPv6 traffic analysis via targeted tshark queries
- TCP connections, retransmissions, zero-window, RST events, port probes
- UDP flows, SNMP community analysis
- ICMPv6/NDP patterns (Router Solicitation, Neighbor Discovery)
- Traffic overview with protocol distribution and peer analysis
- Outputs JSON results + self-contained HTML report
- Usage: `python3 scripts/run_ipv6_analysis.py <pcap> <ipv6_address>`

---

### 3. Machine Learning Models (`src/core/model.py`)

**Isolation Forest** (Unsupervised):
- Anomaly detection without labeled data
- Configurable contamination threshold

**Autoencoder** (Deep Learning, Unsupervised):
- Neural network-based anomaly detection via reconstruction error
- TensorFlow/Keras (gracefully disabled if not installed)

**Random Forest Classifier** (Supervised):
- Multi-class attack classification
- Feature importance analysis
- Requires labeled training data

---

### 4. Data Processing Pipeline

**Packet Parsing** (`src/parsers/packet_parser.py`):
- PyShark integration for structured field extraction
- Multi-protocol support, flow aggregation, 50+ features

**Preprocessing** (`src/preprocessing/`):
- Data cleaning, validation, dedup, missing value handling
- Feature engineering: IP, port, protocol, statistical, time, DNS, HTTP features

---

### 5. Interfaces

**REST API** (`src/api/rest.py`) — FastAPI + Uvicorn:
- `POST /analyze` — Full PCAP analysis
- `POST /detect-anomalies` — ML-based detection
- `GET /health`, `GET /models`, `GET /protocols`
- OpenAPI docs at `/docs` (Swagger) and `/redoc`

**CLI** (`src/api/cli.py`) — Click + Rich:
- `analyze` — protocol analysis with `-f` display filter support (e.g. `ip.addr==`, `tcp.port==`)
- `analyze-wlan` — WLAN analysis with `-f` MAC/display filter (e.g. `wlan.addr==aa:bb:cc:dd:ee:ff`)
- `detect-anomalies`, `visualize`, `info`

---

### 6. HTML Report Engine (`src/reports/html_generator.py`)

- Self-contained reports (no external CSS/JS)
- Severity badges: Critical / High / Medium / Low / Info
- Embedded Base64 charts
- Remediation guidance keyed by threat type
- Used by all `src/protocols/` analyzers and `run_wlan_analysis.py`
- `analyze_tcp_udp.py` has its own inline HTML generator with timeline charts

---

## Usage Examples

### CLI

```bash
# Analyze TCP traffic
python3 src/protocols/tcp_analyzer.py --input traffic.pcap

# Full analysis (reports auto-generated in results/)
python3 src/api/cli.py analyze -i traffic.pcap -p all -v

# With IP filter
python3 src/api/cli.py analyze -i traffic.pcap -p tcp -f "ip.addr==192.168.1.1"

# Anomaly detection
python3 src/api/cli.py detect-anomalies -i traffic.pcap -m isolation_forest
```

### WLAN Analysis

```bash
# Full WLAN analysis — auto-generates JSON + HTML report in results/
python3 scripts/run_wlan_analysis.py wifi.pcapng

# With MAC filter
python3 scripts/run_wlan_analysis.py wifi.pcapng aa:bb:cc:dd:ee:ff

# Using CLI with display filter
python3 src/api/cli.py analyze-wlan -i wifi.pcapng -f "wlan.addr==aa:bb:cc:dd:ee:ff"
```

### TCP/UDP Application Traffic

```bash
python3 scripts/analyze_tcp_udp.py capture.pcapng results/tcp_udp_report.html
```

### IPv6 Traffic Analysis

```bash
python3 scripts/run_ipv6_analysis.py capture.pcapng 2408:8a04:e001:0:faed:fcff:fefe:10c1
```

### REST API

```bash
python3 src/api/rest.py

curl -X POST "http://localhost:8000/analyze" \
  -F "file=@traffic.pcap" \
  -F "protocol=tcp"
```

### Python API

```python
from src.parsers.packet_parser import PacketParser
from src.protocols.tcp_analyzer import TCPAnalyzer
from src.core.model import IsolationForestModel

parser = PacketParser()
df = parser.parse_pcap('traffic.pcap')

analyzer = TCPAnalyzer()
results = analyzer.analyze('traffic.pcap')

model = IsolationForestModel()
model.train(X_train)
predictions = model.predict(X_test)
```

---

## Technologies Used

- **tshark** — High-performance packet field extraction (WLAN runner, TCP/UDP analyser)
- **PyShark** — Python tshark wrapper for structured parsing (protocol analyzers, packet parser)
- **Scikit-learn** — Isolation Forest, Random Forest
- **TensorFlow/Keras** — Autoencoder (optional)
- **Pandas / NumPy** — Data processing
- **FastAPI / Uvicorn** — REST API
- **Click / Rich** — CLI
- **Matplotlib / Seaborn** — Visualisation charts
- **Loguru** — Structured logging
- **PyYAML** — Configuration management
- **PyTest** — Unit testing

---

## Installation

```bash
cd /home/bidnal/Downloads/AI_wireshark
source .venv/bin/activate   # recommended
python3 src/api/cli.py info
```

---

## Key Highlights

- Complete modular protocol analysis pipeline
- Full 802.11 WLAN analysis including WPA3/SAE
- TCP/UDP application-level diagnostics (zero-window, retransmissions, RST)
- ML/DL anomaly detection (unsupervised + supervised)
- Self-contained HTML reports with charts and remediation guidance
- Clean codebase — unused imports and dead code removed

## License

MIT License
- ✅ Amplification attacks
- ✅ Port scanning
- ✅ Fragmentation attacks

**DNS Analyzer** (`dns_analyzer.py`):
- ✅ DNS tunneling detection
- ✅ DGA (Domain Generation Algorithm) patterns
- ✅ Cache poisoning indicators
- ✅ Excessive NXDOMAIN responses
- ✅ DNS amplification attacks

**HTTP Analyzer** (`http_analyzer.py`):
- ✅ SQL injection detection
- ✅ XSS (Cross-Site Scripting) detection
- ✅ Suspicious user agent identification
- ✅ HTTP flood attacks
- ✅ Directory traversal attempts

**HTTPS Analyzer** (`https_analyzer.py`):
- ✅ SSL/TLS downgrade detection
- ✅ Certificate issues
- ✅ HTTPS flood attacks

**ICMP Analyzer** (`icmp_analyzer.py`):
- ✅ ICMP flood detection
- ✅ Ping of Death
- ✅ Smurf attack detection
- ✅ ICMP tunneling
- ✅ Network scanning

### 2. Machine Learning Models

**Isolation Forest** (Anomaly Detection):
- Unsupervised learning
- Fast training and inference
- Configurable contamination threshold

**Autoencoder** (Deep Learning):
- Neural network-based anomaly detection
- Automatic feature learning
- Reconstruction error scoring

**Random Forest Classifier**:
- Attack type classification
- Feature importance analysis
- Multi-class support

### 3. Data Processing Pipeline

**Packet Parsing**:
- PyShark integration
- Multi-protocol support
- Flow aggregation
- Feature extraction

**Preprocessing**:
- Data cleaning and validation
- Missing value handling
- Duplicate removal
- Feature engineering (50+ features)

### 4. Interfaces

**REST API** (FastAPI):
- `/analyze` - Full PCAP analysis
- `/detect-anomalies` - ML-based detection
- `/health` - Health check
- `/models` - List models
- Interactive docs at `/docs`

**CLI** (Click + Rich):
- `analyze` - Analyze PCAP files
- `detect-anomalies` - Run anomaly detection
- `visualize` - Generate charts
- `info` - System information

### 5. Visualization

- Protocol distribution charts
- Traffic timeline plots
- Anomaly score distributions
- Confusion matrices
- Feature importance plots
- Packet size distributions
- IP traffic analysis

### 6. Testing & Documentation

**Tests**:
- Unit tests for parsers
- Preprocessing tests
- Model tests
- Pytest framework

**Documentation**:
- Comprehensive README
- API reference
- Architecture documentation
- Quick start guide
