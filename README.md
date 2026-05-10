# AI-Wireshark-Analyzer

A comprehensive Python project that uses Machine Learning and Deep Learning to analyze Wireshark packet captures (PCAP/PCAPNG files) for network protocol insights, security threat detection, and application traffic diagnostics.

## Features

- **Packet Parsing**: Extract features from PCAP/PCAPNG files using tshark (bulk field extraction) and PyShark
- **Protocol Analysis**: Dedicated analyzers for TCP, UDP, HTTP, HTTPS, DNS, ICMP, DHCP, and WLAN (802.11)
- **WLAN / Wi-Fi Analysis**: Full 802.11 analysis — WPA2/WPA3/SAE authentication, connection failures, beacon loss, scan patterns, IP connectivity, power-save behaviour
- **IPv6 Traffic Analysis**: Per-address IPv6 diagnostics — TCP connections, UDP flows, ICMPv6/NDP, SNMP, retransmissions, port probes
- **TCP/UDP Application Diagnostics**: Direct tshark-based analysis for print and application traffic — zero-window stalls, retransmissions, RST events, UDP flows
- **Anomaly Detection**: Unsupervised learning (Isolation Forest, Autoencoders)
- **Traffic Classification**: Supervised models to detect DoS, port scanning, DNS tunneling
- **Visualization**: Protocol distribution, anomaly scores, time-series traffic patterns
- **HTML Reports**: Self-contained, browser-ready reports with embedded charts, severity badges, and remediation guidance
- **REST API**: Upload PCAP files and get analysis results
- **CLI Tool**: Command-line interface for local analysis

## Installation

### Prerequisites
- Python 3.10+ (3.12 recommended)
- Wireshark/TShark installed on your system (`tshark` must be on `$PATH`)

### Setup

1. Navigate to the project:
```bash
cd /home/bidnal/Downloads/AI_wireshark
```

2. Install dependencies:

**Option A: Direct Installation (No Virtual Environment)**

Packages are already installed! Ready to use immediately.

If reinstalling is needed:
```bash
# Using VS Code Python extension (recommended)
# Dependencies are auto-installed

# Or manual system-wide install (use with caution)
pip install -r requirements.txt --break-system-packages
```

**Option B: With Virtual Environment (Recommended)**

```bash
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

> **Note**: A virtual environment at `.venv/` is the recommended setup. Activate it before running any script.

## Quick Start

### CLI Usage

1. **Analyze a PCAP file**:
```bash
python3 src/api/cli.py analyze --input data/raw/sample.pcap

# With display filter (IP-based)
python3 src/api/cli.py analyze -i data/raw/sample.pcap -f "ip.addr==192.168.1.1"

# With protocol + filter
python3 src/api/cli.py analyze -i traffic.pcap -p tcp -f "ip.addr==10.0.0.5"
```

2. **Train anomaly detection model**:
```bash
python3 scripts/train_model.py --data data/processed/features.csv --model-type isolation_forest
```

3. **Evaluate model**:
```bash
python3 scripts/evaluate_model.py --model models/isolation_forest.pkl --data data/processed/test.csv
```

4. **Protocol-specific analysis**:
```bash
# TCP Analysis
python3 src/protocols/tcp_analyzer.py --input data/raw/sample.pcap

# TCP Analysis with HTML Report
python3 src/protocols/tcp_analyzer.py --input data/raw/sample.pcap --html-report results/report.html

# DNS Analysis
python3 src/protocols/dns_analyzer.py --input data/raw/sample.pcap

# HTTP Analysis
python3 src/protocols/http_analyzer.py --input data/raw/sample.pcap
```

5. **WLAN / Wi-Fi Analysis**:
```bash
# Full WLAN analysis — auto-generates JSON + HTML report in results/
python3 scripts/run_wlan_analysis.py capture.pcapng

# Filter to a single client MAC address
python3 scripts/run_wlan_analysis.py capture.pcapng aa:bb:cc:dd:ee:ff

# Using the CLI with Wireshark display filter
python3 src/api/cli.py analyze-wlan -i capture.pcapng -f "wlan.addr==aa:bb:cc:dd:ee:ff"
```

6. **TCP/UDP Application Traffic Analysis**:
```bash
# Auto-detects print stream, RSTs, zero-window stalls, UDP flows
python3 scripts/analyze_tcp_udp.py capture.pcapng results/tcp_udp_report.html
```

7. **IPv6 Traffic Analysis**:
```bash
# Analyse IPv6 traffic for a specific address
python3 scripts/run_ipv6_analysis.py capture.pcapng 2408:8a04:e001:0:faed:fcff:fefe:10c1
```

8. **Generate web reports**:
```bash
# Comprehensive analysis with visualizations (reports auto-generated in results/)
python3 src/api/cli.py analyze -i traffic.pcap -p all -v

# With IP filter
python3 src/api/cli.py analyze -i traffic.pcap -p all -f "ip.addr==192.168.1.100"

# Open in browser
xdg-open results/traffic_all_report.html
```

### API Usage

1. **Start the REST API**:
```bash
python3 src/api/rest.py
```

2. **Upload and analyze PCAP**:
```bash
curl -X POST "http://localhost:8000/analyze" \
  -F "file=@data/raw/sample.pcap" \
  -F "protocol=tcp"
```

3. **API Endpoints**:
- `POST /analyze` - Analyze PCAP file
- `GET /health` - Health check
- `GET /models` - List available models
- `POST /detect-anomalies` - Run anomaly detection

## Filtering

All analysis tools support filtering to focus on specific traffic. Use Wireshark display filter syntax.

### Common Filter Examples

| Filter | Description |
|--------|-------------|
| `ip.addr==192.168.1.1` | All traffic to/from an IP |
| `ip.src==10.0.0.5` | Traffic from a specific source IP |
| `ip.dst==10.0.0.5` | Traffic to a specific destination IP |
| `tcp.port==443` | Traffic on a specific TCP port |
| `wlan.addr==aa:bb:cc:dd:ee:ff` | WLAN frames involving a MAC address |
| `wlan.sa==aa:bb:cc:dd:ee:ff` | WLAN frames from a source MAC |

### Applying Filters

**CLI (`analyze` command)** — use `-f` for any Wireshark display filter:
```bash
python3 src/api/cli.py analyze -i capture.pcap -p tcp -f "ip.addr==192.168.1.1"
```

**CLI (`analyze-wlan` command)** — use `-f` for WLAN display filters:
```bash
python3 src/api/cli.py analyze-wlan -i capture.pcapng -f "wlan.addr==aa:bb:cc:dd:ee:ff"
```

**WLAN script** — pass MAC address as the 2nd argument:
```bash
python3 scripts/run_wlan_analysis.py capture.pcapng aa:bb:cc:dd:ee:ff
```

## Project Structure

```
AI_wireshark/
├── README.md
├── QUICKSTART.md
├── PROJECT_SUMMARY.md
├── WEB_REPORTS_GUIDE.md
├── requirements.txt
├── setup.py
├── config/
│   ├── default.yaml
│   └── dev.yaml
├── data/
│   ├── raw/              # Original PCAP/PCAPNG files
│   ├── processed/        # Extracted features
│   └── external/         # Third-party datasets
├── models/               # Trained ML models
├── docs/
│   ├── api.md
│   ├── architecture.md
│   ├── DESIGN_DOCUMENT.md
│   └── html_reports.md
├── src/
│   ├── __init__.py
│   ├── core/
│   │   ├── model.py      # ML models (Isolation Forest, Autoencoder, RF)
│   │   └── utils.py
│   ├── preprocessing/
│   │   ├── cleaning.py
│   │   └── feature_engineering.py
│   ├── protocols/
│   │   ├── tcp_analyzer.py    # TCP threat detection + zero-window analysis
│   │   ├── udp_analyzer.py    # UDP flood / amplification detection
│   │   ├── http_analyzer.py
│   │   ├── https_analyzer.py
│   │   ├── dns_analyzer.py
│   │   ├── icmp_analyzer.py
│   │   ├── dhcp_analyzer.py   # DHCP analysis
│   │   └── wlan_analyzer.py   # Full 802.11 / WLAN analysis
│   ├── evaluation/
│   │   ├── metrics.py
│   │   └── visualization.py
│   ├── api/
│   │   ├── rest.py
│   │   └── cli.py
│   ├── parsers/
│   │   └── packet_parser.py
│   └── reports/
│       └── html_generator.py  # HTML report engine
├── tests/
│   ├── test_parser.py
│   ├── test_preprocessing.py
│   └── test_models.py
├── scripts/
│   ├── run_wlan_analysis.py   # WLAN analysis runner (tshark + WLANAnalyzer)
│   ├── analyze_tcp_udp.py     # TCP/UDP application traffic analyser
│   ├── run_ipv6_analysis.py   # IPv6 per-address traffic analysis
│   ├── monitor_capture.sh     # Monitor-mode capture helper (stub)
│   ├── train_model.py
│   ├── evaluate_model.py
│   └── download_data.py
├── logs/
└── results/                   # Generated reports and JSON outputs
```

## Critical Issues Detected

The analyzers focus on detecting critical network issues:

### TCP Analyzer
- SYN Flood attacks
- Connection hijacking attempts (sequence number anomalies)
- Excessive retransmissions
- RST storms
- Zero-window / window-full stalls
- Data transmission gaps

### UDP Analyzer
- UDP flood attacks
- Amplification attacks (DNS, NTP, SSDP service abuse)
- Excessive packet loss
- Fragmentation attacks

### WLAN Analyzer *(new)*
- 802.11 connection failures with per-reason evidence (all 40+ IEEE reason/status codes)
- EAPOL 4-way handshake stall detection (WPA2)
- WPA3/SAE authentication failures — wrong-password loops, anti-clogging token, EC group mismatch
- WPA3-OWE detection
- Beacon loss / AP disappearance detection
- Probe request failures (no probe response)
- Weak signal detection (RSSI/SNR thresholds)
- Unprotected traffic detection (data frames without encryption)
- IP connectivity failures (multicast-only client pattern, no unicast traffic)
- High retry rate (data frames only)
- Power-save scan pattern detection
- Per-client connection flow reconstruction

### DHCP Analyzer *(new)*
- DHCP starvation / exhaustion
- Rogue DHCP server detection
- DHCP lease anomalies

### DNS Analyzer
- DNS tunneling
- Cache poisoning attempts
- Excessive NXDOMAIN responses
- DGA (Domain Generation Algorithm) patterns

### HTTP/HTTPS Analyzer
- SQL injection attempts
- XSS patterns
- Suspicious user agents
- Abnormal request rates

### ICMP Analyzer
- ICMP flood attacks
- Ping of death
- Smurf attacks

## Model Training

The project includes pre-configured models:

1. **Isolation Forest**: Detects network anomalies
2. **Autoencoder**: Deep learning-based anomaly detection
3. **Random Forest Classifier**: Classifies attack types

Train custom models:
```bash
python scripts/train_model.py \
  --data data/processed/features.csv \
  --model-type autoencoder \
  --epochs 100 \
  --output models/custom_autoencoder.h5
```

## Configuration

Edit `config/default.yaml` to customize:
- Feature extraction parameters
- Model hyperparameters
- API settings
- Logging configuration

## Testing

Run tests:
```bash
pytest tests/
```

Run with coverage:
```bash
pytest --cov=src tests/
```

## Documentation

- [API Reference](docs/api.md)
- [Architecture Overview](docs/architecture.md)
- [Design Document](docs/DESIGN_DOCUMENT.md)
- [HTML Reports Guide](docs/html_reports.md)
- [Web Reports Quick Reference](WEB_REPORTS_GUIDE.md)
- [Quick Start](QUICKSTART.md)

## Dependencies

- pyshark >= 0.6
- scikit-learn >= 1.3.0
- tensorflow >= 2.13.0 *(optional — required only for Autoencoder model)*
- pandas >= 2.0.0
- numpy >= 1.24.0
- fastapi >= 0.104.0
- matplotlib >= 3.7.0
- seaborn >= 0.12.0
- loguru >= 0.7.0
- pyyaml >= 6.0

## License

MIT License

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## Contact

For issues and questions, please open a GitHub issue.
