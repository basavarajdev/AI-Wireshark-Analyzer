# Quick Start Guide

Get started with AI-Wireshark-Analyzer in 5 minutes!

## Installation

### 1. Clone or Navigate to Project

```bash
cd /home/bidnal/Downloads/AI_wireshark
```

### 2. Install Dependencies

**Option A: Direct Installation (No Virtual Environment)**

The packages are already installed and ready to use! Skip to "First Analysis" below.

If you need to reinstall:
```bash
pip install -r requirements.txt --break-system-packages
```

**Option B: With Virtual Environment (Recommended)**

```bash
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

> **Note**: The project ships with a pre-configured `.venv/`. Activate it with `source .venv/bin/activate` before running scripts.

## First Analysis

### Option 1: Using CLI

```bash
# Analyze a PCAP file
python3 src/api/cli.py analyze --input data/raw/sample.pcap --visualize

# Analyze with IP filter
python3 src/api/cli.py analyze -i data/raw/sample.pcap -f "ip.addr==192.168.1.1"

# Analyze with protocol + filter
python3 src/api/cli.py analyze -i traffic.pcap -p tcp -f "ip.src==10.0.0.5"

# Detect anomalies
python3 src/api/cli.py detect-anomalies --input data/raw/sample.pcap

# Generate visualizations
python3 src/api/cli.py visualize --input data/raw/sample.pcap
```

### Option 2: Using Protocol Analyzers

```bash
# TCP analysis
python3 src/protocols/tcp_analyzer.py --input data/raw/sample.pcap

# TCP analysis with HTML report
python3 src/protocols/tcp_analyzer.py --input data/raw/sample.pcap --html-report results/tcp_report.html

# DNS analysis
python3 src/protocols/dns_analyzer.py --input data/raw/sample.pcap

# HTTP analysis
python3 src/protocols/http_analyzer.py --input data/raw/sample.pcap
```

### Option 3: WLAN / Wi-Fi Analysis

Designed for 802.11 PCAPNG captures (monitor mode or over-the-air).

```bash
# Full WLAN analysis — auto-generates JSON + HTML report in results/
python3 scripts/run_wlan_analysis.py capture.pcapng

# Filter analysis to a single client MAC address
python3 scripts/run_wlan_analysis.py capture.pcapng aa:bb:cc:dd:ee:ff

# Using CLI with Wireshark display filter
python3 src/api/cli.py analyze-wlan -i capture.pcapng -f "wlan.addr==aa:bb:cc:dd:ee:ff"

# Filter by source MAC only
python3 src/api/cli.py analyze-wlan -i capture.pcapng -f "wlan.sa==aa:bb:cc:dd:ee:ff"
```

Detects:
- 802.11 connection failures (all 40+ IEEE reason/status codes)
- EAPOL 4-way handshake stalls (WPA2)
- WPA3/SAE authentication failures — wrong-password loops, anti-clogging, EC group mismatch
- Beacon loss, probe failures, weak signal
- Unprotected (non-encrypted) data frames
- IP connectivity failures (multicast-only client pattern)
- High retry rate, power-save scan patterns

### Option 4: TCP/UDP Application Traffic Analysis

Optimised for diagnosing application-level issues — print jobs, file transfers, slowness.

```bash
# Auto-detects print stream, zero-window stalls, retransmissions, RSTs, UDP flows
python3 scripts/analyze_tcp_udp.py capture.pcapng

# Custom output path
python3 scripts/analyze_tcp_udp.py capture.pcapng results/my_analysis.html
```

Produces a self-contained HTML report covering:
- Zero-window / buffer exhaustion events (with timeline chart)
- Retransmissions, duplicate ACKs, lost segments
- RST event catalogue with burst detection
- Top UDP flows, QUIC detection, broadcast/multicast UDP
- Root-cause diagnosis and prioritised remediation steps

### Option 5: IPv6 Traffic Analysis

Per-address IPv6 diagnostics covering TCP, UDP, ICMPv6, and SNMP.

```bash
# Analyse all traffic for a specific IPv6 address
python3 scripts/run_ipv6_analysis.py capture.pcapng 2408:8a04:e001:0:faed:fcff:fefe:10c1
```

Produces JSON + HTML report in `results/` covering:
- TCP connections, retransmissions, zero-window events, RST events, port probes
- UDP flows, SNMP community analysis
- ICMPv6/NDP patterns (Router Solicitation, Neighbor Discovery)
- Traffic overview with protocol distribution and peer analysis

### Option 6: Using REST API

```bash
# Start the API server
python3 src/api/rest.py
```

In another terminal:

```bash
# Upload and analyze
curl -X POST "http://localhost:8000/analyze" \
  -F "file=@data/raw/sample.pcap" \
  -F "protocol=tcp"

# Detect anomalies
curl -X POST "http://localhost:8000/detect-anomalies" \
  -F "file=@data/raw/sample.pcap"
```

Visit `http://localhost:8000/docs` for interactive API documentation.

## Filtering Reference

All analysis commands support Wireshark display filters via `-f` / `--filter`. The WLAN script accepts a MAC address as the 2nd positional argument.

| Use Case | Command |
|----------|---------|
| Filter by IP | `python3 src/api/cli.py analyze -i cap.pcap -f "ip.addr==192.168.1.1"` |
| Filter by source IP | `python3 src/api/cli.py analyze -i cap.pcap -f "ip.src==10.0.0.5"` |
| Filter by TCP port | `python3 src/api/cli.py analyze -i cap.pcap -p tcp -f "tcp.port==443"` |
| WLAN by MAC (script) | `python3 scripts/run_wlan_analysis.py cap.pcapng aa:bb:cc:dd:ee:ff` |
| WLAN by MAC (CLI) | `python3 src/api/cli.py analyze-wlan -i cap.pcapng -f "wlan.addr==aa:bb:cc:dd:ee:ff"` |
| WLAN by source MAC | `python3 src/api/cli.py analyze-wlan -i cap.pcapng -f "wlan.sa==aa:bb:cc:dd:ee:ff"` |
| IPv6 by address | `python3 scripts/run_ipv6_analysis.py cap.pcapng 2408:8a04:e001::1` |

## Get Sample Data

```bash
# Download sample PCAP files
python3 scripts/download_data.py --sample all
```

Or manually download from [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures).

## Training Models

### Train Isolation Forest

```bash
python3 scripts/train_model.py \
  --data data/raw/training.pcap \
  --model-type isolation_forest \
  --output models/my_isolation_forest.pkl
```

### Train Autoencoder

```bash
python3 scripts/train_model.py \
  --data data/raw/training.pcap \
  --model-type autoencoder \
  --output models/my_autoencoder.h5 \
  --epochs 100
```

## Evaluating Models

```bash
python3 scripts/evaluate_model.py \
  --model models/isolation_forest.pkl \
  --data data/raw/test.pcap \
  --model-type anomaly \
  --output-dir results/evaluation
```

## Generate HTML Reports

### Web-Based Analysis Reports

Generate professional HTML reports with charts and critical issues visualization:

```bash
# TCP analysis with HTML report
python3 src/protocols/tcp_analyzer.py \
  --input traffic.pcap \
  --html-report results/tcp_report.html

# Full analysis with HTML report
python3 src/api/cli.py analyze \
  -i traffic.pcap \
  -p all \
  -r results/full_analysis_report.html

# WLAN analysis report (auto-generates JSON + HTML in results/)
python3 scripts/run_wlan_analysis.py \
  traffic.pcapng

# WLAN with MAC filter
python3 scripts/run_wlan_analysis.py \
  traffic.pcapng aa:bb:cc:dd:ee:ff

# IPv6 traffic analysis report
python3 scripts/run_ipv6_analysis.py \
  traffic.pcapng 2408:8a04:e001:0:faed:fcff:fefe:10c1

# TCP/UDP application traffic report
python3 scripts/analyze_tcp_udp.py \
  traffic.pcapng results/tcp_udp_report.html

# Open the report in your browser
xdg-open results/tcp_report.html  # Linux
open results/tcp_report.html      # macOS
start results/tcp_report.html     # Windows
```

**HTML Report Features:**
- Executive summary with risk assessment and overall severity
- Critical issues with colour-coded severity badges (Critical / High / Medium / Low)
- Detailed threat analysis and evidence
- Traffic statistics, metrics, and temporal charts
- Prioritised remediation recommendations
- Self-contained — no external CSS/JS dependencies

## Common Use Cases

### 1. Detect Network Attacks

```bash
# Comprehensive analysis
python3 src/api/cli.py analyze -i suspicious_traffic.pcap -p all -v
```

### 2. Diagnose Wi-Fi Connection Problems

```bash
python3 scripts/run_wlan_analysis.py wifi_capture.pcapng
```

### 3. Diagnose Slow/Stalled Print Jobs

```bash
python3 scripts/analyze_tcp_udp.py print_capture.pcapng results/print_report.html
```

### 4. Analyse IPv6 Traffic

```bash
python3 scripts/run_ipv6_analysis.py capture.pcapng 2408:8a04:e001:0:faed:fcff:fefe:10c1
```

### 5. Find DNS Tunneling

```bash
python3 src/protocols/dns_analyzer.py --input dns_traffic.pcap --output dns_analysis.json
```

### 6. Identify SQL Injection Attempts

```bash
python3 src/protocols/http_analyzer.py --input web_traffic.pcap
```

### 7. Monitor for DoS/DDoS

```bash
# TCP SYN flood
python3 src/protocols/tcp_analyzer.py --input ddos_traffic.pcap

# UDP flood
python3 src/protocols/udp_analyzer.py --input ddos_traffic.pcap

# ICMP flood
python3 src/protocols/icmp_analyzer.py --input ddos_traffic.pcap
```

## Configuration

Edit `config/default.yaml` to customize:

- Detection thresholds
- Model parameters
- Visualization settings
- API configuration

## Troubleshooting

### PyShark/TShark Not Found

Install Wireshark/TShark:

**Ubuntu/Debian:**
```bash
sudo apt-get install tshark
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
Download from [Wireshark.org](https://www.wireshark.org/download.html)

### Permission Denied (PCAP)

On Linux, you may need to run with sudo or add user to wireshark group:

```bash
sudo usermod -a -G wireshark $USER
```
  -F "protocol=tcp"

# Detect anomalies
curl -X POST "http://localhost:8000/detect-anomalies" \
  -F "file=@data/raw/sample.pcap"
```

Visit `http://localhost:8000/docs` for interactive API documentation.

## Get Sample Data

```bash
# Download sample PCAP files
python3 scripts/download_data.py --sample all
```

Or manually download from [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures).

## Training Models

### Train Isolation Forest

```bash
python3 scripts/train_model.py \
  --data data/raw/training.pcap \
  --model-type isolation_forest \
  --output models/my_isolation_forest.pkl
```

### Train Autoencoder

```bash
python3 scripts/train_model.py \
  --data data/raw/training.pcap \
  --model-type autoencoder \
  --output models/my_autoencoder.h5 \
  --epochs 100
```

## Evaluating Models

```bash
python3 scripts/evaluate_model.py \
  --model models/isolation_forest.pkl \
  --data data/raw/test.pcap \
  --model-type anomaly \
  --output-dir results/evaluation
```

## Generate HTML Reports

### Web-Based Analysis Reports

Generate professional HTML reports with charts and critical issues visualization:

```bash
# TCP analysis with HTML report
python3 src/protocols/tcp_analyzer.py \
  --input traffic.pcap \
  --html-report results/tcp_report.html

# Full analysis with HTML report
python3 src/api/cli.py analyze \
  -i traffic.pcap \
  -p all \
  -r results/full_analysis_report.html

# Open the report in your browser
xdg-open results/tcp_report.html  # Linux
open results/tcp_report.html      # macOS
start results/tcp_report.html     # Windows
```

**HTML Report Features:**
- 📊 Executive summary with risk assessment
- 🚨 Critical issues with severity badges
- ⚠️ Detailed threat analysis
- 📈 Traffic statistics and metrics
- 📉 Interactive charts and visualizations
- 🎨 Professional, print-ready design

## Common Use Cases

### 1. Detect Network Attacks

```bash
# Comprehensive analysis
python3 src/api/cli.py analyze -i suspicious_traffic.pcap -p all -v
```

### 2. Find DNS Tunneling

```bash
python3 src/protocols/dns_analyzer.py --input dns_traffic.pcap --output dns_analysis.json
```

### 3. Identify SQL Injection Attempts

```bash
python3 src/protocols/http_analyzer.py --input web_traffic.pcap
```

### 4. Monitor for DoS/DDoS

```bash
# TCP SYN flood
python3 src/protocols/tcp_analyzer.py --input ddos_traffic.pcap

# UDP flood
python3 src/protocols/udp_analyzer.py --input ddos_traffic.pcap

# ICMP flood
python3 src/protocols/icmp_analyzer.py --input ddos_traffic.pcap
```

## Configuration

Edit `config/default.yaml` to customize:

- Detection thresholds
- Model parameters
- Visualization settings
- API configuration

## Troubleshooting

### PyShark/TShark Not Found

Install Wireshark/TShark:

**Ubuntu/Debian:**
```bash
sudo apt-get install tshark
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
Download from [Wireshark.org](https://www.wireshark.org/download.html)

### Permission Denied (PCAP)

On Linux, you may need to run with sudo or add user to wireshark group:

```bash
sudo usermod -a -G wireshark $USER
```

Log out and log back in for changes to take effect.

### Memory Issues with Large Files

Set packet limit in config:

```yaml
features:
  max_packets: 100000  # Limit packets to process
```

## Next Steps

- Read [API Documentation](docs/api.md)
- Understand [Architecture](docs/architecture.md)
- Check [test examples](tests/)
- Explore protocol analyzers in `src/protocols/`

## Getting Help

- Check documentation in `docs/`
- Review example outputs in `results/`
- Run tests: `pytest tests/`
- Display system info: `python3 src/api/cli.py info`

## Example Output

After running analysis, you'll see:

```
=== CRITICAL ISSUES DETECTED ===

[CRITICAL] SYN Flood
  SYN flood detected: 450.50 SYN/sec (threshold: 100)

[HIGH] Port Scanning
  Port scanning detected from 2 source(s)

[HIGH] SQL Injection
  SQL injection attempts detected: 15 malicious requests
```

Enjoy analyzing network traffic with AI! 🚀
