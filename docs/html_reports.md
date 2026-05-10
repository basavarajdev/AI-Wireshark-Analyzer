# HTML Report Generation Guide

## Overview

The AI-Wireshark-Analyzer now includes comprehensive HTML report generation with professional visualizations and critical issue tracking.

## Features

### 📊 Executive Summary
- Total packet count
- Critical issues count
- Threat detection summary
- Overall risk assessment (Critical/High/Medium/Low)

### 🚨 Critical Issues Section
- Color-coded severity badges (Critical, High, Medium, Low)
- Detailed issue descriptions
- Attack vectors and indicators
- Remediation recommendations

### ⚠️ Threat Analysis
- Port scanning detection with top scanner IPs
- DDoS attack indicators
- Connection hijacking attempts
- Retransmission rate analysis
- Protocol-specific threats

### 📈 Traffic Statistics
- Protocol distribution
- Top destination ports
- Packet size statistics
- Source/destination IP diversity
- Traffic patterns

### 📉 Visualizations
- Port distribution charts
- Threat severity pie charts
- Traffic timeline plots
- Protocol distribution graphs

## Usage

### Basic HTML Report

```bash
# TCP Analysis Report
python3 src/protocols/tcp_analyzer.py \
  --input traffic.pcap \
  --html-report results/tcp_report.html

# View the report
xdg-open results/tcp_report.html
```

### Comprehensive Analysis Report

```bash
# Full multi-protocol analysis (reports auto-generated in results/)
python3 src/api/cli.py analyze \
  -i traffic.pcap \
  -p all \
  -v

# With IP filter
python3 src/api/cli.py analyze \
  -i traffic.pcap \
  -p tcp \
  -f "ip.addr==192.168.1.100"

# This generates:
# - JSON results
# - HTML report
# - Visualization charts
```

### WLAN Analysis Report

```bash
# Full WLAN analysis — auto-generates JSON + HTML report in results/
python3 scripts/run_wlan_analysis.py \
  capture.pcapng

# With MAC filter (single client)
python3 scripts/run_wlan_analysis.py \
  capture.pcapng aa:bb:cc:dd:ee:ff

# Using CLI with display filter
python3 src/api/cli.py analyze-wlan \
  -i capture.pcapng \
  -f "wlan.addr==aa:bb:cc:dd:ee:ff"
```

### Protocol-Specific Reports

```bash
# DNS Analysis Report
python3 src/protocols/dns_analyzer.py \
  --input dns_traffic.pcap \
  --html-report results/dns_report.html

# HTTP Security Analysis Report
python3 src/protocols/http_analyzer.py \
  --input web_traffic.pcap \
  --html-report results/http_report.html

# UDP Analysis Report
python3 src/protocols/udp_analyzer.py \
  --input udp_traffic.pcap \
  --html-report results/udp_report.html
```

### Combined JSON and HTML Output

```bash
# Save both JSON and HTML
python3 src/protocols/tcp_analyzer.py \
  --input traffic.pcap \
  --output results/analysis.json \
  --html-report results/analysis.html
```

## Report Structure

### 1. Header Section
- Report title
- Analyzed file name
- Analysis timestamp
- Protocol analyzed

### 2. Executive Summary Cards
```
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│ Total Packets   │ Critical Issues │ Threats Detected│ Risk Level      │
│    43,881       │       0         │       3         │   HIGH RISK     │
└─────────────────┴─────────────────┴─────────────────┴─────────────────┘
```

### 3. Critical Issues List
Each issue displays:
- Severity badge (color-coded)
- Issue title
- Detailed description
- Attack indicators
- Affected resources

### 4. Threat Analysis
Detailed breakdown of each detected threat:
- **Port Scanning**: Source IPs and ports targeted
- **DDoS Indicators**: Request rates and patterns
- **Connection Issues**: Hijacking attempts, retransmissions
- **Protocol Violations**: Malformed packets, suspicious patterns

### 5. Traffic Statistics
- Network-wide metrics
- Top ports table with packet counts and percentages
- IP diversity analysis
- Packet size distribution

### 6. Visual Charts
- Bar charts for port distribution
- Pie charts for threat severity
- Time-series plots for traffic patterns

## Opening Reports

### Linux
```bash
xdg-open results/report.html
firefox results/report.html
google-chrome results/report.html
```

### macOS
```bash
open results/report.html
```

### Windows
```bash
start results/report.html
```

## Customization

The HTML reports use inline CSS and are fully self-contained, making them:
- ✅ Easy to share via email
- ✅ No external dependencies
- ✅ Print-ready formatting
- ✅ Mobile-responsive design

## Example Output

Here's what your HTML report will look like:

```
🛡️ Network Analysis Report - TCP
📁 File: onboarding_1_attempt_FW-926.pcapng
📅 Date: 2026-02-05 11:50:20
🔍 Protocol: TCP

┌── Executive Summary ──────────────────────────┐
│ Total Packets: 43,881                         │
│ Critical Issues: 0                            │
│ Threats Detected: 3                           │
│ Risk Level: HIGH RISK                         │
└───────────────────────────────────────────────┘

🚨 Critical Issues
✓ No critical issues detected

⚠️ Threats Detected

[HIGH] Port Scanning
Port scanning detected from 10 source(s)

Top Scanners:
├─ 165.225.113.190 → 200 ports
├─ 192.168.0.126 → 167 ports
├─ 165.225.122.37 → 72 ports
└─ 203.116.175.96 → 43 ports

[MEDIUM] Excessive Retransmissions
High retransmission rate: 16.66%
Retransmission Rate: 16.66%
Retransmissions: 7,312

[HIGH] Connection Hijacking
Potential connection hijacking: 1 suspicious flow(s)
```

## Printing Reports

The HTML reports are optimized for printing:
- A4/Letter page formatting
- Page break optimization
- Clean black & white output
- Logo and branding

To print:
1. Open report in browser
2. File → Print (or Ctrl+P)
3. Select printer or "Save as PDF"

## Sharing Reports

HTML reports are self-contained and can be shared:
- Email attachment
- Upload to documentation systems
- Share via file sharing services
- Include in incident reports

## Tips

1. **Save to descriptive filenames**:
   ```bash
   python3 src/protocols/tcp_analyzer.py \
     -i suspicious_traffic.pcap \
     -r "reports/incident_$(date +%Y%m%d)_tcp_analysis.html"
   ```

2. **Combine with visualizations**:
   ```bash
   python3 src/api/cli.py analyze \
     -i traffic.pcap \
     -p all \
     -r results/report.html \
     -v \
     --output-dir results/charts
   ```

3. **Archive reports by date**:
   ```bash
   mkdir -p reports/$(date +%Y-%m-%d)
   python3 src/protocols/tcp_analyzer.py \
     -i traffic.pcap \
     -r "reports/$(date +%Y-%m-%d)/analysis.html"
   ```

## Troubleshooting

### Charts not appearing
Install matplotlib and seaborn:
```bash
pip install matplotlib seaborn
```

### Report not opening
Check file path and permissions:
```bash
ls -lh results/report.html
```

### Styling issues
Reports use inline CSS and should work in all modern browsers. If you see formatting issues, try:
- Chrome/Chromium
- Firefox
- Edge
- Safari

## Advanced Usage

### Batch Report Generation

```bash
#!/bin/bash
# Generate reports for all PCAP files in a directory

for pcap in data/raw/*.pcap; do
    filename=$(basename "$pcap" .pcap)
    python3 src/protocols/tcp_analyzer.py \
        -i "$pcap" \
        -r "results/${filename}_tcp_report.html"
    
    python3 src/protocols/dns_analyzer.py \
        -i "$pcap" \
        -r "results/${filename}_dns_report.html"
done

echo "Reports generated in results/ directory"
```

### Scheduled Reports

```bash
# Add to crontab for daily reports
0 2 * * * cd /path/to/AI_wireshark && python3 src/api/cli.py analyze -i /var/log/traffic/daily.pcap --output-dir /var/www/html/reports/
```

## Support

For issues or questions about HTML reports:
1. Check that all dependencies are installed
2. Verify PCAP file is valid
3. Check write permissions on output directory
4. Review logs for error messages

---

**Generated by AI-Wireshark-Analyzer v1.0.0**
