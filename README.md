# AI-Wireshark Analyzer

Standalone desktop application for analyzing Wireshark captures (PCAP/PCAPNG) with Wi-Fi diagnostics, channel analytics, decryption workflows, protocol checks, and ML anomaly detection.

---

## Current Build Status (June 2026)

| Platform | Package Type | Status |
|----------|--------------|--------|
| Linux x86_64 | PyInstaller folder (`dist/AI-Wireshark-Analyzer/`) | Built and validated |
| Windows x64 | EXE + optional Inno Setup installer | Build on Windows host |
| macOS | App bundle / DMG | Build on macOS host |

Important: desktop binaries must be built on their native OS.

---

## Quick Start

### 1) Install tshark (required)

```bash
sudo apt install tshark          # Ubuntu/Debian
sudo dnf install wireshark-cli   # RHEL/Fedora
brew install wireshark           # macOS
# Windows: install Wireshark from https://wireshark.org/download.html
```

### 2) Launch the app

```bash
# Linux packaged build
./dist/AI-Wireshark-Analyzer/AI-Wireshark-Analyzer

# Source mode (dev)
python -m app.main
```

### 3) Run analysis

1. Open a capture file (`.pcap` / `.pcapng`)
2. Pick panel from sidebar
3. Run analysis
4. Review HTML + JSON results in `results/`

---

## Analysis Panels

| Panel | What it analyzes |
|-------|------------------|
| Home | Overview, guided navigation |
| WLAN / Wi-Fi | Auth failures, beacon/retry/signal diagnostics |
| WPA Decrypt | WPA/WPA2/WPA3 decryption and post-decrypt traffic inspection |
| Channel & Network Map | RF utilization, client activity, station spotlight, combined map |
| TCP/UDP Diagnostics | Retransmissions, zero-window stalls, RST/flood indicators |
| IPv6 Analysis | Per-address ICMPv6/NDP/TCP/UDP/SNMP analysis |
| Protocol Analyzers | TCP/UDP/HTTP/DNS/ICMP/DHCP security-focused checks |
| ML Anomaly | Isolation Forest / Autoencoder anomaly scoring |
| CLI & Workflow | End-to-end flow and command reference |

---

## Documentation

| Document | Purpose |
|----------|---------|
| [GETTING_STARTED.md](GETTING_STARTED.md) | Platform-specific installation and first run |
| [QUICKSTART.md](QUICKSTART.md) | GUI/CLI usage examples by analysis type |
| [BUILD_GUIDE.md](BUILD_GUIDE.md) | Linux/Windows/macOS build and packaging guide |
| [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) | Feature and architecture summary |
| [RELEASE_NOTES.md](RELEASE_NOTES.md) | Release history and current packaging status |
| [docs/architecture.md](docs/architecture.md) | Internal architecture and processing flow |
| [docs/api.md](docs/api.md) | CLI/API-level references |

---

## Requirements

- tshark (Wireshark CLI)
- GUI runtime: Linux desktop session (X11/Wayland), Windows desktop, or macOS desktop
- For source mode only: Python 3.10+

---

## License

MIT License - see [LICENSE](LICENSE)

