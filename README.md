# AI-Wireshark Analyzer

Standalone desktop application for analyzing Wireshark captures (PCAP/PCAPNG) with Wi-Fi diagnostics, channel analytics, decryption workflows, protocol checks, ML anomaly detection, and comprehensive filtering capabilities.

---

## Current Build Status (July 2026)

| Platform | Package Type | Status |
|----------|--------------|--------|
| Linux x86_64 | PyInstaller folder (`dist/AI-Wireshark-Analyzer/`) | Built and validated ✓ |
| Windows x64 | EXE + optional Inno Setup installer | Build on Windows host |
| macOS | App bundle / DMG | Build on macOS host |

Important: desktop binaries must be built on their native OS.

**Latest Release (v1.6.2 — July 2026):**
- ✓ **Connection Lifecycle Analysis:** 802.11 auth→assoc timing, SAE rounds, deauth/disassoc tracking with 65+ status/reason codes
- ✓ **Protocol Detection:** DPP (Easy Connect), WPS, Wi-Fi Direct, and printer scan cycle analysis
- ✓ **DHCP Analysis Framework:** IP provisioning and address assignment tracking (enhanced in next release)
- ✓ **Data Transfer Quality:** TCP/UDP throughput, link quality assessment, signal strength, retry rate analysis
- ✓ Full STA (Station) lifecycle profiling: connection → DHCP → data transfers
- ✓ Enhanced HTML/JSON reports with per-capture remediation advice

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
3. Apply optional filters (IP address, ports)
4. Run analysis
5. Review HTML + JSON results in `results/`

---

## Building Distributions

### From Source

Build standalone distributions for your platform:

```bash
# Linux
bash installer/build_linux.sh

# Windows (Command Prompt)
installer\build_windows.bat

# macOS
bash installer/build_macos.sh
```

**Output:**
- Linux: `AI-Wireshark-Analyzer-Linux-x64.zip` (1.1 GB)
- Windows: `AI-Wireshark-Analyzer-Windows-x64.zip` (1.1 GB)
- macOS: `AI-Wireshark-Analyzer-macOS.dmg` (1.1 GB)

Each package includes the binary, dependencies, and a checksum for verification.

**For detailed build instructions:**
- See [build/BUILD_SUMMARY.md](build/BUILD_SUMMARY.md) for complete workflow
- Or platform-specific guide: [installer/README.md](installer/README.md)

---

## Analysis Panels

| Panel | What it analyzes | Latest Updates |
|-------|-----------------|----------------|
| Home | Overview, guided navigation | — |
| WLAN / Wi-Fi | Auth failures, beacon/retry/signal diagnostics | **v1.7.1:** Connection failures prioritised; dynamic per-BSSID retry; connection delay root cause |
| WPA Decrypt | WPA/WPA2/WPA3 decryption and post-decrypt traffic inspection | — |
| Channel & Network Map | RF utilization, client activity, station spotlight, combined map | — |
| TCP/UDP Diagnostics | Retransmissions, zero-window stalls, RST/flood indicators | **v1.7.0:** IP & port filters; dynamic HTML report |
| IPv6 Analysis | Per-address ICMPv6/NDP/TCP/UDP/SNMP analysis; statistical metrics | **v1.7.1:** Specific IP in NDP/DAD/NXDOMAIN remediations |
| Protocol Analyzers | TCP/UDP/DNS/ICMP/DHCP security-focused checks | **v1.7.1:** Dynamic RCA with specific IPs/rates; **v1.7.0:** HTTP/HTTPS merged into TCP (port-based) |
| ML Anomaly | Isolation Forest / Autoencoder anomaly scoring | **FIXED:** GPU crash |
| CLI & Workflow | End-to-end flow and command reference | — |

---

## Documentation

### For End Users
| Document | Purpose |
|----------|---------|
| [GETTING_STARTED.md](GETTING_STARTED.md) | Platform-specific installation and first run |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | GUI/CLI usage examples by analysis type |
| [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) | Download, verify checksums, and install distributions |

### For Developers & Builders
| Document | Purpose |
|----------|---------|
| [build/BUILD_SUMMARY.md](build/BUILD_SUMMARY.md) | Complete build system overview and workflow |
| [build/BUILD_GUIDE.md](build/BUILD_GUIDE.md) | Quick build status and overview |
| [build/BUILD_INSTRUCTIONS.md](build/BUILD_INSTRUCTIONS.md) | Detailed multi-platform build prerequisites and steps |
| [installer/README.md](installer/README.md) | Platform-specific build configuration and scripts |
| [installer/linux/README.md](installer/linux/README.md) | Linux build documentation |
| [installer/windows/README.md](installer/windows/README.md) | Windows build documentation |
| [installer/macos/README.md](installer/macos/README.md) | macOS build documentation |

### Project Documentation
| Document | Purpose |
|----------|---------|
| [ENHANCEMENTS_2026_Q3.md](ENHANCEMENTS_2026_Q3.md) | **NEW:** Connection lifecycle, protocol detection, DHCP & data transfer analysis |
| [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) | Feature and architecture summary |
| [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md) | Release history and current packaging status |
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