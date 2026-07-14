# Documentation

Comprehensive user documentation, guides, and release information.

---

## For Users (Start Here)

| Document | Purpose |
|----------|---------|
| [QUICKSTART.md](QUICKSTART.md) | Usage examples for all analysis panels (GUI and CLI) |
| [DISTRIBUTION.md](DISTRIBUTION.md) | Download, verify checksums, and install |
| [RELEASE_NOTES.md](RELEASE_NOTES.md) | Release history, features, and what's new |

---

## Project Architecture & Design

| Document | Purpose |
|----------|---------|
| [architecture.md](architecture.md) | Internal code structure and data flow |
| [api.md](api.md) | CLI and API-level command reference |
| [PRESENTATION.md](PRESENTATION.md) | Project overview presentation (slide notes) |

---

## Build & Development

For build instructions and scripts, see:
- [../build/README.md](../build/README.md) — Build documentation index
- [../build/BUILD_COMMANDS.md](../build/BUILD_COMMANDS.md) — Step-by-step build guide
- [../installer/README.md](../installer/README.md) — Installer scripts and configuration

---

## Main Project Files

Quick reference for key project files:
- [../README.md](../README.md) — Project overview
- [../PROJECT_SUMMARY.md](../PROJECT_SUMMARY.md) — Features and capabilities
- [../requirements.txt](../requirements.txt) — Python dependencies
- [../LICENSE](../LICENSE) — MIT License

---

## Analysis Guides

### WLAN/WiFi Analysis
See [QUICKSTART.md](QUICKSTART.md) for:
- WPA/WPA2/WPA3 authentication troubleshooting
- Beacon loss and retry diagnostics
- Connection delay analysis
- Signal strength assessment

### IPv6 Analysis
See [QUICKSTART.md](QUICKSTART.md) for:
- IPv6 traffic patterns
- SNMP polling detection
- Router solicitation and NDP analysis
- Statistical metrics (IPI, packet sizes, hourly aggregates)

### Protocol Analysis
See [QUICKSTART.md](QUICKSTART.md) for:
- TCP retransmission detection
- UDP flood identification
- DNS tunneling detection
- DHCP analysis

### Decryption & Post-Decrypt
See [QUICKSTART.md](QUICKSTART.md) for:
- WPA2/WPA3 decryption workflows
- PSK and password-based decryption
- Post-decrypt traffic inspection

---

## Change History

Latest Release: **v1.6.1 (July 2026)**

Key features:
- ✓ IPv6 statistical analysis (IPI stats, packet size distribution, hourly metrics)
- ✓ WPA3-SAE root cause analysis with 24 IEEE 802.11-2020 error codes
- ✓ Automatic forensic report generation
- ✓ Enhanced UI with filtering capabilities
- ✓ ML anomaly detection (fixed GPU issues)

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for complete changelog.
