# Distribution Guide

Instructions for end-users downloading and using AI-Wireshark Analyzer distributions.

**Current Status (July 3, 2026):**
- ✅ Linux x86_64: AVAILABLE (1.1 GB)
  - Checksum: `a4be37eddd713af8e73918ae6c397431cd04cb5b446ed48370f80103840698df`
- ⏳ Windows x64: Ready for build
- ⏳ macOS: Ready for build

**Features in This Release:**
- IPv6 statistical analysis (IPI stats, packet size distribution, hourly metrics, SNMP polling)
- WPA3-SAE root cause analysis (24 IEEE 802.11-2020 error codes with remediation)
- WLAN/WiFi threat detection (40+ IEEE reason/status codes)
- Channel RF analysis with client activity breakdown
- WPA/WPA2/WPA3 decryption
- TCP/UDP diagnostic analysis
- ML anomaly detection

---

## Verify Downloads

Checksums ensure the downloaded file is authentic and uncorrupted.

### Linux & macOS
```bash
sha256sum -c AI-Wireshark-Analyzer-Linux-x64.zip.sha256
# Output: AI-Wireshark-Analyzer-Linux-x64.zip: OK

# Or manually verify
sha256sum AI-Wireshark-Analyzer-Linux-x64.zip
# Compare with contents of .sha256 file
```

### Windows
```powershell
# PowerShell (Windows 10+)
$hash = (Get-FileHash "AI-Wireshark-Analyzer-Windows-x64.zip" -Algorithm SHA256).Hash
$hash  # Compare with .sha256 file

# Or use Certificate Manager
certutil -hashfile AI-Wireshark-Analyzer-Windows-x64.zip SHA256
```

## Installation

### Linux

```bash
# Extract
unzip AI-Wireshark-Analyzer-Linux-x64.zip
cd AI-Wireshark-Analyzer

# Install system dependencies
sudo apt install tshark  # Ubuntu/Debian
sudo dnf install wireshark-cli  # Fedora/RHEL

# Run
./AI-Wireshark-Analyzer
```

**Optional: Add to Applications Menu**
```bash
sudo cp ai-wireshark.desktop ~/.local/share/applications/
# Or: cp ai-wireshark.desktop ~/.local/share/applications/
```

### Windows

#### Option 1: ZIP (Manual)
```cmd
REM Extract ZIP
tar -xf AI-Wireshark-Analyzer-Windows-x64.zip
cd AI-Wireshark-Analyzer

REM Install Wireshark if needed
REM Download from https://wireshark.org/download

REM Run
AI-Wireshark-Analyzer.exe
```

#### Option 2: Installer (If Available)
```cmd
REM Run the installer
AI-Wireshark-Analyzer-Setup-x64.exe

REM Follow the wizard
REM Check "Add to PATH" option
REM Finish - shortcut will be added to Start Menu
```

### macOS

#### Option 1: DMG (Recommended)
```bash
# Open DMG
open AI-Wireshark-Analyzer-macOS.dmg

# Drag app to Applications folder
# (Or use Terminal: cp -r /Volumes/AI-Wireshark-Analyzer/AI-Wireshark-Analyzer.app /Applications/)

# Eject DMG
hdiutil eject /Volumes/AI-Wireshark-Analyzer

# Run from Applications or Spotlight (Cmd+Space, type "AI-Wireshark")
open /Applications/AI-Wireshark-Analyzer.app
```

#### Option 2: ZIP (Manual)
```bash
unzip AI-Wireshark-Analyzer-macOS.zip
cp -r AI-Wireshark-Analyzer.app /Applications/
open /Applications/AI-Wireshark-Analyzer.app
```

## System Requirements

### Linux
- **OS:** Ubuntu 20.04+, Debian 11+, RHEL 9+, Fedora 38+
- **CPU:** x86_64 processor
- **RAM:** 4 GB minimum (8 GB recommended)
- **Storage:** 2 GB for installation + data
- **Dependencies:** `tshark` or `wireshark-cli`

### Windows
- **OS:** Windows 10 (21H2+) or Windows 11
- **CPU:** x64 processor
- **RAM:** 4 GB minimum (8 GB recommended)
- **Storage:** 2 GB for installation + data
- **Visual C++ Redistributable:** Usually pre-installed
- **Dependencies:** Wireshark (for tshark)

### macOS
- **OS:** macOS 11 Big Sur or newer
- **CPU:** Intel (x86_64) or Apple Silicon (M1+)
- **RAM:** 4 GB minimum (8 GB recommended)
- **Storage:** 2 GB for installation + data
- **Dependencies:** Wireshark (via Homebrew)

## Troubleshooting

### Application Won't Start

**Linux:**
```bash
# Check for missing tshark
which tshark

# If not found, install:
sudo apt install tshark  # Debian/Ubuntu
sudo dnf install wireshark-cli  # Fedora/RHEL

# Try running again
./AI-Wireshark-Analyzer
```

**Windows:**
```cmd
REM Check for Visual C++ Redistributable
REM Download from: https://support.microsoft.com/en-us/help/2977003/

REM Ensure Wireshark is installed
where tshark
```

**macOS:**
```bash
# Check quarantine attribute
xattr -l AI-Wireshark-Analyzer.app

# Remove if needed
xattr -dr com.apple.quarantine /Applications/AI-Wireshark-Analyzer.app

# Install Wireshark if needed
brew install wireshark
```

### "tshark" Not Found

All platforms need Wireshark installed for packet capture:

**Linux:**
```bash
sudo apt install tshark  # Debian/Ubuntu
sudo dnf install wireshark-cli  # Fedora/RHEL
sudo pacman -S wireshark-cli  # Arch
```

**Windows:**
- Download from https://wireshark.org/download
- Run installer, select "tshark" during installation

**macOS:**
```bash
brew install wireshark
```

### Out of Memory / Crash

- Close other applications
- Try capturing smaller time windows
- Reduce packet filter complexity
- Increase system swap/pagefile

### GUI Issues / Display Problems

**Linux (No Display):**
- Requires X11 or Wayland display server
- Cannot run on headless systems without display

**macOS (App Won't Open):**
```bash
# Try from Terminal for error messages
open /Applications/AI-Wireshark-Analyzer.app
```

## Security

- **Verify checksums** before running
- **Keep Wireshark updated** for security patches
- **Run packet capture with appropriate privileges** (may need admin/root)
- **Don't share captured data** if it contains sensitive information

## Getting Help

- **Documentation:** See GETTING_STARTED.md in source distribution
- **Issues:** Report at project GitHub repository
- **Building from Source:** See BUILD_GUIDE.md

## Next Steps

1. Extract the distribution
2. Install system dependencies (especially Wireshark/tshark)
3. Launch the application
4. Load a PCAP file or start a packet capture
5. Select analysis type and run
