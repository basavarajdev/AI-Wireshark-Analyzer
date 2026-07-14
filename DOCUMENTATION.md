# Project Documentation Guide

Complete navigation guide for AI-Wireshark Analyzer documentation.

---

## 📍 Quick Navigation

### For Users (Non-Technical)
1. **First Time?** → [QUICKSTART.md](docs/QUICKSTART.md) — GUI walkthrough by analysis type
2. **Need to Install?** → [DISTRIBUTION.md](docs/DISTRIBUTION.md) — Download and verify checksums
3. **What's New?** → [RELEASE_NOTES.md](docs/RELEASE_NOTES.md) — Features and changes

### For Developers & Builders
1. **Quick Build** → Run `bash installer/build_linux.sh` (or `build_macos.sh`, `build_windows.bat`)
2. **Full Details** → [build/README.md](build/README.md) — Build documentation index
3. **Manual Build** → [build/BUILD_COMMANDS.md](build/BUILD_COMMANDS.md) — Step-by-step instructions
4. **Troubleshooting** → [build/COMMANDS_REFERENCE.md](build/COMMANDS_REFERENCE.md) — All commands explained

### For Architects & Contributors
1. **Project Overview** → [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) — Features and architecture
2. **Code Structure** → [docs/architecture.md](docs/architecture.md) — Internal organization
3. **API Reference** → [docs/api.md](docs/api.md) — CLI and programmatic interfaces

---

## 📁 File Organization

### Root Level (Project Files)
```
├── README.md                    🎯 Start here - project overview
├── PROJECT_SUMMARY.md           Feature set and architecture
├── DOCUMENTATION.md             This file - navigation guide
├── requirements.txt             Python dependencies
├── setup.py                     Package configuration
├── LICENSE                      MIT License
```

### build/ — Build System Documentation
```
├── README.md                    Build documentation index
├── BUILD_COMMANDS.md            Step-by-step manual build (all platforms)
├── BUILD_GUIDE.md               Quick build status and overview
├── BUILD_INSTRUCTIONS.md        Prerequisites and detailed steps
├── BUILD_SUMMARY.md             Complete build system status
├── BUILD_COMMANDS_QUICK_REF.md  Quick reference cheat sheet
├── BUILD_SUMMARY_FINAL.txt      Final comprehensive summary
└── COMMANDS_REFERENCE.md        Command reference with examples
```

### docs/ — User Documentation
```
├── README.md                    Documentation index
├── QUICKSTART.md                Usage guide - GUI and CLI walkthrough
├── DISTRIBUTION.md              Download, verify, and install
├── RELEASE_NOTES.md             Release history and changelog
├── architecture.md              Internal code structure
├── api.md                        CLI and API reference
└── PRESENTATION.md              Project overview presentation
```

### installer/ — Build Scripts & Configuration
```
├── README.md                    Installer scripts index
├── build_linux.sh               Linux build automation
├── build_macos.sh               macOS build automation
├── build_windows.bat            Windows build automation
├── install.sh                   Development environment setup
├── wifi.sh                      WiFi capture utility
├── ai_wireshark.spec            PyInstaller specification
├── ai-wireshark.desktop         Linux application entry
├── app_icon.{ico,png}           Application icons
├── generate_icon.py             Icon generation script
├── setup.iss                    Windows Inno Setup config
├── linux/                       Linux-specific config
├── windows/                     Windows-specific config
└── macos/                       macOS-specific config
```

---

## 🎯 Common Tasks

### "I want to use the application"
1. Read [QUICKSTART.md](docs/QUICKSTART.md) for GUI walkthrough
2. Get binary from [DISTRIBUTION.md](docs/DISTRIBUTION.md)
3. Run analysis from GUI or CLI

### "I want to build the application"
1. Clone/download project
2. Read [build/README.md](build/README.md) for overview
3. Run: `bash installer/build_linux.sh` (or equivalent)
4. Check [build/BUILD_COMMANDS.md](build/BUILD_COMMANDS.md) if issues

### "I want to understand the code"
1. Start with [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) for capabilities
2. Review [docs/architecture.md](docs/architecture.md) for structure
3. Check [docs/api.md](docs/api.md) for interfaces

### "I'm a contributor"
1. Review [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) for current status
2. Check [RELEASE_NOTES.md](docs/RELEASE_NOTES.md) for recent changes
3. See [docs/architecture.md](docs/architecture.md) for adding features
4. Follow build guide for testing changes

### "I want to distribute this"
1. Build: `bash installer/build_linux.sh` (etc.)
2. Verify: Check [build/BUILD_COMMANDS_QUICK_REF.md](build/BUILD_COMMANDS_QUICK_REF.md)
3. Share: Send ZIP + .sha256 file to users
4. Help users: Point them to [DISTRIBUTION.md](docs/DISTRIBUTION.md)

---

## 📊 Documentation by Purpose

### Feature Documentation
- **What can it do?** → [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)
- **What's the latest?** → [RELEASE_NOTES.md](docs/RELEASE_NOTES.md)
- **How do I use it?** → [QUICKSTART.md](docs/QUICKSTART.md)

### Technical Documentation
- **How is it built?** → [build/README.md](build/README.md)
- **What's inside?** → [docs/architecture.md](docs/architecture.md)
- **What are the APIs?** → [docs/api.md](docs/api.md)

### Build & Distribution
- **How do I build it?** → [build/BUILD_COMMANDS.md](build/BUILD_COMMANDS.md)
- **How do I run the build?** → [build/BUILD_COMMANDS_QUICK_REF.md](build/BUILD_COMMANDS_QUICK_REF.md)
- **How do I distribute?** → [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md)
- **What are the build scripts?** → [installer/README.md](installer/README.md)

---

## 🔗 Cross-References

### From README.md
- User docs → [docs/QUICKSTART.md](docs/QUICKSTART.md)
- Build docs → [build/README.md](build/README.md)
- Distribution → [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md)
- Architecture → [docs/architecture.md](docs/architecture.md)

### From PROJECT_SUMMARY.md
- Standalone features, no external links

### From build/ Files
- Installer scripts → [installer/README.md](installer/README.md)
- Documentation → This file

### From docs/ Files
- Build system → [build/README.md](build/README.md)
- Home → [README.md](../README.md)
- Project → [PROJECT_SUMMARY.md](../PROJECT_SUMMARY.md)

---

## 📋 Checklist for Documentation Maintenance

After updating files:
- [ ] Update cross-references if files move
- [ ] Verify relative paths in all documents
- [ ] Check that README.md reflects latest status
- [ ] Update RELEASE_NOTES.md with changes
- [ ] Verify build commands in installer/README.md
- [ ] Test build scripts with documented commands
- [ ] Update this file if structure changes

---

## 🆘 Troubleshooting Documentation Issues

**"I can't find [document]"**
- Check if moved to [build/](build/) or [docs/](docs/)
- See file organization section above

**"A link is broken"**
- Check relative paths (should use `../` for parent folder)
- Verify file exists in new location

**"Build command doesn't work"**
- Check [build/README.md](build/README.md) for current location
- See [build/BUILD_COMMANDS.md](build/BUILD_COMMANDS.md) for steps
- Run from project root: `bash installer/build_linux.sh`

---

## 📝 Version Information

- **Project Version:** v1.6.1
- **Documentation Updated:** July 2026
- **Build System:** PyInstaller 6.21
- **Python Version:** 3.10+

Last updated: See [RELEASE_NOTES.md](docs/RELEASE_NOTES.md) for details.
