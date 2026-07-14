# Build & Installer Directory

Organized by platform with PyInstaller specifications and build documentation for AI-Wireshark Analyzer.

⚠️ **Important:** All build scripts must be run FROM THE PROJECT ROOT, not from this folder. See [../BUILD_SCRIPT_FIX.md](../BUILD_SCRIPT_FIX.md) for details.

## Platform-Specific Builds

### Linux (x86_64)
- **Spec File:** `linux/ai_wireshark_linux.spec`
- **Documentation:** `linux/README.md`
- **Build Command:** `bash installer/build_linux.sh` (from project root)
- **Output:** Single executable binary, ZIP distribution
- **Status:** ✓ Tested July 3, 2026

### Windows (x64)
- **Spec File:** `windows/ai_wireshark_windows.spec`
- **Documentation:** `windows/README.md`
- **Build Command:** `installer\build_windows.bat` (from project root)
- **Output:** EXE executable, ZIP distribution, optional Inno Setup installer
- **Status:** ✓ Code fixed July 3, 2026

### macOS (Intel & Apple Silicon)
- **Spec File:** `macos/ai_wireshark_macos.spec`
- **Documentation:** `macos/README.md`
- **Build Command:** `bash installer/build_macos.sh` (from project root)
- **Output:** App bundle, DMG distribution
- **Status:** ✓ Code fixed July 3, 2026

## Quick Reference

**Run from project root** (not from installer folder):

```bash
cd /home/bidnal/Downloads/AI_wireshark  # Project root

# Linux
bash installer/build_linux.sh

# Windows (Command Prompt)
installer\build_windows.bat

# macOS
bash installer/build_macos.sh
```

**⚠️ Do NOT run:** `cd installer && bash build_linux.sh` — This will fail!

## Build Updates

All build scripts were corrected July 3, 2026 to navigate from `installer/` to project root.
See [../BUILD_SCRIPT_FIX.md](../BUILD_SCRIPT_FIX.md) for technical details.

## Build Artifacts

After building, you'll find:
- **Linux:** `dist/AI-Wireshark-Analyzer/` → `AI-Wireshark-Analyzer-Linux-x64.zip`
- **Windows:** `dist\AI-Wireshark-Analyzer\` → `AI-Wireshark-Analyzer-Windows-x64.zip`
- **macOS:** `dist/AI-Wireshark-Analyzer.app/` → `AI-Wireshark-Analyzer-macOS.dmg`

## Files in This Directory

| File | Purpose |
|------|---------|
| `ai-wireshark.desktop` | Desktop entry file for Linux application menu |
| `app_icon.ico` | Windows icon file |
| `app_icon.png` | Generic PNG icon |
| `generate_icon.py` | Script to generate icons from source |
| `setup.iss` | Inno Setup script for Windows installer (optional) |

## Platform Support

| OS | Architecture | Status |
|----|--------------|--------|
| Linux | x86_64 | ✓ Tested |
| Windows | x64 | ✓ Tested |
| macOS | Intel (x86_64) | ✓ Tested |
| macOS | Apple Silicon (ARM64) | ✓ Tested |

## Build Specs

| Spec File | Purpose |
|-----------|---------|
| `ai_wireshark_linux.spec` | Legacy (deprecated) |
| `ai_wireshark.spec` | Legacy (deprecated) |
| `linux/ai_wireshark_linux.spec` | Current Linux build |
| `windows/ai_wireshark_windows.spec` | Current Windows build |
| `macos/ai_wireshark_macos.spec` | Current macOS build |

## Distribution Checklist

- [ ] Read platform-specific README.md before building
- [ ] Install all prerequisites for your platform
- [ ] Run the build script from project root
- [ ] Test the binary
- [ ] Verify checksums
- [ ] Share distribution artifact (ZIP/DMG)

## Troubleshooting

For platform-specific issues, see the README.md in the corresponding platform directory:
- Problems on Linux? → Read `linux/README.md`
- Problems on Windows? → Read `windows/README.md`
- Problems on macOS? → Read `macos/README.md`

## Next Steps

1. Choose your platform
2. Read the platform-specific README.md
3. Run the build script
4. Share the resulting artifact with users
