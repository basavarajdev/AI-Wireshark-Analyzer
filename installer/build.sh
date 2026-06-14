#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
#  AI-Wireshark Analyzer — Linux/macOS Build Script
#
#  This builds the standalone application bundle.
#
#  Usage:
#    ./installer/build.sh           — Build standalone app
#    ./installer/build.sh clean     — Remove build artifacts
# ══════════════════════════════════════════════════════════════════════════════

set -e
cd "$(dirname "$0")/.."

echo ""
echo " ╔══════════════════════════════════════════════════════════╗"
echo " ║   AI-Wireshark Analyzer — Build System                  ║"
echo " ╚══════════════════════════════════════════════════════════╝"
echo ""

if [ "$1" = "clean" ]; then
    echo "[CLEAN] Removing build artifacts..."
    rm -rf dist/ build/
    echo "[OK] Clean complete."
    exit 0
fi

# Check dependencies
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python3 not found."
    exit 1
fi

echo "[OK] Python: $(python3 --version)"

# Ensure PyInstaller is available
if ! python3 -m PyInstaller --version &> /dev/null 2>&1; then
    echo "[INFO] Installing PyInstaller..."
    pip install pyinstaller
fi

echo "[OK] PyInstaller: $(python3 -m PyInstaller --version)"
echo ""
echo "[1/2] Building standalone executable..."
echo "      This may take 3-5 minutes..."
echo ""

python3 -m PyInstaller installer/ai_wireshark.spec --noconfirm --clean

echo ""
echo "[2/2] Verifying build..."

if [ -f "dist/AI-Wireshark-Analyzer/AI-Wireshark-Analyzer" ]; then
    SIZE=$(du -sh dist/AI-Wireshark-Analyzer/ | cut -f1)
    echo "[OK] Build successful! Size: $SIZE"
    echo "     Location: dist/AI-Wireshark-Analyzer/"
    echo ""
    echo " To run:"
    echo "     ./dist/AI-Wireshark-Analyzer/AI-Wireshark-Analyzer"
elif [ -f "dist/AI-Wireshark-Analyzer/AI-Wireshark-Analyzer.exe" ]; then
    echo "[OK] Build successful (Windows .exe)"
    echo "     Location: dist/AI-Wireshark-Analyzer/"
else
    echo "[ERROR] Build output not found."
    exit 1
fi

echo ""
echo " ╔══════════════════════════════════════════════════════════╗"
echo " ║   BUILD COMPLETE                                        ║"
echo " ╚══════════════════════════════════════════════════════════╝"
echo ""
