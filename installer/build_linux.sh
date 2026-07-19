#!/bin/bash
# AI-Wireshark Analyzer - Linux x86_64 Build Script
# For Ubuntu/Debian, RHEL/Fedora, and other Linux distributions
# Usage: bash installer/build_linux.sh (from project root)

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../" && pwd)"
cd "$PROJECT_ROOT"

echo "================================"
echo "AI-Wireshark Analyzer - Linux Build"
echo "================================"
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "✓ Python version: $PYTHON_VERSION"

# Activate virtual environment
if [ -d ".venv" ]; then
    echo "Removing existing virtual environment to avoid stale dependency state..."
    rm -rf .venv
fi

echo "Creating virtual environment..."
python3 -m venv .venv

source .venv/bin/activate
echo "✓ Virtual environment activated"

# Install/update dependencies
echo ""
echo "Installing dependencies..."
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install pyinstaller

# Clean previous builds
echo ""
echo "Cleaning previous builds..."
rm -rf build/ dist/ *.spec

# Run tests
echo ""
echo "Running tests..."
python -m pytest tests/test_v160_release.py -v --tb=short || true

# Build with PyInstaller
echo ""
echo "Building application with PyInstaller..."
python3 -m PyInstaller installer/ai_wireshark.spec --noconfirm --clean

# Verify build
echo ""
echo "Verifying build..."
BINARY="dist/AI-Wireshark-Analyzer/AI-Wireshark-Analyzer"
if [ -f "$BINARY" ]; then
    SIZE=$(du -h "$BINARY" | cut -f1)
    echo "✓ Binary created: $SIZE"
    echo "  Location: $BINARY"
else
    echo "✗ Build failed: Binary not found"
    exit 1
fi

# Create distribution package
echo ""
echo "Creating distribution package..."
DIST_DIR="dist/AI-Wireshark-Analyzer"
SIZE=$(du -sh "$DIST_DIR" | cut -f1)
echo "✓ Application directory: $SIZE"

cd dist && zip -r ../AI-Wireshark-Analyzer-Linux-x64.zip AI-Wireshark-Analyzer > /dev/null 2>&1 && cd ..
ZIP_SIZE=$(du -h AI-Wireshark-Analyzer-Linux-x64.zip | cut -f1)
echo "✓ Distribution ZIP created: $ZIP_SIZE"

# Generate checksum
sha256sum AI-Wireshark-Analyzer-Linux-x64.zip > AI-Wireshark-Analyzer-Linux-x64.zip.sha256
CHECKSUM=$(cat AI-Wireshark-Analyzer-Linux-x64.zip.sha256 | awk '{print $1}')
echo "✓ SHA256: ${CHECKSUM:0:16}..."

# Next steps
echo ""
echo "================================"
echo "Build Complete!"
echo "================================"
echo ""
echo "Artifacts:"
echo "  • Binary: $BINARY"
echo "  • Distribution: AI-Wireshark-Analyzer-Linux-x64.zip"
echo "  • Checksum: AI-Wireshark-Analyzer-Linux-x64.zip.sha256"
echo ""
echo "Next steps:"
echo "  1. Test the binary:"
echo "     ./dist/AI-Wireshark-Analyzer/AI-Wireshark-Analyzer"
echo ""
echo "  2. Verify ZIP integrity:"
echo "     unzip -t AI-Wireshark-Analyzer-Linux-x64.zip"
echo ""
echo "  3. Distribute the ZIP file to users"
echo ""
echo "To deactivate venv: deactivate"
