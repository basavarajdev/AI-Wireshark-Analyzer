#!/bin/bash
# AI-Wireshark Analyzer - macOS Build Script
# For macOS 11+ with Python 3.10+
# Usage: bash installer/build_macos.sh (from project root)

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../" && pwd)"
cd "$PROJECT_ROOT"

echo ""
echo "================================"
echo "AI-Wireshark Analyzer - macOS Build"
echo "================================"
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "✓ Python version: $PYTHON_VERSION"

# Check for required tools
command -v brew &> /dev/null || { echo "✗ Homebrew not found. Install from https://brew.sh"; exit 1; }
echo "✓ Homebrew installed"

# Install required tools
echo ""
echo "Installing/checking required tools..."
brew list wireshark &>/dev/null && echo "✓ Wireshark installed" || echo "? Wireshark not installed (optional for build, required for runtime)"

# Activate virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate
echo "✓ Virtual environment activated"

# Install/update dependencies
echo ""
echo "Installing dependencies..."
pip install --upgrade pip
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
APP_BUNDLE="dist/AI-Wireshark-Analyzer.app"
BINARY="$APP_BUNDLE/Contents/MacOS/AI-Wireshark-Analyzer"

if [ -f "$BINARY" ]; then
    SIZE=$(du -h "$BINARY" | cut -f1)
    echo "✓ App bundle created: $SIZE"
    echo "  Location: $APP_BUNDLE"
else
    echo "✗ Build failed: App bundle not found"
    exit 1
fi

# Create DMG (optional, requires create-dmg)
echo ""
if command -v create-dmg &> /dev/null; then
    echo "Creating DMG installer..."
    DMG_NAME="AI-Wireshark-Analyzer-macOS.dmg"
    rm -f "$DMG_NAME"
    
    create-dmg \
        --volname "AI-Wireshark Analyzer" \
        --app-drop-link 425 120 \
        --icon-size 120 \
        "$DMG_NAME" \
        "dist/"
    
    if [ -f "$DMG_NAME" ]; then
        DMG_SIZE=$(du -h "$DMG_NAME" | cut -f1)
        echo "✓ DMG created: $DMG_SIZE"
        
        # Generate checksum
        shasum -a 256 "$DMG_NAME" > "$DMG_NAME.sha256"
        CHECKSUM=$(cat "$DMG_NAME.sha256" | awk '{print $1}')
        echo "✓ SHA256: ${CHECKSUM:0:16}..."
    fi
else
    echo "Note: create-dmg not installed. Skipping DMG creation."
    echo "To create DMG: brew install create-dmg"
    echo "Then run: create-dmg --volname 'AI-Wireshark Analyzer' --app-drop-link 425 120 AI-Wireshark-Analyzer-macOS.dmg dist/"
fi

# Generate checksum for app bundle
echo ""
BUNDLE_SIZE=$(du -sh "$APP_BUNDLE" | cut -f1)
echo "✓ App bundle size: $BUNDLE_SIZE"

# Next steps
echo ""
echo "================================"
echo "Build Complete!"
echo "================================"
echo ""
echo "Artifacts:"
echo "  • App Bundle: $APP_BUNDLE"
if [ -f "AI-Wireshark-Analyzer-macOS.dmg" ]; then
    echo "  • DMG: AI-Wireshark-Analyzer-macOS.dmg"
    echo "  • Checksum: AI-Wireshark-Analyzer-macOS.dmg.sha256"
fi
echo ""
echo "Next steps:"
echo "  1. Test the app bundle:"
echo "     open '$APP_BUNDLE'"
echo ""
echo "  2. For distribution, create DMG:"
echo "     brew install create-dmg"
echo "     bash build_macos.sh"
echo ""
if [ -f "AI-Wireshark-Analyzer-macOS.dmg" ]; then
    echo "  3. Verify DMG integrity:"
    echo "     hdiutil verify AI-Wireshark-Analyzer-macOS.dmg"
    echo ""
    echo "  4. Note: You may need to sign and notarize for distribution"
fi
echo ""
echo "To deactivate venv: deactivate"
