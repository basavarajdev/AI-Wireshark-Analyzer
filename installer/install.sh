#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
#  AI-Wireshark Analyzer — Standalone Installation Script (Linux/macOS)
#
#  Installs the application system-wide like a regular app.
#  No virtual environment needed.
#
#  Usage:
#    sudo ./install.sh              — Install system-wide
#    sudo ./install.sh --uninstall  — Remove installation
#    ./install.sh --user            — Install for current user only (no sudo)
# ══════════════════════════════════════════════════════════════════════════════

set -e
APP_NAME="AI-Wireshark Analyzer"
APP_CMD="ai-wireshark"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo " ╔══════════════════════════════════════════════════════════╗"
echo " ║   AI-Wireshark Analyzer — Installer                     ║"
echo " ╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Parse arguments ──
USER_INSTALL=false
UNINSTALL=false

for arg in "$@"; do
    case $arg in
        --user)
            USER_INSTALL=true
            ;;
        --uninstall)
            UNINSTALL=true
            ;;
        --help|-h)
            echo "Usage: ./install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --user       Install for current user only (no sudo required)"
            echo "  --uninstall  Remove the installation"
            echo "  --help       Show this help message"
            echo ""
            exit 0
            ;;
    esac
done

# ── Uninstall ──
if [ "$UNINSTALL" = true ]; then
    echo -e "${YELLOW}[UNINSTALL]${NC} Removing AI-Wireshark Analyzer..."
    
    if [ "$USER_INSTALL" = true ]; then
        pip uninstall ai-wireshark-analyzer -y 2>/dev/null || true
        rm -f "$HOME/.local/share/applications/ai-wireshark.desktop"
    else
        if [ "$EUID" -ne 0 ]; then
            echo -e "${RED}[ERROR]${NC} System-wide uninstall requires sudo."
            echo "       Run: sudo ./install.sh --uninstall"
            exit 1
        fi
        pip uninstall ai-wireshark-analyzer -y 2>/dev/null || true
        rm -f /usr/share/applications/ai-wireshark.desktop
        rm -f /usr/share/pixmaps/ai-wireshark.png
        rm -f /usr/local/bin/ai-wireshark-gui
    fi
    
    echo -e "${GREEN}[OK]${NC} Uninstallation complete."
    exit 0
fi

# ── Check prerequisites ──
echo "[1/5] Checking prerequisites..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} Python3 not found. Please install Python 3.8+."
    echo "       Ubuntu/Debian: sudo apt install python3 python3-pip"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "  ${GREEN}✓${NC} Python $PYTHON_VERSION"

# Check pip
if ! python3 -m pip --version &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} pip not found. Please install pip."
    echo "       Ubuntu/Debian: sudo apt install python3-pip"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} pip available"

# Check tshark
if command -v tshark &> /dev/null; then
    TSHARK_VER=$(tshark --version 2>/dev/null | head -1)
    echo -e "  ${GREEN}✓${NC} tshark found: $TSHARK_VER"
else
    echo -e "  ${YELLOW}⚠${NC} tshark not found. Install Wireshark for full functionality."
    echo "       Ubuntu/Debian: sudo apt install tshark"
    echo "       Continuing installation anyway..."
fi

# ── Install dependencies and application ──
echo ""
echo "[2/5] Installing application and dependencies..."
echo "      This may take a few minutes..."
echo ""

if [ "$USER_INSTALL" = true ]; then
    # User-level install (no sudo needed)
    python3 -m pip install --user --upgrade pip setuptools wheel 2>/dev/null || true
    python3 -m pip install --user "$APP_DIR"
    PIP_FLAG="--user"
else
    # System-wide install (requires sudo)
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} System-wide install requires sudo."
        echo "       Run: sudo ./install.sh"
        echo "       Or use: ./install.sh --user (for user-only install)"
        exit 1
    fi
    python3 -m pip install --upgrade pip setuptools wheel 2>/dev/null || true
    python3 -m pip install "$APP_DIR" --break-system-packages 2>/dev/null || \
    python3 -m pip install "$APP_DIR"
    PIP_FLAG=""
fi

echo ""
echo -e "${GREEN}[OK]${NC} Application installed successfully."

# ── Install desktop entry ──
echo ""
echo "[3/5] Installing desktop integration..."

DESKTOP_ENTRY="[Desktop Entry]
Name=AI-Wireshark Analyzer
Comment=AI-powered network packet analysis tool
Exec=ai-wireshark-gui
Icon=ai-wireshark
Terminal=false
Type=Application
Categories=Network;Security;Development;
MimeType=application/vnd.tcpdump.pcap;application/x-pcapng;
Keywords=wireshark;pcap;network;packet;analysis;
StartupNotify=true
"

if [ "$USER_INSTALL" = true ]; then
    DESKTOP_DIR="$HOME/.local/share/applications"
    ICON_DIR="$HOME/.local/share/icons"
    mkdir -p "$DESKTOP_DIR" "$ICON_DIR"
    echo "$DESKTOP_ENTRY" > "$DESKTOP_DIR/ai-wireshark.desktop"
    if [ -f "$APP_DIR/installer/app_icon_orig.png" ]; then
        cp "$APP_DIR/installer/app_icon_orig.png" "$ICON_DIR/ai-wireshark.png"
    fi
    echo -e "  ${GREEN}✓${NC} Desktop entry installed to $DESKTOP_DIR"
else
    echo "$DESKTOP_ENTRY" > /usr/share/applications/ai-wireshark.desktop
    if [ -f "$APP_DIR/installer/app_icon_orig.png" ]; then
        cp "$APP_DIR/installer/app_icon_orig.png" /usr/share/pixmaps/ai-wireshark.png
    fi
    echo -e "  ${GREEN}✓${NC} Desktop entry installed system-wide"
fi

# ── Verify installation ──
echo ""
echo "[4/5] Verifying installation..."

if command -v ai-wireshark &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} 'ai-wireshark' CLI command available"
else
    # For --user installs, the binary might be in ~/.local/bin
    if [ "$USER_INSTALL" = true ] && [ -f "$HOME/.local/bin/ai-wireshark" ]; then
        echo -e "  ${GREEN}✓${NC} 'ai-wireshark' CLI installed to ~/.local/bin/"
        if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
            echo -e "  ${YELLOW}⚠${NC} Add ~/.local/bin to your PATH:"
            echo "       export PATH=\"\$HOME/.local/bin:\$PATH\""
            echo "       (Add this to ~/.bashrc or ~/.profile for persistence)"
        fi
    else
        echo -e "  ${YELLOW}⚠${NC} 'ai-wireshark' command not found in PATH (may need terminal restart)"
    fi
fi

if command -v ai-wireshark-gui &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} 'ai-wireshark-gui' command available"
elif [ "$USER_INSTALL" = true ] && [ -f "$HOME/.local/bin/ai-wireshark-gui" ]; then
    echo -e "  ${GREEN}✓${NC} 'ai-wireshark-gui' installed to ~/.local/bin/"
fi

# ── Done ──
echo ""
echo "[5/5] Installation complete!"
echo ""
echo " ╔══════════════════════════════════════════════════════════╗"
echo " ║   INSTALLATION COMPLETE                                 ║"
echo " ╠══════════════════════════════════════════════════════════╣"
echo " ║                                                         ║"
echo " ║   Launch GUI:    ai-wireshark-gui                       ║"
echo " ║   Launch CLI:    ai-wireshark --help                    ║"
echo " ║                                                         ║"
echo " ║   Or find 'AI-Wireshark Analyzer' in your              ║"
echo " ║   application menu.                                     ║"
echo " ║                                                         ║"
echo " ║   Uninstall:                                            ║"
if [ "$USER_INSTALL" = true ]; then
echo " ║     ./install.sh --user --uninstall                     ║"
else
echo " ║     sudo ./install.sh --uninstall                       ║"
fi
echo " ║                                                         ║"
echo " ╚══════════════════════════════════════════════════════════╝"
echo ""
