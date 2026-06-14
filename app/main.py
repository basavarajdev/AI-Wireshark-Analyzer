#!/usr/bin/env python3
"""AI-Wireshark-Analyzer — Desktop Application Entry Point.

Launch:
    python app/main.py
    # or from project root:
    python -m app.main
"""

import sys
import os
import ctypes.util
from pathlib import Path

# Ensure project root is on sys.path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon

from app.main_window import MainWindow
from app.resources import get_resource_path


def _linux_gui_preflight() -> str:
    """Return a user-facing error when Linux GUI prerequisites are missing."""
    if not sys.platform.startswith("linux"):
        return ""

    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if not has_display:
        return (
            "AI-Wireshark Analyzer requires a graphical desktop session to launch.\n"
            "No X11 or Wayland display was detected in this environment.\n\n"
            "Run the application from a desktop terminal on the target machine, or use X11/Wayland forwarding."
        )

    has_xcb_cursor = bool(
        ctypes.util.find_library("xcb-cursor")
        or ctypes.util.find_library("xcb-cursor0")
        or os.path.exists("/lib/x86_64-linux-gnu/libxcb-cursor.so.0")
        or os.path.exists("/usr/lib/x86_64-linux-gnu/libxcb-cursor.so.0")
    )
    if not has_xcb_cursor:
        return (
            "AI-Wireshark Analyzer could not find the Qt xcb runtime dependency 'libxcb-cursor0'.\n"
            "Install it and start the application again.\n\n"
            "Ubuntu/Debian: sudo apt install libxcb-cursor0\n"
            "RHEL/Fedora: sudo dnf install xcb-util-cursor"
        )

    return ""


def main():
    preflight_error = _linux_gui_preflight()
    if preflight_error:
        print(preflight_error, file=sys.stderr)
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName("AI-Wireshark Analyzer")
    app.setApplicationVersion("1.5.0")
    app.setOrganizationName("AI-Wireshark")

    # Set application icon (Analyser brand icon)
    icon_path = get_resource_path("installer", "app_icon.png")
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    # Set default font
    font = QFont()
    font.setFamilies([
        "Inter",
        "Noto Sans",
        "Segoe UI Variable Text",
        "Segoe UI",
        "Ubuntu",
    ])
    font.setPointSize(11)
    app.setFont(font)

    # Apply dark theme
    from app.styles import DARK_STYLESHEET
    app.setStyleSheet(DARK_STYLESHEET)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
