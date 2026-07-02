#!/usr/bin/env bash
# Launcher for AI-Wireshark Analyzer
# Works with or without a virtual environment

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$APP_DIR/.venv"

if [ -f "$VENV/bin/python" ]; then
    PYTHON="$VENV/bin/python"
else
    PYTHON="python3"
fi

exec "$PYTHON" "$APP_DIR/app/main.py" "$@"
