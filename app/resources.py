"""Helpers for resolving bundled resource paths in dev and PyInstaller builds."""

from pathlib import Path
import sys


def get_resource_path(*parts: str) -> Path:
    """Return absolute path to resource in source tree or PyInstaller bundle."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base = Path(sys._MEIPASS)
    else:
        base = Path(__file__).resolve().parent.parent
    return base.joinpath(*parts)
