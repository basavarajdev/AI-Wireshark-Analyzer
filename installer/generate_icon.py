#!/usr/bin/env python3
"""Generate app icon (.ico) for the application.

Converts the Analyser.png brand icon to a multi-resolution .ico file.
Requires: Pillow (pip install Pillow)

Usage:
    python installer/generate_icon.py
"""

from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Installing Pillow for icon generation...")
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow", "-q"])
    from PIL import Image


def create_icon():
    """Convert Analyser.png brand icon to multi-resolution .ico and PNG files."""
    ROOT = Path(__file__).parent.parent
    source_png = ROOT / "installer" / "app_icon.png"

    if not source_png.exists():
        raise FileNotFoundError(f"Source icon not found: {source_png}")

    source = Image.open(str(source_png)).convert("RGBA")
    print(f"Loaded source icon: {source.size} {source.mode}")

    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = []

    for size in sizes:
        resized = source.resize((size, size), Image.LANCZOS)
        images.append(resized)

    # Save as .ico
    output = Path(__file__).parent / "app_icon.ico"
    images[0].save(
        str(output),
        format='ICO',
        sizes=[(s, s) for s in sizes],
        append_images=images[1:]
    )
    print(f"Icon saved: {output}")
    print(f"Resolutions: {sizes}")

    # Save a 256x256 PNG copy for Linux/macOS
    png_output = Path(__file__).parent / "app_icon_256.png"
    images[-1].save(str(png_output))
    print(f"PNG (256px) saved: {png_output}")


if __name__ == "__main__":
    create_icon()
