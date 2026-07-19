# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec — AI-Wireshark Analyzer (Linux x86_64)

Produces a standalone folder bundle under dist/AI-Wireshark-Analyzer/
containing the executable and all bundled libraries.  No Python install
is required on the target machine; only tshark must be present.

Build:
    source .venv/bin/activate
    pyinstaller installer/ai_wireshark_linux.spec --noconfirm --clean
"""

from pathlib import Path

block_cipher = None
ROOT = Path(SPECPATH).parent          # project root (parent of installer/)

a = Analysis(
    [str(ROOT / 'app' / 'main.py')],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        (str(ROOT / 'config'),                        'config'),
        (str(ROOT / 'installer' / 'app_icon.png'),    'installer'),
    ],
    hiddenimports=[
        # PyQt6
        'PyQt6.sip',
        'PyQt6.QtWebEngineWidgets',
        'PyQt6.QtWebEngineCore',
        # ML / data
        'sklearn',
        'sklearn.ensemble',
        'sklearn.ensemble._iforest',
        'sklearn.preprocessing',
        'sklearn.utils._cython_blas',
        'sklearn.neighbors._partition_nodes',
        'pandas',
        'numpy',
        'scipy',
        'joblib',
        # Network parsing
        'pyshark',
        # Utilities
        'loguru',
        'yaml',
        # Project modules — protocols
        'src.protocols.tcp_analyzer',
        'src.protocols.udp_analyzer',
        'src.protocols.dns_analyzer',
        'src.protocols.http_analyzer',
        'src.protocols.https_analyzer',
        'src.protocols.icmp_analyzer',
        'src.protocols.dhcp_analyzer',
        'src.protocols.wlan_analyzer',
        'src.protocols.wlan_decryptor',
        'src.protocols.wlan_rf_monitor',
        # Project modules — core
        'src.core.model',
        'src.core.utils',
        'src.parsers.packet_parser',
        'src.preprocessing.cleaning',
        'src.preprocessing.feature_engineering',
        'src.reports.html_generator',
        'src.api.cli',
        # Analysis scripts — bundled as bytecode (no .py exposed)
        'scripts.run_wlan_analysis',
        'scripts.run_ipv6_analysis',
        'scripts.run_channel_monitor',
        'scripts.analyze_tcp_udp',
        'scripts.build_client_map_report',
        'scripts.build_combined_report',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'test',
        'unittest',
        'xmlrpc',
        'lib2to3',
        'ensurepip',
    ],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AI-Wireshark-Analyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,           # GUI app — no terminal window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / 'installer' / 'app_icon.png'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=['libQt6*', 'libssl*', 'libcrypto*'],
    name='AI-Wireshark-Analyzer',
)
