# -*- mode: python ; coding: utf-8 -*-
# AI-Wireshark Analyzer PyInstaller Spec File

block_cipher = None

a = Analysis(
    ['../app/main.py'],
    pathex=['..'],
    binaries=[],
    datas=[
        ('../config', 'config'),
        ('../src', 'src'),
        ('../installer/app_icon_orig.png', 'installer'),
    ],
    hiddenimports=[
        'pyshark',
        'scapy', 
        'scapy.layers',
        'scapy.layers.l2',
        'scapy.layers.inet',
        'scapy.layers.inet6',
        'pandas',
        'pandas.io.json',
        'loguru',
        'urllib3',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'tcltk',
        'pytest',
        'pytest_asyncio',
        '_pytest',
        'pytest_cov',
        'cryptography',
    ],
    noarchive=False,
    optimize=0,
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
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='installer/app_icon_orig.png',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='AI-Wireshark-Analyzer',
)
