#!/usr/bin/env python3
"""
WLAN Channel Monitor
====================
Quantifies channel utilisation, throughput, retry pressure, and overload
indicators from a live capture interface or a saved pcap/pcapng file.

Metrics (per rolling window and overall):
  - Channel utilisation %   (estimated airtime used / window duration)
  - Data throughput (Mbps)
  - Frame rate (fps)
  - Retry rate (%)          (data + QoS data frames)
  - RTS/CTS ratio           (hidden-node indicator)
  - Frame-type breakdown    (mgmt / ctrl / data % share)
  - PHY mode distribution   (802.11b/g/n/ac/ax)
  - Per-BSSID summary       (frames, bytes, clients, avg RSSI, SSID)
    * Client activity breakdown: Actively connected (>50 frames) vs
      medium activity (6-50 frames) vs low activity (≤5 frames)
  - Per-client summary      (frames, bytes, retry rate, avg RSSI, role)
  - Overload flags          (util > 80%, retry > 15%, ctrl overhead > 20%)

Usage
-----
  # From pcap file:
  python scripts/run_channel_monitor.py --pcap <file.pcap> [--channel 6]

  # Live capture (interface must already be in monitor mode):
  python scripts/run_channel_monitor.py --iface wlan0mon --channel 6 [--duration 60]

  # Focus on a specific BSSID or client MAC:
  python scripts/run_channel_monitor.py --pcap <file> --bssid 00:04:EA:38:70:E0
  python scripts/run_channel_monitor.py --pcap <file> --mac F8:ED:FC:FE:F0:06

  # Station performance spotlight (full channel + dedicated station section):
  python scripts/run_channel_monitor.py --pcap <file> --station F8:ED:FC:FE:F0:06

  # Save report:
  python scripts/run_channel_monitor.py --pcap <file> --out results/ch6_monitor

Options
-------
  --interval    Rolling window size in seconds (default: 10)
  --duration    Live capture time in seconds   (default: 60)
  --top-n       Top-N talkers to show          (default: 10)
  --out         Output path prefix for .json + _report.html
  --station     MAC address of a station to spotlight (full channel stats +
                dedicated station profile: TX/RX, retry vs channel avg, signal,
                airtime share, associated APs, data rates, events, issues)
"""

import argparse
import json
import math
import re
import subprocess
import sys
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from loguru import logger

# ─────────────────────────────────────────────────────────────────────────────
# 802.11 frame-type classification (tshark hex type_subtype values)
# ─────────────────────────────────────────────────────────────────────────────
MGMT_SET = set(f'0x{v:04x}' for v in range(0x00, 0x10))   # type=0: 0x00-0x0e
CTRL_SET = set(f'0x{v:04x}' for v in range(0x10, 0x20))   # type=1: 0x10-0x1f
DATA_SET = set(f'0x{v:04x}' for v in range(0x20, 0x30))   # type=2: 0x20-0x2f

# Named subtypes used in analysis
BEACON       = '0x0008'
PROBE_REQ    = '0x0004'
PROBE_RESP   = '0x0005'
RTS          = '0x001b'
CTS          = '0x001c'
ACK          = '0x001d'
BLOCK_ACK_R  = '0x0018'
BLOCK_ACK    = '0x0019'
PS_POLL      = '0x001a'
NULL_DATA    = '0x0024'
QOS_NULL     = '0x002c'
DATA_SUBTYPES = DATA_SET  # alias

# wlan_radio.phy → human-readable
PHY_NAME = {
    0: 'Unknown', 1: '802.11a', 2: '802.11b', 3: '802.11g',
    4: '802.11n', 5: '802.11ac', 6: '802.11ax', 7: '802.11ad',
    8: '802.11ah',
}

# WiFi Direct / P2P SSID identification patterns
# Matches HP printers (DIRECT-XX-HP ...), Android P2P (DIRECT-XX), and HP setup SSIDs
WIFI_DIRECT_SSID_PATTERNS = ('DIRECT-', 'DIRECT_', 'HP-Print-', 'HP=Setup', 'HP-Setup>')

# Overload thresholds
THRESH_UTIL_PCT   = 80.0    # channel utilisation %
THRESH_RETRY_RATE = 0.15    # data-frame retry fraction
THRESH_CTRL_RATIO = 0.20    # control frames as fraction of all frames
THRESH_RTS_RATE   = 0.10    # RTS as fraction of data frames

# tshark fields to capture
TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "frame.number",
    "wlan.fc.type_subtype",
    "wlan.sa",
    "wlan.da",
    "wlan.ta",
    "wlan.ra",
    "wlan.bssid",
    "wlan.fc.retry",
    "wlan.fc.pwrmgt",
    "wlan_radio.signal_dbm",
    "wlan_radio.noise_dbm",
    "wlan_radio.channel",
    "wlan_radio.frequency",
    "wlan_radio.data_rate",
    "wlan_radio.phy",
    "wlan.ssid",
    "wlan.duration",
]

COLUMN_NAMES = [
    "timestamp", "length", "frame_number", "type_subtype",
    "sa", "da", "ta", "ra", "bssid",
    "retry", "pwrmgt",
    "signal_dbm", "noise_dbm", "channel", "frequency",
    "data_rate", "phy", "ssid", "duration",
]

# ─────────────────────────────────────────────────────────────────────────────
# tshark invocation
# ─────────────────────────────────────────────────────────────────────────────

def _field_args() -> List[str]:
    args = []
    for f in TSHARK_FIELDS:
        args += ["-e", f]
    return args


def _display_filter(channel: Optional[int], bssid: Optional[str],
                    mac: Optional[str]) -> str:
    parts = ["wlan"]
    if channel:
        parts.append(f"wlan_radio.channel == {channel}")
    if bssid:
        b = bssid.lower()
        parts.append(f"wlan.bssid == {b}")
    if mac:
        m = mac.lower()
        parts.append(
            f"(wlan.sa == {m} || wlan.da == {m} "
            f"|| wlan.ta == {m} || wlan.ra == {m})"
        )
    return " && ".join(parts)


def run_tshark_file(pcap: str, channel: Optional[int], bssid: Optional[str],
                    mac: Optional[str]) -> str:
    """Run tshark on a pcap file and return raw tab-separated output."""
    filt = _display_filter(channel, bssid, mac)
    cmd = (
        ["tshark", "-r", pcap, "-Y", filt, "-T", "fields",
         "-E", "separator=\t", "-E", "quote=n", "-E", "header=n"]
        + _field_args()
    )
    logger.info(f"tshark: {Path(pcap).name}  filter: {filt}")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0 and not proc.stdout.strip():
        logger.error(f"tshark error: {proc.stderr.strip()}")
        sys.exit(1)
    if proc.stderr.strip():
        logger.warning(f"tshark: {proc.stderr.strip()[:120]}")
    return proc.stdout


def run_tshark_live(iface: str, channel: Optional[int], bssid: Optional[str],
                    mac: Optional[str], duration: int) -> str:
    """Capture live traffic from a monitor-mode interface."""
    filt = _display_filter(channel, bssid, mac)
    cmd = (
        ["tshark", "-i", iface, "-a", f"duration:{duration}",
         "-Y", filt, "-T", "fields",
         "-E", "separator=\t", "-E", "quote=n", "-E", "header=n"]
        + _field_args()
    )
    logger.info(f"Live capture on {iface} for {duration}s  filter: {filt}")
    logger.info("Press Ctrl-C to stop early …")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=duration + 30)
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user.")
        return ""
    if proc.returncode not in (0, 2) and not proc.stdout.strip():
        logger.error(f"tshark error: {proc.stderr.strip()}")
        sys.exit(1)
    return proc.stdout


# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────

def _to_bool_int(series: pd.Series) -> pd.Series:
    return series.map({
        'True': 1, 'False': 0, 'true': 1, 'false': 0, '1': 1, '0': 0
    }).fillna(0).astype(int)


def _normalize_subtype(val: str) -> str:
    try:
        return f'0x{int(val, 0):04x}'
    except (ValueError, TypeError):
        return 'unknown'


def parse_output(raw: str) -> pd.DataFrame:
    """Parse tab-separated tshark output into a typed DataFrame."""
    rows = []
    for line in raw.strip().split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        while len(parts) < len(COLUMN_NAMES):
            parts.append('')
        rows.append(parts[:len(COLUMN_NAMES)])

    if not rows:
        return pd.DataFrame(columns=COLUMN_NAMES)

    df = pd.DataFrame(rows, columns=COLUMN_NAMES)

    for col in ['timestamp', 'length', 'frame_number', 'signal_dbm',
                'noise_dbm', 'channel', 'frequency', 'data_rate', 'phy',
                'duration']:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    df['retry']  = _to_bool_int(df['retry'])
    df['pwrmgt'] = _to_bool_int(df['pwrmgt'])
    df['type_subtype'] = df['type_subtype'].apply(_normalize_subtype)

    for col in ['sa', 'da', 'ta', 'ra', 'bssid']:
        df[col] = df[col].replace('', None).str.lower()

    def _decode_ssid(v):
        if not v:
            return None
        try:
            return bytes.fromhex(v).decode('utf-8', errors='replace')
        except (ValueError, TypeError):
            return v

    df['ssid'] = df['ssid'].apply(_decode_ssid)
    return df


# ─────────────────────────────────────────────────────────────────────────────
# MAC address utilities
# ─────────────────────────────────────────────────────────────────────────────

def is_unicast(mac: str) -> bool:
    """Check if MAC is unicast (first octet LSB = 0)."""
    if not mac or ':' not in mac:
        return False
    try:
        first = int(mac.split(':')[0], 16)
        return (first & 1) == 0
    except (ValueError, IndexError):
        return False


def is_globally_administered(mac: str) -> bool:
    """Check if MAC is globally administered / OUI-assigned (bit 1 = 0)."""
    if not mac or ':' not in mac:
        return False
    try:
        first = int(mac.split(':')[0], 16)
        return (first & 2) == 0  # bit 1 = 0 means globally administered
    except (ValueError, IndexError):
        return False


def is_multicast_or_broadcast(mac: str) -> bool:
    """Check if MAC is multicast/broadcast (first octet LSB = 1)."""
    if not mac or ':' not in mac:
        return False
    try:
        first = int(mac.split(':')[0], 16)
        return (first & 1) == 1
    except (ValueError, IndexError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Statistics computation
# ─────────────────────────────────────────────────────────────────────────────

def _airtime(length_bytes: float, rate_mbps: float) -> float:
    """Estimated airtime for one frame in seconds."""
    rate = rate_mbps if rate_mbps > 0 else 1.0   # floor at 1 Mbps
    return (length_bytes * 8) / (rate * 1e6)


def compute_stats(df: pd.DataFrame, window_sec: float) -> Dict:
    """Compute all channel-monitor metrics for a DataFrame slice."""
    if df.empty:
        return {}

    n_frames = len(df)
    total_bytes = df['length'].sum()
    duration = window_sec if window_sec > 0 else 1.0

    # --- Frame type breakdown ---
    n_mgmt = df['type_subtype'].isin(MGMT_SET).sum()
    n_ctrl = df['type_subtype'].isin(CTRL_SET).sum()
    n_data = df['type_subtype'].isin(DATA_SET).sum()

    # --- Channel utilisation ---
    airtimes = df.apply(
        lambda r: _airtime(r['length'], r['data_rate']), axis=1
    )
    total_airtime = airtimes.sum()
    utilisation_pct = min((total_airtime / duration) * 100, 100.0)

    # --- Throughput ---
    throughput_mbps = (total_bytes * 8) / (duration * 1e6)

    # Data-only throughput (no mgmt/ctrl overhead)
    data_df = df[df['type_subtype'].isin(DATA_SET)]
    data_bytes = data_df['length'].sum()
    data_throughput_mbps = (data_bytes * 8) / (duration * 1e6)

    # --- Retry rate ---
    retry_eligible = df[df['type_subtype'].isin(DATA_SET)]
    retry_rate = (retry_eligible['retry'].sum() / len(retry_eligible)
                  if len(retry_eligible) > 0 else 0.0)

    # --- RTS / CTS ---
    n_rts = (df['type_subtype'] == RTS).sum()
    n_cts = (df['type_subtype'] == CTS).sum()
    n_ack = (df['type_subtype'] == ACK).sum()
    rts_per_data = n_rts / max(n_data, 1)
    cts_rts_ratio = n_cts / max(n_rts, 1)   # 1.0 = balanced, <1 = drops/hidden
    rts_cts_overhead_pct = (n_rts + n_cts) / max(n_frames, 1) * 100  # overhead as % of all traffic

    # --- Block Ack ---
    n_bar = (df['type_subtype'] == BLOCK_ACK_R).sum()
    n_ba  = (df['type_subtype'] == BLOCK_ACK).sum()

    # --- PS-Poll / Null data ---
    n_pspoll  = (df['type_subtype'] == PS_POLL).sum()
    n_null    = df['type_subtype'].isin({NULL_DATA, QOS_NULL}).sum()

    # --- Beacons ---
    n_beacon      = (df['type_subtype'] == BEACON).sum()
    beacon_fps    = round(n_beacon / duration, 2)

    # --- Probe requests / responses ---
    n_probe_req   = (df['type_subtype'] == PROBE_REQ).sum()
    n_probe_resp  = (df['type_subtype'] == PROBE_RESP).sum()
    probe_resp_rate = round(n_probe_resp / max(n_probe_req, 1), 3)   # ideally ≥ 1.0

    # --- NAV (wlan.duration field, µs) ---
    # Non-zero durations only; values > 32767 µs indicate potential NAV abuse
    nav_vals = df.loc[df['duration'] > 0, 'duration']
    max_nav_usec   = int(nav_vals.max())           if len(nav_vals) else 0
    avg_nav_usec   = round(float(nav_vals.mean()), 1) if len(nav_vals) else 0.0
    nav_abuse_count = int((df['duration'] > 32767).sum())   # > half of 65535 max

    # --- Signal ---
    sig = df.loc[df['signal_dbm'] < 0, 'signal_dbm']
    noise = df.loc[df['noise_dbm'] < 0, 'noise_dbm']
    avg_signal = float(sig.mean()) if len(sig) else float('nan')
    min_signal = float(sig.min()) if len(sig) else float('nan')
    avg_noise  = float(noise.mean()) if len(noise) else float('nan')

    # --- PHY distribution ---
    phy_counts: Dict[str, int] = {}
    for phy_id, count in df['phy'].value_counts().items():
        name = PHY_NAME.get(int(phy_id), f'phy={int(phy_id)}')
        phy_counts[name] = int(count)

    # --- Channels seen ---
    channels = sorted(
        int(c) for c in df.loc[df['channel'] > 0, 'channel'].unique()
    )

    # --- Active BSSIDs ---
    bssid_stats: Dict[str, Dict] = {}
    for bssid, grp in df.groupby('bssid', dropna=True):
        ssid_vals = grp.loc[grp['ssid'].notna(), 'ssid']
        ssid = ssid_vals.mode()[0] if len(ssid_vals) else None
        
        # Count clients: unicast, globally-administered (real OUI) MACs only
        clients_all = set()           # all unique MACs except bssid
        clients_real = set()          # only real OUI-assigned MACs (no virtual)
        client_frame_counts = defaultdict(int)  # per-client frame count
        
        for col in ['sa', 'da', 'ta']:
            for addr in grp[col].dropna():
                addr_lower = addr.lower()
                if addr_lower != bssid.lower() and is_unicast(addr_lower):
                    clients_all.add(addr_lower)
                    client_frame_counts[addr_lower] += 1
                    if is_globally_administered(addr_lower):
                        clients_real.add(addr_lower)
        
        # Breakdown by activity level (OUI devices only)
        real_clients_by_activity = defaultdict(int)
        for mac in clients_real:
            frames = client_frame_counts[mac]
            if frames <= 5:
                real_clients_by_activity['low_activity'] += 1
            elif frames <= 50:
                real_clients_by_activity['medium_activity'] += 1
            else:
                real_clients_by_activity['actively_connected'] += 1
        
        sig_vals = grp.loc[grp['signal_dbm'] < 0, 'signal_dbm']
        is_wifi_direct = bool(ssid and any(p in ssid for p in WIFI_DIRECT_SSID_PATTERNS))
        bssid_stats[bssid] = {
            'ssid': ssid,
            'frames': int(len(grp)),
            'bytes': int(grp['length'].sum()),
            'clients': len(clients_real),  # real OUI clients
            'clients_all_unicast': len(clients_all),  # including virtual MACs
            'client_breakdown': {
                'total_oui_devices': len(clients_real),
                'low_activity_le5frames': int(real_clients_by_activity['low_activity']),
                'medium_activity_6to50frames': int(real_clients_by_activity['medium_activity']),
                'actively_connected_gt50frames': int(real_clients_by_activity['actively_connected']),
            },
            'avg_signal_dbm': round(float(sig_vals.mean()), 1) if len(sig_vals) else None,
            'is_wifi_direct': is_wifi_direct,
            'ap_type': 'wifi_direct' if is_wifi_direct else 'regular',
        }

    # --- Per-client stats ---
    client_stats: Dict[str, Dict] = {}
    all_bssid_macs = set(bssid_stats.keys())  # use bssid_stats for precise AP identification
    # Only stations (not AP BSSIDs appearing as TA for control frames)
    for addr, grp in df[df['sa'].notna()].groupby('sa'):
        tx_data = grp[grp['type_subtype'].isin(DATA_SET)]
        tx_mgmt = grp[grp['type_subtype'].isin(MGMT_SET)]
        sig_vals = grp.loc[grp['signal_dbm'] < 0, 'signal_dbm']
        # Determine role: AP if same address appears in bssid_stats (beaconing AP)
        is_ap = addr in all_bssid_macs
        role = 'AP' if is_ap else 'STA'
        # Associated BSSIDs — maps each AP this STA communicated with to frame count + SSID
        assoc_bssids: Dict[str, Dict] = {}
        if not is_ap:
            for bssid_val, bgrp in grp[grp['bssid'].notna()].groupby('bssid'):
                ssid_v = bgrp.loc[bgrp['ssid'].notna(), 'ssid']
                assoc_bssids[bssid_val] = {
                    'ssid': ssid_v.mode()[0] if len(ssid_v) else None,
                    'frames': int(len(bgrp)),
                }
        # Check if this is a real OUI or virtual MAC
        is_real_oui = is_globally_administered(addr.lower())
        client_stats[addr] = {
            'role': role,
            'is_real_oui': is_real_oui,  # True if globally-administered, False if virtual
            'frames_tx': int(len(grp)),
            'total_frames': int(len(grp)),   # alias for frames_tx
            'bytes_tx': int(grp['length'].sum()),
            'data_frames': int(len(tx_data)),
            'mgmt_frames': int(len(tx_mgmt)),
            'retry_count': int(tx_data['retry'].sum()),
            'retry_rate': round(float(tx_data['retry'].sum() / len(tx_data)), 3)
                          if len(tx_data) > 0 else 0.0,
            'avg_signal_dbm': round(float(sig_vals.mean()), 1) if len(sig_vals) else None,
            'ps_mode': int(grp['pwrmgt'].sum()) > 0,
            'associated_bssids': assoc_bssids,
        }

    # --- Overload flags ---
    overload_flags = []
    if utilisation_pct >= THRESH_UTIL_PCT:
        overload_flags.append(
            f"HIGH_UTILISATION ({utilisation_pct:.1f}% ≥ {THRESH_UTIL_PCT}%)"
        )
    if retry_rate >= THRESH_RETRY_RATE:
        overload_flags.append(
            f"HIGH_RETRY ({retry_rate*100:.1f}% ≥ {THRESH_RETRY_RATE*100:.0f}%)"
        )
    ctrl_ratio = n_ctrl / max(n_frames, 1)
    if ctrl_ratio >= THRESH_CTRL_RATIO:
        overload_flags.append(
            f"CTRL_OVERHEAD ({ctrl_ratio*100:.1f}% ≥ {THRESH_CTRL_RATIO*100:.0f}%)"
        )
    if rts_per_data >= THRESH_RTS_RATE:
        overload_flags.append(
            f"HIDDEN_NODE_RISK (RTS/data={rts_per_data*100:.1f}%)"
        )
    if probe_resp_rate < 0.5 and n_probe_req >= 10:
        overload_flags.append(
            f"LOW_PROBE_RESP_RATE ({probe_resp_rate*100:.0f}% of probe reqs answered)"
        )
    if nav_abuse_count > 0:
        overload_flags.append(
            f"NAV_ABUSE ({nav_abuse_count} frames with NAV > 32767 µs)"
        )

    return {
        'window_sec': round(duration, 2),
        'n_frames': n_frames,
        'total_bytes': int(total_bytes),
        'frame_rate_fps': round(n_frames / duration, 1),
        'utilisation_pct': round(utilisation_pct, 2),
        'throughput_mbps': round(throughput_mbps, 3),
        'data_throughput_mbps': round(data_throughput_mbps, 3),
        'frame_types': {
            'mgmt': int(n_mgmt), 'ctrl': int(n_ctrl), 'data': int(n_data),
        },
        'retry_rate': round(retry_rate, 4),
        'rts_count': int(n_rts),
        'cts_count': int(n_cts),
        'ack_count': int(n_ack),
        'rts_per_data_frame': round(rts_per_data, 4),
        'cts_rts_ratio': round(cts_rts_ratio, 3),
        'rts_cts_overhead_pct': round(rts_cts_overhead_pct, 2),
        'block_ack_req': int(n_bar),
        'block_ack': int(n_ba),
        'ps_poll_count': int(n_pspoll),
        'null_data_count': int(n_null),
        'beacon_count': int(n_beacon),
        'beacon_fps': beacon_fps,
        'probe_req_count': int(n_probe_req),
        'probe_resp_count': int(n_probe_resp),
        'probe_resp_rate': probe_resp_rate,
        'max_nav_usec': max_nav_usec,
        'avg_nav_usec': avg_nav_usec,
        'nav_abuse_count': nav_abuse_count,
        'avg_signal_dbm': round(avg_signal, 1) if not math.isnan(avg_signal) else None,
        'min_signal_dbm': round(min_signal, 1) if not math.isnan(min_signal) else None,
        'avg_noise_dbm': round(avg_noise, 1) if not math.isnan(avg_noise) else None,
        'phy_distribution': phy_counts,
        'channels_seen': channels,
        'bssid_stats': bssid_stats,
        'client_stats': client_stats,
        'overload_flags': overload_flags,
        'is_overloaded': len(overload_flags) > 0,
    }


def compute_station_profile(df: pd.DataFrame, station_mac: str,
                            window_sec: float) -> Dict:
    """Compute a detailed performance profile for a specific station MAC.

    Unlike --mac (which filters the whole capture), this function operates on
    the full channel DataFrame so that channel-context comparisons (airtime
    share, retry rate vs average) are meaningful.
    """
    mac = station_mac.lower()
    tx_df  = df[df['sa'] == mac]                          # frames sent by station
    rx_df  = df[df['da'] == mac]                          # frames addressed to station

    if tx_df.empty and rx_df.empty:
        return {'found': False, 'mac': mac}

    duration = window_sec if window_sec > 0 else 1.0
    total_ch_frames = len(df)
    total_ch_bytes  = df['length'].sum()

    # --- TX frame breakdown ---
    tx_data = tx_df[tx_df['type_subtype'].isin(DATA_SET)]
    tx_mgmt = tx_df[tx_df['type_subtype'].isin(MGMT_SET)]
    tx_ctrl = tx_df[tx_df['type_subtype'].isin(CTRL_SET)]
    tx_retry_rate = (float(tx_data['retry'].sum()) / len(tx_data)
                     if len(tx_data) > 0 else 0.0)

    # --- RX frame breakdown ---
    rx_data = rx_df[rx_df['type_subtype'].isin(DATA_SET)]

    # --- Throughput ---
    tx_tput = (tx_data['length'].sum() * 8) / (duration * 1e6)
    rx_tput = (rx_data['length'].sum() * 8) / (duration * 1e6)

    # --- Airtime (station TX only, for share calculation) ---
    tx_airtime = tx_df.apply(
        lambda r: _airtime(r['length'], r['data_rate']), axis=1
    ).sum()
    total_airtime = df.apply(
        lambda r: _airtime(r['length'], r['data_rate']), axis=1
    ).sum()
    airtime_share_pct = (tx_airtime / total_airtime * 100
                         if total_airtime > 0 else 0.0)

    # --- Signal (frames seen coming from station) ---
    sig   = tx_df.loc[tx_df['signal_dbm'] < 0, 'signal_dbm']
    noise = tx_df.loc[tx_df['noise_dbm']  < 0, 'noise_dbm']
    avg_sig   = float(sig.mean())   if len(sig)   else None
    min_sig   = float(sig.min())    if len(sig)   else None
    max_sig   = float(sig.max())    if len(sig)   else None
    avg_noise = float(noise.mean()) if len(noise) else None
    snr = (avg_sig - avg_noise
           if avg_sig is not None and avg_noise is not None else None)

    # --- Associated APs (BSSIDs seen in station's TX frames) ---
    associated_aps: Dict[str, Dict] = {}
    for bssid, grp in tx_df[tx_df['bssid'].notna()].groupby('bssid'):
        ssid_v = grp.loc[grp['ssid'].notna(), 'ssid']
        associated_aps[bssid] = {
            'ssid': ssid_v.mode()[0] if len(ssid_v) else None,
            'frames': int(len(grp)),
            'bytes':  int(grp['length'].sum()),
        }

    # --- PHY modes and data rates (station TX) ---
    phy_counts: Dict[str, int] = {}
    for phy_id, cnt in tx_df['phy'].value_counts().items():
        phy_counts[PHY_NAME.get(int(phy_id), f'phy={int(phy_id)}')] = int(cnt)

    rate_counts: Dict[str, int] = {}
    for rate, cnt in (tx_df.loc[tx_df['data_rate'] > 0, 'data_rate']
                      .value_counts().items()):
        rate_counts[f"{float(rate):.1f} Mbps"] = int(cnt)

    # --- Connection events ---
    DEAUTH_T    = {'0x000c'}
    DISASSOC_T  = {'0x000a'}
    AUTH_T      = {'0x000b'}
    ASSOC_T     = {'0x0000', '0x0002'}
    probe_reqs  = tx_df[tx_df['type_subtype'] == PROBE_REQ]
    probed_ssids = sorted({
        s for s in probe_reqs['ssid'].dropna().tolist() if s
    })
    events = {
        'probe_requests':     int(len(probe_reqs)),
        'auth_frames':        int(tx_df['type_subtype'].isin(AUTH_T).sum()),
        'assoc_frames':       int(tx_df['type_subtype'].isin(ASSOC_T).sum()),
        'deauth_received':    int(rx_df['type_subtype'].isin(DEAUTH_T).sum()),
        'disassoc_received':  int(rx_df['type_subtype'].isin(DISASSOC_T).sum()),
        'null_data_sent':     int(tx_df['type_subtype'].isin({NULL_DATA, QOS_NULL}).sum()),
        'ps_poll_sent':       int((tx_df['type_subtype'] == PS_POLL).sum()),
    }

    # --- Power-save ---
    ps_pct = (float(tx_df['pwrmgt'].sum()) / len(tx_df) * 100
              if len(tx_df) > 0 else 0.0)

    # --- Issues ---
    issues = []
    if tx_retry_rate >= THRESH_RETRY_RATE:
        issues.append(f"HIGH_RETRY: {tx_retry_rate*100:.1f}% — interference or congestion")
    if events['deauth_received'] > 0:
        issues.append(f"DEAUTH: {events['deauth_received']} deauth frame(s) received")
    if events['disassoc_received'] > 0:
        issues.append(f"DISASSOC: {events['disassoc_received']} disassoc frame(s) received")
    if avg_sig is not None and avg_sig < -75:
        issues.append(f"WEAK_SIGNAL: {avg_sig:.1f} dBm (threshold −75 dBm)")
    if len(associated_aps) > 1:
        issues.append(
            f"MULTI_BSSID: station seen on {len(associated_aps)} BSSIDs — possible roaming"
        )

    return {
        'found': True,
        'mac': mac,
        'duration_sec': round(duration, 2),
        # TX
        'frames_tx':       int(len(tx_df)),
        'bytes_tx':        int(tx_df['length'].sum()),
        'data_frames_tx':  int(len(tx_data)),
        'mgmt_frames_tx':  int(len(tx_mgmt)),
        'ctrl_frames_tx':  int(len(tx_ctrl)),
        'retry_count':     int(tx_data['retry'].sum()),
        'retry_rate':      round(tx_retry_rate, 4),
        'tx_throughput_mbps': round(tx_tput, 4),
        # RX
        'frames_rx':       int(len(rx_df)),
        'bytes_rx':        int(rx_df['length'].sum()),
        'data_frames_rx':  int(len(rx_data)),
        'rx_throughput_mbps': round(rx_tput, 4),
        # Channel share
        'frame_share_pct':   round(len(tx_df) / max(total_ch_frames, 1) * 100, 2),
        'bytes_share_pct':   round(tx_df['length'].sum() / max(total_ch_bytes, 1) * 100, 2),
        'airtime_share_pct': round(airtime_share_pct, 2),
        # Signal
        'avg_signal_dbm':  round(avg_sig,   1) if avg_sig   is not None else None,
        'min_signal_dbm':  round(min_sig,   1) if min_sig   is not None else None,
        'max_signal_dbm':  round(max_sig,   1) if max_sig   is not None else None,
        'avg_noise_dbm':   round(avg_noise, 1) if avg_noise is not None else None,
        'snr_db':          round(snr,       1) if snr       is not None else None,
        # Association
        'associated_aps':  associated_aps,
        # PHY
        'phy_modes':       phy_counts,
        'data_rates_used': rate_counts,
        # Events
        'events':          events,
        'probed_ssids':    probed_ssids,
        # Power-save
        'ps_mode_pct':     round(ps_pct, 1),
        'ps_active':       ps_pct > 10.0,
        # Issues
        'issues':          issues,
        'has_issues':      len(issues) > 0,
    }


def compute_station_windows(df: pd.DataFrame, station_mac: str,
                            interval_sec: float) -> List[Dict]:
    """Per-window station performance for trend charts."""
    if df.empty:
        return []
    mac = station_mac.lower()
    t_start = df['timestamp'].min()
    t_end   = df['timestamp'].max()
    windows = []
    t = t_start
    while t < t_end:
        t_next = t + interval_sec
        w_df = df[(df['timestamp'] >= t) & (df['timestamp'] < t_next)]
        if not w_df.empty:
            prof = compute_station_profile(w_df, mac,
                                           min(interval_sec, t_end - t))
            if prof.get('found'):
                prof['window_start'] = datetime.fromtimestamp(
                    t, tz=timezone.utc
                ).strftime('%H:%M:%S')
                prof['window_start_epoch'] = round(t, 3)
                windows.append(prof)
        t = t_next
    return windows


def compute_windows(df: pd.DataFrame, interval_sec: float) -> List[Dict]:
    """Slice the DataFrame into equal time windows and compute stats for each."""
    if df.empty or df['timestamp'].max() == 0:
        return []

    t_start = df['timestamp'].min()
    t_end   = df['timestamp'].max()
    windows = []
    t = t_start
    while t < t_end:
        t_next = t + interval_sec
        window_df = df[(df['timestamp'] >= t) & (df['timestamp'] < t_next)]
        if not window_df.empty:
            stats = compute_stats(window_df, min(interval_sec, t_end - t))
            stats['window_start'] = datetime.fromtimestamp(
                t, tz=timezone.utc
            ).strftime('%H:%M:%S')
            stats['window_start_epoch'] = round(t, 3)
            windows.append(stats)
        t = t_next
    return windows


# ─────────────────────────────────────────────────────────────────────────────
# Terminal output (ANSI colours)
# ─────────────────────────────────────────────────────────────────────────────

BOLD = '\033[1m'
RED  = '\033[91m'
YEL  = '\033[93m'
GRN  = '\033[92m'
CYN  = '\033[96m'
DIM  = '\033[2m'
RST  = '\033[0m'


def _bar(value: float, max_val: float = 100.0, width: int = 20) -> str:
    filled = int(round(value / max_val * width))
    filled = max(0, min(filled, width))
    bar = '█' * filled + '░' * (width - filled)
    if value >= 80:
        colour = RED
    elif value >= 50:
        colour = YEL
    else:
        colour = GRN
    return f"{colour}{bar}{RST}"


def print_window(s: Dict, window_idx: int, top_n: int = 10) -> None:
    if not s:
        return
    overloaded = s.get('is_overloaded', False)
    hdr_colour = RED if overloaded else CYN
    print(f"\n{hdr_colour}{BOLD}{'─'*70}{RST}")
    print(f"{hdr_colour}{BOLD}  Window {window_idx:>3}  {s.get('window_start', '')} "
          f"({s['window_sec']:.1f}s)  {'⚠ OVERLOADED' if overloaded else 'OK'}{RST}")
    print(f"{hdr_colour}{BOLD}{'─'*70}{RST}")

    u = s['utilisation_pct']
    r = s['retry_rate'] * 100
    ft = s['frame_types']
    total_ft = max(ft['mgmt'] + ft['ctrl'] + ft['data'], 1)

    print(f"  {BOLD}Channel utilisation:{RST} {_bar(u)}  {u:.1f}%")
    print(f"  {BOLD}Retry rate:         {RST} {_bar(r, 30.0)}  {r:.1f}%")
    print(f"  {BOLD}Throughput:         {RST} {s['throughput_mbps']:.3f} Mbps "
          f"(data {s['data_throughput_mbps']:.3f} Mbps)")
    print(f"  {BOLD}Frame rate:         {RST} {s['frame_rate_fps']:.1f} fps  |  "
          f"total {s['n_frames']} frames  ({s['total_bytes']:,} bytes)")

    if s.get('avg_signal_dbm') is not None:
        snr = ""
        if s.get('avg_noise_dbm') is not None:
            snr = f"  SNR≈{s['avg_signal_dbm'] - s['avg_noise_dbm']:.0f} dB"
        print(f"  {BOLD}Avg signal:         {RST} {s['avg_signal_dbm']} dBm "
              f"(min {s['min_signal_dbm']} dBm){snr}")

    # Frame types
    print(f"\n  {BOLD}Frame types:{RST}  "
          f"mgmt {ft['mgmt']} ({ft['mgmt']/total_ft*100:.0f}%)  "
          f"ctrl {ft['ctrl']} ({ft['ctrl']/total_ft*100:.0f}%)  "
          f"data {ft['data']} ({ft['data']/total_ft*100:.0f}%)")

    # Control detail
    if s['rts_count'] > 0 or s['ack_count'] > 0:
        rts_cts = (f"RTS {s['rts_count']} / CTS {s['cts_count']}  "
                   f"(ratio {s['cts_rts_ratio']:.2f})")
        if s['rts_per_data_frame'] >= THRESH_RTS_RATE:
            rts_cts = f"{YEL}{rts_cts}  ← hidden-node risk{RST}"
        print(f"  {BOLD}Control detail:{RST}  ACK {s['ack_count']}  "
              f"BAReq {s['block_ack_req']}  BA {s['block_ack']}  "
              f"PS-Poll {s['ps_poll_count']}  NullData {s['null_data_count']}")
        print(f"                   {rts_cts}")

    # Probe requests / responses
    pr  = s.get('probe_req_count', 0)
    prr = s.get('probe_resp_count', 0)
    prr_rate = s.get('probe_resp_rate', 1.0)
    if pr > 0:
        rate_str = (f"{RED}{prr_rate*100:.0f}%{RST}" if prr_rate < 0.5
                    else f"{YEL}{prr_rate*100:.0f}%{RST}" if prr_rate < 0.8
                    else f"{GRN}{prr_rate*100:.0f}%{RST}")
        beacons   = s.get('beacon_count', 0)
        beacon_fps_v = s.get('beacon_fps', 0)
        print(f"  {BOLD}Probe req/resp:{RST}  {pr} req → {prr} resp "
              f"(response rate {rate_str})  "
              f"Beacons {beacons} ({beacon_fps_v:.1f}/s)")

    # NAV (Duration field)
    max_nav = s.get('max_nav_usec', 0)
    avg_nav = s.get('avg_nav_usec', 0)
    nav_abuse = s.get('nav_abuse_count', 0)
    if max_nav > 0:
        nav_abuse_str = (f"  {YEL}⚠ {nav_abuse} frames NAV>32767µs{RST}"
                         if nav_abuse > 0 else "")
        print(f"  {BOLD}NAV (Duration):{RST}  max {max_nav:,} µs  "
              f"avg {avg_nav:.0f} µs{nav_abuse_str}")

    # PHY modes
    if s['phy_distribution']:
        phy_str = '  '.join(
            f"{k}: {v}" for k, v in sorted(
                s['phy_distribution'].items(), key=lambda x: -x[1]
            )
        )
        print(f"  {BOLD}PHY modes:{RST}       {phy_str}")

    # Channels seen
    if s['channels_seen']:
        print(f"  {BOLD}Channels seen:{RST}   {s['channels_seen']}")

    # BSSIDs
    if s['bssid_stats']:
        print(f"\n  {BOLD}BSSIDs ({len(s['bssid_stats'])}){RST}")
        for bssid, b in sorted(
            s['bssid_stats'].items(), key=lambda x: -x[1]['frames']
        ):
            ssid = b['ssid'] or ''
            sig_str = (f"{b['avg_signal_dbm']} dBm"
                       if b['avg_signal_dbm'] is not None else '  —  ')
            wd_tag = f"  {YEL}[WiFi-Direct]{RST}" if b.get('is_wifi_direct') else ""
            print(f"    {DIM}{bssid}{RST}  {BOLD}{ssid:<22}{RST}  "
                  f"frames {b['frames']:>5}  bytes {b['bytes']:>8,}  "
                  f"clients {b['clients']:>3}  sig {sig_str}{wd_tag}")

    # Top-N clients by TX frames
    clients_sorted = sorted(
        s['client_stats'].items(), key=lambda x: -x[1]['frames_tx']
    )[:top_n]
    if clients_sorted:
        print(f"\n  {BOLD}Top-{top_n} clients (by TX frames){RST}")
        for addr, c in clients_sorted:
            rr = c['retry_rate'] * 100
            rr_str = (f"{RED}{rr:.1f}%{RST}" if rr >= 15
                      else f"{YEL}{rr:.1f}%{RST}" if rr >= 8
                      else f"{GRN}{rr:.1f}%{RST}")
            sig_str = (f"{c['avg_signal_dbm']} dBm"
                       if c['avg_signal_dbm'] is not None else '—')
            ps_tag = f" {DIM}[PS]{RST}" if c['ps_mode'] else ''
            role_tag = f" {CYN}[AP]{RST}" if c['role'] == 'AP' else f" {GRN}[STA]{RST}"
            mgmt_str = f"  mgmt {c.get('mgmt_frames', 0):>4}" if c['role'] != 'AP' else ""
            print(f"    {DIM}{addr}{RST}{role_tag}{ps_tag}  "
                  f"tx {c['frames_tx']:>5}  data {c['data_frames']:>5}{mgmt_str}  "
                  f"retry {rr_str}  sig {sig_str}")

    # Overload flags
    if overloaded:
        print(f"\n  {RED}{BOLD}⚠ Overload:{RST}")
        for flag in s['overload_flags']:
            print(f"    {RED}• {flag}{RST}")


def print_station_profile(profile: Dict, channel_overall: Dict) -> None:
    """Print a station performance spotlight to the terminal."""
    mac = profile.get('mac', '?').upper()
    if not profile.get('found'):
        print(f"\n  {YEL}Station {mac} — not found in capture{RST}")
        return

    ch_retry = channel_overall.get('retry_rate', 0) * 100
    st_retry = profile['retry_rate'] * 100
    retry_diff = st_retry - ch_retry

    print(f"\n\n{BOLD}{'═'*70}{RST}")
    print(f"{BOLD}  STATION PROFILE — {mac}{RST}")
    print(f"{BOLD}{'═'*70}{RST}")

    # --- Associated APs ---
    if profile['associated_aps']:
        print(f"\n  {BOLD}Associated AP(s):{RST}")
        for bssid, info in sorted(
            profile['associated_aps'].items(), key=lambda x: -x[1]['frames']
        ):
            ssid = info.get('ssid') or ''
            print(f"    {DIM}{bssid}{RST}  {BOLD}{ssid:<24}{RST}"
                  f"  frames {info['frames']:>5}  bytes {info['bytes']:>8,}")
    else:
        print(f"\n  {DIM}No BSSID association seen in capture{RST}")

    # --- Traffic ---
    print(f"\n  {BOLD}Traffic:{RST}")
    print(f"    TX  {profile['frames_tx']:>6,} frames  {profile['bytes_tx']:>10,} bytes"
          f"  data {profile['tx_throughput_mbps']:.3f} Mbps"
          f"  (data {profile['data_frames_tx']}  mgmt {profile['mgmt_frames_tx']}"
          f"  ctrl {profile['ctrl_frames_tx']})")
    print(f"    RX  {profile['frames_rx']:>6,} frames  {profile['bytes_rx']:>10,} bytes"
          f"  data {profile['rx_throughput_mbps']:.3f} Mbps"
          f"  (data {profile['data_frames_rx']})")

    # --- Channel share ---
    print(f"\n  {BOLD}Channel share:{RST}")
    print(f"    Frames:  {_bar(profile['frame_share_pct'], 100, 16)}"
          f"  {profile['frame_share_pct']:.1f}%")
    print(f"    Airtime: {_bar(profile['airtime_share_pct'], 100, 16)}"
          f"  {profile['airtime_share_pct']:.1f}%")

    # --- Retry rate vs channel ---
    rr_col = (RED if st_retry >= 15 else YEL if st_retry >= 8 else GRN)
    diff_col = (RED if retry_diff > 5 else YEL if retry_diff > 2 else GRN)
    print(f"\n  {BOLD}Retry rate:{RST}  {rr_col}{st_retry:.1f}%{RST}"
          f"  ({profile['retry_count']} retries / {profile['data_frames_tx']} data frames)"
          f"  {diff_col}{retry_diff:+.1f}pp vs channel avg ({ch_retry:.1f}%){RST}")

    # --- Signal ---
    if profile.get('avg_signal_dbm') is not None:
        ch_sig = channel_overall.get('avg_signal_dbm')
        snr_str = (f"  SNR≈{profile['snr_db']:.0f} dB"
                   if profile.get('snr_db') is not None else '')
        ch_str  = (f"  [channel avg {ch_sig} dBm]" if ch_sig is not None else '')
        print(f"  {BOLD}Signal:{RST}      "
              f"avg {profile['avg_signal_dbm']} dBm  "
              f"min {profile['min_signal_dbm']} dBm  "
              f"max {profile['max_signal_dbm']} dBm"
              f"{snr_str}{ch_str}")

    # --- PHY modes ---
    if profile['phy_modes']:
        phy_str = '  '.join(
            f"{k}: {v}" for k, v in
            sorted(profile['phy_modes'].items(), key=lambda x: -x[1])
        )
        print(f"  {BOLD}PHY modes:{RST}   {phy_str}")

    # --- Top data rates ---
    if profile['data_rates_used']:
        top5 = sorted(profile['data_rates_used'].items(),
                      key=lambda x: -x[1])[:5]
        rate_str = '  '.join(f"{k}({v})" for k, v in top5)
        print(f"  {BOLD}Data rates:{RST}  {rate_str}")

    # --- Power-save ---
    ps_col = YEL if profile['ps_active'] else GRN
    ps_lbl = (f"active ({profile['ps_mode_pct']:.0f}% of TX frames)"
              if profile['ps_active'] else 'inactive')
    print(f"  {BOLD}Power-save:{RST}  {ps_col}{ps_lbl}{RST}")

    # --- Events ---
    ev = profile['events']
    print(f"\n  {BOLD}Events:{RST}")
    print(f"    Probe requests {ev['probe_requests']}  "
          f"Auth {ev['auth_frames']}  Assoc {ev['assoc_frames']}  "
          f"Null/QoS-null {ev['null_data_sent']}  PS-Poll {ev['ps_poll_sent']}")
    if ev['deauth_received'] or ev['disassoc_received']:
        print(f"    {YEL}Deauth received {ev['deauth_received']}  "
              f"Disassoc received {ev['disassoc_received']}{RST}")
    if profile['probed_ssids']:
        ssids_str = ', '.join(f'"{s}"' for s in profile['probed_ssids'][:8])
        print(f"    Probed SSIDs: {ssids_str}")

    # --- Issues ---
    if profile['has_issues']:
        print(f"\n  {RED}{BOLD}⚠ Issues:{RST}")
        for issue in profile['issues']:
            print(f"    {RED}• {issue}{RST}")
    else:
        print(f"\n  {GRN}No issues detected{RST}")


def print_summary(overall: Dict, windows: List[Dict], top_n: int = 10) -> None:
    if not overall:
        return
    print(f"\n\n{BOLD}{'═'*70}{RST}")
    print(f"{BOLD}  CHANNEL MONITOR — OVERALL SUMMARY{RST}")
    print(f"{BOLD}{'═'*70}{RST}")
    print_window(overall, 0, top_n)

    if windows:
        utils = [w['utilisation_pct'] for w in windows]
        retries = [w['retry_rate'] * 100 for w in windows]
        print(f"\n  {BOLD}Trend (per {windows[0]['window_sec']:.0f}s window):{RST}")
        print(f"    Utilisation: min={min(utils):.1f}%  avg={sum(utils)/len(utils):.1f}%  "
              f"max={max(utils):.1f}%")
        print(f"    Retry rate:  min={min(retries):.1f}%  avg={sum(retries)/len(retries):.1f}%  "
              f"max={max(retries):.1f}%")
        overloaded_windows = sum(1 for w in windows if w['is_overloaded'])
        if overloaded_windows:
            print(f"    {RED}{BOLD}{overloaded_windows}/{len(windows)} windows were overloaded{RST}")
        else:
            print(f"    {GRN}No overloaded windows{RST}")


# ─────────────────────────────────────────────────────────────────────────────
# Report generation
# ─────────────────────────────────────────────────────────────────────────────

def save_json(overall: Dict, windows: List[Dict], path: str,
              station_profile: Optional[Dict] = None,
              station_windows: Optional[List[Dict]] = None) -> None:
    payload = {
        'generated': datetime.now().isoformat(),
        'overall': overall,
        'windows': windows,
    }
    if station_profile:
        payload['station_profile'] = station_profile
    if station_windows:
        payload['station_windows'] = station_windows
    with open(path, 'w') as f:
        json.dump(payload, f, indent=2, default=str)
    logger.info(f"JSON saved → {path}")


def _esc(s) -> str:
    if s is None:
        return '—'
    return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _util_class(v: float) -> str:
    if v >= 80:   return 'high'
    if v >= 50:   return 'med'
    return 'low'


def _build_station_html(sp: Dict, sw: List[Dict], channel_overall: Dict) -> str:
    """Build the Station Profile HTML section."""
    mac = sp.get('mac', '').upper()
    ch_retry = channel_overall.get('retry_rate', 0) * 100
    st_retry = sp['retry_rate'] * 100
    retry_diff = st_retry - ch_retry
    rr_cls = 'val-bad' if st_retry >= 15 else ('val-warn' if st_retry >= 8 else 'val-ok')
    diff_sign = '+' if retry_diff >= 0 else ''

    # Associated APs table
    ap_rows = ''.join(
        f"<tr><td>{_esc(bssid)}</td><td>{_esc(info.get('ssid'))}</td>"
        f"<td>{info['frames']:,}</td><td>{info['bytes']:,}</td></tr>"
        for bssid, info in sorted(
            sp.get('associated_aps', {}).items(), key=lambda x: -x[1]['frames']
        )
    ) or '<tr><td colspan="4" style="color:var(--dim)">No BSSID seen</td></tr>'

    # Data rates table
    rate_rows = ''.join(
        f"<tr><td>{_esc(r)}</td><td>{c:,}</td></tr>"
        for r, c in sorted(
            sp.get('data_rates_used', {}).items(),
            key=lambda x: -x[1]
        )
    ) or '<tr><td colspan="2" style="color:var(--dim)">—</td></tr>'

    # Issues list
    issues_html = ''
    if sp.get('has_issues'):
        items = ''.join(
            f"<li class='issue-item'>{_esc(i)}</li>"
            for i in sp.get('issues', [])
        )
        issues_html = f"<ul class='flag-list'>{items}</ul>"
    else:
        issues_html = "<p class='ok-badge'>✓ No issues detected</p>"

    ev = sp.get('events', {})
    sig_str = (f"{sp['avg_signal_dbm']} dBm avg  "
               f"{sp['min_signal_dbm']} min  {sp['max_signal_dbm']} max"
               if sp.get('avg_signal_dbm') is not None else '—')
    snr_str = f"{sp['snr_db']:.0f} dB" if sp.get('snr_db') is not None else '—'
    ps_str  = (f"Active ({sp['ps_mode_pct']:.0f}% of TX)"
               if sp.get('ps_active') else 'Inactive')
    probed  = ', '.join(f'&quot;{_esc(s)}&quot;'
                        for s in sp.get('probed_ssids', [])[:10]) or '—'
    phy_str = '  '.join(
        f"{_esc(k)}: {v}"
        for k, v in sorted(sp.get('phy_modes', {}).items(), key=lambda x: -x[1])
    ) or '—'
    ch_sig = channel_overall.get('avg_signal_dbm')
    ch_sig_str = f"channel avg {ch_sig} dBm" if ch_sig is not None else ''

    # Trend chart canvases (only if we have windows)
    trend_charts = ''
    if sw:
        trend_charts = """
<h3>Station Trends</h3>
<div class="chart-grid">
  <div class="chart-wrap"><h3>Signal (dBm)</h3><canvas id="stChartSig"></canvas></div>
  <div class="chart-wrap"><h3>Retry Rate (%)</h3><canvas id="stChartRetry"></canvas></div>
  <div class="chart-wrap"><h3>TX Throughput (Mbps)</h3><canvas id="stChartTput"></canvas></div>
  <div class="chart-wrap"><h3>Airtime Share (%)</h3><canvas id="stChartAirtime"></canvas></div>
</div>"""

    return f"""
<div class="station-section">
<h2>Station Profile — {_esc(mac)}</h2>

<div class="cards">
  <div class="card">
    <div class="card-label">TX Frames</div>
    <div class="card-value">{sp['frames_tx']:,}</div>
    <div class="card-sub">{sp['bytes_tx']:,} bytes</div>
  </div>
  <div class="card">
    <div class="card-label">RX Frames</div>
    <div class="card-value">{sp['frames_rx']:,}</div>
    <div class="card-sub">{sp['bytes_rx']:,} bytes</div>
  </div>
  <div class="card">
    <div class="card-label">TX Throughput</div>
    <div class="card-value">{sp['tx_throughput_mbps']:.3f}</div>
    <div class="card-sub">Mbps (data only)</div>
  </div>
  <div class="card">
    <div class="card-label">RX Throughput</div>
    <div class="card-value">{sp['rx_throughput_mbps']:.3f}</div>
    <div class="card-sub">Mbps (data only)</div>
  </div>
  <div class="card">
    <div class="card-label">Retry Rate</div>
    <div class="card-value {rr_cls}">{st_retry:.1f}%</div>
    <div class="card-sub">{diff_sign}{retry_diff:.1f}pp vs ch. avg ({ch_retry:.1f}%)</div>
  </div>
  <div class="card">
    <div class="card-label">Airtime Share</div>
    <div class="card-value">{sp['airtime_share_pct']:.1f}%</div>
    <div class="card-sub">{sp['frame_share_pct']:.1f}% of frames</div>
  </div>
  <div class="card">
    <div class="card-label">Signal</div>
    <div class="card-value">{sp.get('avg_signal_dbm') or '—'}</div>
    <div class="card-sub">dBm avg  SNR {snr_str}  {_esc(ch_sig_str)}</div>
  </div>
  <div class="card">
    <div class="card-label">Power-Save</div>
    <div class="card-value" style="font-size:1rem">{_esc(ps_str)}</div>
    <div class="card-sub">PHY: {_esc(phy_str)}</div>
  </div>
</div>

<h3>TX Frame Mix</h3>
<p>Data {sp['data_frames_tx']:,} &nbsp; Mgmt {sp['mgmt_frames_tx']:,}
   &nbsp; Ctrl {sp['ctrl_frames_tx']:,}
   &nbsp; Retries {sp['retry_count']:,}</p>

<h3>Events</h3>
<p>Probe requests {ev.get('probe_requests',0):,} &nbsp;
   Auth {ev.get('auth_frames',0):,} &nbsp;
   Assoc {ev.get('assoc_frames',0):,} &nbsp;
   Deauth rcvd <strong style="color:{'var(--red)' if ev.get('deauth_received') else 'inherit'}">{ev.get('deauth_received',0)}</strong> &nbsp;
   Disassoc rcvd <strong style="color:{'var(--red)' if ev.get('disassoc_received') else 'inherit'}">{ev.get('disassoc_received',0)}</strong> &nbsp;
   PS-Poll {ev.get('ps_poll_sent',0):,} &nbsp;
   Null/QoS-null {ev.get('null_data_sent',0):,}</p>
<p>Probed SSIDs: {probed}</p>

<h3>Associated APs</h3>
<table>
  <tr><th>BSSID</th><th>SSID</th><th>Frames</th><th>Bytes</th></tr>
  {ap_rows}
</table>

<h3>Data Rates Used</h3>
<table style="max-width:360px">
  <tr><th>Rate</th><th>Frames</th></tr>
  {rate_rows}
</table>

{trend_charts}

<h3>Issues</h3>
{issues_html}
</div>"""


def _build_station_js(sw: List[Dict]) -> str:
    """Return Chart.js calls for the 4 station trend charts."""
    if not sw:
        return ''
    labels  = json.dumps([w.get('window_start', f"W{i}") for i, w in enumerate(sw)])
    signals = json.dumps([w.get('avg_signal_dbm') for w in sw])
    retries = json.dumps([round(w['retry_rate'] * 100, 2) for w in sw])
    tputs   = json.dumps([w.get('tx_throughput_mbps', 0) for w in sw])
    airtime = json.dumps([w.get('airtime_share_pct', 0) for w in sw])
    return f"""
const stLabels = {labels};
makeChart('stChartSig',     {signals}, '#58a6ff', 'Signal dBm', null);
makeChart('stChartRetry',   {retries}, '#f85149', 'Retry %',    30);
makeChart('stChartTput',    {tputs},   '#3fb950', 'Mbps',       null);
makeChart('stChartAirtime', {airtime}, '#d29922', 'Airtime %',  100);
// patch x-axis labels for station charts
['stChartSig','stChartRetry','stChartTput','stChartAirtime'].forEach(id => {{
  const c = Chart.getChart(id);
  if (c) {{ c.data.labels = stLabels; c.update(); }}
}});"""


def save_html(overall: Dict, windows: List[Dict], path: str,
              pcap_name: str, filters: Dict,
              station_profile: Optional[Dict] = None,
              station_windows: Optional[List[Dict]] = None) -> None:
    """Generate a self-contained HTML report."""
    gen_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Build window-trend chart data
    chart_labels   = json.dumps([w.get('window_start', f"W{i}") for i, w in enumerate(windows)])
    chart_util     = json.dumps([w['utilisation_pct'] for w in windows])
    chart_retry    = json.dumps([round(w['retry_rate'] * 100, 2) for w in windows])
    chart_tput     = json.dumps([w['throughput_mbps'] for w in windows])
    chart_fps      = json.dumps([w['frame_rate_fps'] for w in windows])
    chart_probe    = json.dumps([round(w.get('probe_resp_rate', 1.0) * 100, 1) for w in windows])
    chart_nav      = json.dumps([w.get('max_nav_usec', 0) for w in windows])

    # Per-BSSID table
    bssid_rows = ''
    for bssid, b in sorted(
        overall.get('bssid_stats', {}).items(), key=lambda x: -x[1]['frames']
    ):
        breakdown = b.get('client_breakdown', {})
        actively = breakdown.get('actively_connected_gt50frames', 0)
        medium = breakdown.get('medium_activity_6to50frames', 0)
        low = breakdown.get('low_activity_le5frames', 0)
        bssid_rows += (
            f"<tr><td>{_esc(bssid)}</td><td>{_esc(b.get('ssid'))}</td>"
            f"<td>{b['frames']:,}</td><td>{b['bytes']:,}</td>"
            f"<td>{b['clients']}</td>"
            f"<td title='Actively connected (>50 frames) / Medium (6-50) / Low (≤5)'>"
            f"{actively} / {medium} / {low}</td>"
            f"<td>{_esc(b.get('avg_signal_dbm'))} dBm</td></tr>\n"
        )

    # Per-client table
    client_rows = ''
    for addr, c in sorted(
        overall.get('client_stats', {}).items(),
        key=lambda x: -x[1]['frames_tx']
    )[:50]:
        rr = c['retry_rate'] * 100
        rr_cls = 'val-bad' if rr >= 15 else ('val-warn' if rr >= 8 else 'val-ok')
        role = c.get('role', 'client')
        ps = '✓' if c.get('ps_mode') else '—'
        client_rows += (
            f"<tr><td>{_esc(addr)}</td><td>{role}</td>"
            f"<td>{c['frames_tx']:,}</td><td>{c['bytes_tx']:,}</td>"
            f"<td>{c['data_frames']:,}</td>"
            f"<td class='{rr_cls}'>{rr:.1f}%</td>"
            f"<td>{_esc(c.get('avg_signal_dbm'))} dBm</td>"
            f"<td>{ps}</td></tr>\n"
        )

    # Overload flags
    flag_rows = ''
    for flag in overall.get('overload_flags', []):
        flag_rows += f"<li class='flag-item'>{_esc(flag)}</li>\n"
    overload_banner = ''
    if overall.get('is_overloaded'):
        overload_banner = (
            "<div class='overload-banner'>⚠ Channel Overloaded — "
            + ', '.join(_esc(f) for f in overall.get('overload_flags', []))
            + "</div>"
        )

    # Window table
    window_rows = ''
    for i, w in enumerate(windows):
        ft = w['frame_types']
        total_ft = max(ft['mgmt'] + ft['ctrl'] + ft['data'], 1)
        u = w['utilisation_pct']
        u_cls = _util_class(u)
        r = w['retry_rate'] * 100
        r_cls = 'val-bad' if r >= 15 else ('val-warn' if r >= 8 else 'val-ok')
        prr   = w.get('probe_resp_rate', 1.0) * 100
        prr_cls = 'val-bad' if prr < 50 else ('val-warn' if prr < 80 else 'val-ok')
        nav_cls = 'val-warn' if w.get('nav_abuse_count', 0) > 0 else ''
        window_rows += (
            f"<tr><td>{_esc(w.get('window_start'))}</td>"
            f"<td>{w['n_frames']:,}</td>"
            f"<td class='util-{u_cls}'>{u:.1f}%</td>"
            f"<td class='{r_cls}'>{r:.1f}%</td>"
            f"<td>{w['throughput_mbps']:.3f}</td>"
            f"<td>{w['frame_rate_fps']:.1f}</td>"
            f"<td>{ft['mgmt']} / {ft['ctrl']} / {ft['data']}</td>"
            f"<td>{w['rts_count']} / {w['cts_count']}</td>"
            f"<td>{w.get('probe_req_count',0)} / {w.get('probe_resp_count',0)}</td>"
            f"<td class='{prr_cls}'>{prr:.0f}%</td>"
            f"<td class='{nav_cls}'>{w.get('max_nav_usec',0):,}</td>"
            f"<td>{w.get('beacon_count',0):,}</td>"
            f"<td>{_esc(w.get('avg_signal_dbm'))}</td>"
            f"<td>{'⚠' if w['is_overloaded'] else '—'}</td></tr>\n"
        )

    o = overall
    phy_rows = ''.join(
        f"<tr><td>{_esc(k)}</td><td>{v:,}</td></tr>"
        for k, v in sorted(o.get('phy_distribution', {}).items(), key=lambda x: -x[1])
    )
    ft = o.get('frame_types', {'mgmt': 0, 'ctrl': 0, 'data': 0})
    total_ft = max(ft['mgmt'] + ft['ctrl'] + ft['data'], 1)

    filter_summary = '  '.join(
        f"{k}: <strong>{_esc(v)}</strong>"
        for k, v in filters.items() if v
    ) or 'none'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WLAN Channel Monitor — {_esc(pcap_name)}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --dim: #8b949e;
    --green: #3fb950; --yellow: #d29922; --red: #f85149; --blue: #58a6ff;
    --cyan: #39d353;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; padding: 24px; }}
  h1 {{ font-size: 1.6rem; color: var(--blue); margin-bottom: 4px; }}
  h2 {{ font-size: 1.1rem; color: var(--dim); margin: 28px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }}
  h3 {{ font-size: 0.95rem; color: var(--dim); margin: 18px 0 8px; }}
  .meta {{ color: var(--dim); font-size: 0.85rem; margin-bottom: 24px; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 24px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; min-width: 160px; }}
  .card-label {{ font-size: 0.75rem; color: var(--dim); text-transform: uppercase; letter-spacing: .05em; }}
  .card-value {{ font-size: 1.6rem; font-weight: 700; margin-top: 4px; }}
  .card-sub {{ font-size: 0.8rem; color: var(--dim); margin-top: 2px; }}
  .val-ok   {{ color: var(--green); }}
  .val-warn {{ color: var(--yellow); }}
  .val-bad  {{ color: var(--red); }}
  .util-low {{ color: var(--green); }}
  .util-med {{ color: var(--yellow); }}
  .util-high{{ color: var(--red); }}
  .overload-banner {{ background: #3d1212; border: 1px solid var(--red); border-radius: 6px;
    padding: 12px 18px; margin-bottom: 20px; color: var(--red); font-weight: 600; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.82rem; }}
  th {{ background: var(--surface); color: var(--dim); text-align: left; padding: 8px 10px;
        border-bottom: 1px solid var(--border); font-weight: 600; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid var(--border); }}
  tr:hover td {{ background: var(--surface); }}
  .chart-wrap {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 16px; margin-bottom: 16px; }}
  .chart-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  canvas {{ max-height: 220px; }}
  .flag-list {{ list-style: none; }}
  .flag-item {{ background: #3d1212; border-left: 3px solid var(--red); padding: 6px 12px;
    margin: 4px 0; border-radius: 0 4px 4px 0; color: var(--red); font-family: monospace; }}
  .station-section {{ border: 1px solid var(--blue); border-radius: 8px; padding: 20px;
    margin: 24px 0; background: #0d1829; }}
  .station-section h2 {{ color: var(--blue); border-color: var(--blue); margin-top: 0; }}
  .issue-item {{ background: #3d1212; border-left: 3px solid var(--red); padding: 6px 12px;
    margin: 4px 0; border-radius: 0 4px 4px 0; color: var(--red); font-family: monospace; }}
  .ok-badge {{ color: var(--green); font-weight: 600; }}
</style>
</head>
<body>
<h1>WLAN Channel Monitor</h1>
<div class="meta">
  Source: <strong>{_esc(pcap_name)}</strong> &nbsp;|&nbsp;
  Filters: {filter_summary} &nbsp;|&nbsp;
  Generated: {gen_time}
</div>

{overload_banner}

<div class="cards">
  <div class="card">
    <div class="card-label">Channel Utilisation</div>
    <div class="card-value util-{_util_class(o.get('utilisation_pct',0))}">{o.get('utilisation_pct', 0):.1f}%</div>
    <div class="card-sub">estimated airtime used</div>
  </div>
  <div class="card">
    <div class="card-label">Data Throughput</div>
    <div class="card-value">{o.get('data_throughput_mbps', 0):.3f}</div>
    <div class="card-sub">Mbps (data frames only)</div>
  </div>
  <div class="card">
    <div class="card-label">Total Throughput</div>
    <div class="card-value">{o.get('throughput_mbps', 0):.3f}</div>
    <div class="card-sub">Mbps incl. overhead</div>
  </div>
  <div class="card">
    <div class="card-label">Retry Rate</div>
    <div class="card-value {'val-bad' if o.get('retry_rate',0)>=0.15 else 'val-warn' if o.get('retry_rate',0)>=0.08 else 'val-ok'}">{o.get('retry_rate', 0)*100:.1f}%</div>
    <div class="card-sub">data frames retransmitted</div>
  </div>
  <div class="card">
    <div class="card-label">Frame Rate</div>
    <div class="card-value">{o.get('frame_rate_fps', 0):.1f}</div>
    <div class="card-sub">frames/sec</div>
  </div>
  <div class="card">
    <div class="card-label">Total Frames</div>
    <div class="card-value">{o.get('n_frames', 0):,}</div>
    <div class="card-sub">{o.get('total_bytes', 0):,} bytes</div>
  </div>
  <div class="card">
    <div class="card-label">Avg Signal</div>
    <div class="card-value">{o.get('avg_signal_dbm') or '—'}</div>
    <div class="card-sub">dBm (min {o.get('min_signal_dbm') or '—'} dBm)</div>
  </div>
  <div class="card">
    <div class="card-label">BSSIDs / Clients</div>
    <div class="card-value">{len(o.get('bssid_stats', {}))} / {len(o.get('client_stats', {}))}</div>
    <div class="card-sub">active on channel</div>
  </div>
</div>

<h2>Frame-Type Breakdown</h2>
<div class="cards">
  <div class="card">
    <div class="card-label">Management</div>
    <div class="card-value">{ft['mgmt']:,}</div>
    <div class="card-sub">{ft['mgmt']/total_ft*100:.1f}%</div>
  </div>
  <div class="card">
    <div class="card-label">Control</div>
    <div class="card-value {'val-warn' if ft['ctrl']/total_ft >= 0.20 else ''}">{ft['ctrl']:,}</div>
    <div class="card-sub">{ft['ctrl']/total_ft*100:.1f}%  ACK {o.get('ack_count',0):,}</div>
  </div>
  <div class="card">
    <div class="card-label">Data</div>
    <div class="card-value">{ft['data']:,}</div>
    <div class="card-sub">{ft['data']/total_ft*100:.1f}%</div>
  </div>
  <div class="card">
    <div class="card-label">RTS / CTS</div>
    <div class="card-value {'val-warn' if o.get('rts_per_data_frame',0)>=0.10 else ''}">{o.get('rts_count',0):,} / {o.get('cts_count',0):,}</div>
    <div class="card-sub">CTS/RTS ratio {o.get('cts_rts_ratio',1):.2f}</div>
  </div>
  <div class="card">
    <div class="card-label">Block Ack</div>
    <div class="card-value">{o.get('block_ack_req',0):,} / {o.get('block_ack',0):,}</div>
    <div class="card-sub">BAR / BA</div>
  </div>
  <div class="card">
    <div class="card-label">PS-Poll / Null</div>
    <div class="card-value">{o.get('ps_poll_count',0):,} / {o.get('null_data_count',0):,}</div>
    <div class="card-sub">power-save frames</div>
  </div>
</div>

<h2>Probe &amp; Beacon Activity</h2>
<div class="cards">
  <div class="card">
    <div class="card-label">Probe Requests</div>
    <div class="card-value">{o.get('probe_req_count',0):,}</div>
    <div class="card-sub">unique probe requests</div>
  </div>
  <div class="card">
    <div class="card-label">Probe Responses</div>
    <div class="card-value">{o.get('probe_resp_count',0):,}</div>
    <div class="card-sub">{o.get('probe_resp_rate',0)*100:.0f}% response rate</div>
  </div>
  <div class="card">
    <div class="card-label">Probe Response Rate</div>
    <div class="card-value {'val-bad' if o.get('probe_resp_rate',1)<0.5 else 'val-warn' if o.get('probe_resp_rate',1)<0.8 else 'val-ok'}">{o.get('probe_resp_rate',0)*100:.0f}%</div>
    <div class="card-sub">{'LOW — APs not responding' if o.get('probe_resp_rate',1)<0.5 else 'acceptable' if o.get('probe_resp_rate',1)<0.8 else 'good'}</div>
  </div>
  <div class="card">
    <div class="card-label">Beacons</div>
    <div class="card-value">{o.get('beacon_count',0):,}</div>
    <div class="card-sub">{o.get('beacon_fps',0):.1f} beacons/sec</div>
  </div>
  <div class="card">
    <div class="card-label">Max NAV (Duration)</div>
    <div class="card-value {'val-warn' if o.get('max_nav_usec',0)>32767 else ''}">{o.get('max_nav_usec',0):,} µs</div>
    <div class="card-sub">avg {o.get('avg_nav_usec',0):.0f} µs  |  {o.get('nav_abuse_count',0)} frames &gt;32767 µs</div>
  </div>
</div>

<h2>Trend Charts</h2>
<div class="chart-grid">
  <div class="chart-wrap">
    <h3>Channel Utilisation (%)</h3>
    <canvas id="chartUtil"></canvas>
  </div>
  <div class="chart-wrap">
    <h3>Retry Rate (%)</h3>
    <canvas id="chartRetry"></canvas>
  </div>
  <div class="chart-wrap">
    <h3>Throughput (Mbps)</h3>
    <canvas id="chartTput"></canvas>
  </div>
  <div class="chart-wrap">
    <h3>Frame Rate (fps)</h3>
    <canvas id="chartFps"></canvas>
  </div>
  <div class="chart-wrap">
    <h3>Probe Response Rate (%)</h3>
    <canvas id="chartProbe"></canvas>
  </div>
  <div class="chart-wrap">
    <h3>Max NAV / Duration (µs per window)</h3>
    <canvas id="chartNav"></canvas>
  </div>
</div>

<h2>PHY Mode Distribution</h2>
<table>
  <tr><th>PHY Mode</th><th>Frames</th></tr>
  {phy_rows}
</table>

<h2>BSSIDs (APs on Channel)</h2>
<table>
  <tr><th>BSSID</th><th>SSID</th><th>Frames</th><th>Bytes</th><th>Total Clients</th><th>Activity Breakdown<br/>(Active/Medium/Low)</th><th>Avg Signal</th></tr>
  {bssid_rows or '<tr><td colspan="7" style="color:var(--dim)">No BSSIDs detected</td></tr>'}
</table>

<h2>Client Summary (top 50 by TX frames)</h2>
<table>
  <tr><th>Address</th><th>Role</th><th>TX Frames</th><th>TX Bytes</th><th>Data Frames</th><th>Retry Rate</th><th>Avg Signal</th><th>PS</th></tr>
  {client_rows or '<tr><td colspan="8" style="color:var(--dim)">No clients detected</td></tr>'}
</table>

<h2>Per-Window Statistics</h2>
<table>
  <tr>
    <th>Window</th><th>Frames</th><th>Utilisation</th><th>Retry</th>
    <th>Throughput (Mbps)</th><th>FPS</th><th>Mgmt/Ctrl/Data</th>
    <th>RTS/CTS</th><th>Probe Req/Resp</th><th>Probe Resp%</th>
    <th>Max NAV (µs)</th><th>Beacons</th><th>Signal (dBm)</th><th>Overload</th>
  </tr>
  {window_rows or '<tr><td colspan="14" style="color:var(--dim)">No windows</td></tr>'}
</table>

{'<h2>Overload Flags</h2><ul class="flag-list">' + flag_rows + '</ul>' if flag_rows else ''}

{_build_station_html(station_profile, station_windows, o) if station_profile and station_profile.get('found') else ''}

<script>
const labels = {chart_labels};
const CHART_OPTS = (color, label, ymax) => ({{
  type: 'line',
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#8b949e', maxTicksLimit: 12 }}, grid: {{ color: '#21262d' }} }},
      y: {{ min: 0, max: ymax, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }}
    }}
  }},
  data: {{
    labels,
    datasets: [{{ data: [], borderColor: color, backgroundColor: color + '22',
                  fill: true, tension: 0.3, pointRadius: 3, borderWidth: 2 }}]
  }}
}});

function makeChart(id, data, color, label, ymax) {{
  const cfg = CHART_OPTS(color, label, ymax);
  cfg.data.datasets[0].data = data;
  new Chart(document.getElementById(id), cfg);
}}

makeChart('chartUtil',  {chart_util},   '#58a6ff', 'Utilisation %', 100);
makeChart('chartRetry', {chart_retry},  '#f85149', 'Retry %',       30);
makeChart('chartTput',  {chart_tput},   '#3fb950', 'Mbps',          null);
makeChart('chartFps',   {chart_fps},    '#d29922', 'FPS',           null);
makeChart('chartProbe', {chart_probe},  '#39d353', 'Probe resp %',  100);
makeChart('chartNav',   {chart_nav},    '#d29922', 'NAV µs',         null);
{_build_station_js(station_windows) if station_windows else ''}
</script>
</body>
</html>
"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)
    logger.info(f"HTML report saved → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Channel auto-detection
# ─────────────────────────────────────────────────────────────────────────────

def detect_channel_from_pcap(pcap: str) -> Optional[int]:
    """Quick tshark pass to find the most common wlan_radio.channel in the capture.

    Returns the dominant channel number, or None if the metadata is absent.
    """
    cmd = [
        "tshark", "-r", pcap, "-Y", "wlan",
        "-T", "fields", "-e", "wlan_radio.channel",
        "-E", "header=n",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    channels = []
    for line in proc.stdout.strip().split('\n'):
        val = line.strip()
        if val.isdigit():
            channels.append(int(val))
    if not channels:
        return None
    dominant, _ = Counter(channels).most_common(1)[0]
    return dominant


# CLI
# ─────────────────────────────────────────────────────────────────────────────

def run(pcap: str, channel: int = None, bssid: str = None, mac: str = None,
        station: str = None, interval: float = 10.0, out_prefix: str = None,
        output_dir: str = 'results') -> dict:
    """Callable entry point — usable from workers without subprocess.

    When *channel* is None the dominant channel is auto-detected from the
    capture's wlan_radio.channel metadata before running the analysis.
    """
    # Auto-detect channel when not supplied
    if channel is None:
        detected = detect_channel_from_pcap(pcap)
        if detected is not None:
            channel = detected
            logger.info(
                f"Auto-detected channel {channel} from {Path(pcap).name}"
            )

    if not out_prefix:
        stem = Path(pcap).stem
        ch_suffix = f"_ch{channel}" if channel else ""
        out_prefix = str(Path(output_dir) / f"ch_monitor_{stem}{ch_suffix}")

    raw = run_tshark_file(pcap, channel, bssid, mac)
    source_name = Path(pcap).name
    df = parse_output(raw)

    if df.empty:
        logger.warning("No frames matched the given filters.")
        return {'error': 'No frames matched', 'json_path': None, 'html_path': None}

    t_span = df['timestamp'].max() - df['timestamp'].min()
    station_profile = None
    station_windows = None
    if station:
        station_mac = station.lower()
        station_profile = compute_station_profile(df, station_mac, t_span if t_span > 0 else 1.0)
        station_windows = compute_station_windows(df, station_mac, interval)

    windows = compute_windows(df, interval)
    overall = compute_stats(df, t_span if t_span > 0 else 1.0)
    overall['window_start'] = datetime.fromtimestamp(
        df['timestamp'].min(), tz=timezone.utc
    ).strftime('%H:%M:%S')

    out = Path(out_prefix)
    out.parent.mkdir(parents=True, exist_ok=True)
    filters = {'channel': channel, 'bssid': bssid, 'mac': mac, 'station': station}
    json_path = str(out) + '.json'
    html_path = str(out) + '_report.html'
    save_json(overall, windows, json_path, station_profile, station_windows)
    save_html(overall, windows, html_path, source_name, filters, station_profile, station_windows)

    return {'json_path': json_path, 'html_path': html_path, 'results': overall}


def main() -> None:
    parser = argparse.ArgumentParser(
        description='WLAN Channel Monitor — quantify channel usage and overload'
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument('--pcap',  metavar='FILE',  help='Path to pcap / pcapng file')
    src.add_argument('--iface', metavar='IFACE', help='Monitor-mode interface for live capture')

    parser.add_argument('--channel',  type=int,   default=None, metavar='N',
                        help='Channel number to filter / capture on')
    parser.add_argument('--bssid',    default=None, metavar='MAC',
                        help='Filter to a specific AP BSSID')
    parser.add_argument('--mac',      default=None, metavar='MAC',
                        help='Filter entire capture to frames involving this MAC')
    parser.add_argument('--station',  default=None, metavar='MAC',
                        help='Spotlight a station MAC: show full channel + dedicated '
                             'performance profile (TX/RX, retry vs avg, signal, '
                             'airtime share, associated APs, data rates, issues)')
    parser.add_argument('--interval', type=float, default=10.0, metavar='SEC',
                        help='Rolling window size in seconds (default: 10)')
    parser.add_argument('--duration', type=int,   default=60,   metavar='SEC',
                        help='Live capture duration in seconds (default: 60)')
    parser.add_argument('--top-n',    type=int,   default=10,   metavar='N',
                        help='Top-N clients to display (default: 10)')
    parser.add_argument('--out',      default=None, metavar='PREFIX',
                        help='Output prefix for .json and _report.html')
    parser.add_argument('--quiet',    action='store_true',
                        help='Suppress per-window output, show only summary')

    args = parser.parse_args()

    # --- Capture / load ---
    if args.pcap:
        raw = run_tshark_file(args.pcap, args.channel, args.bssid, args.mac)
        source_name = Path(args.pcap).name
    else:
        raw = run_tshark_live(args.iface, args.channel, args.bssid, args.mac,
                              args.duration)
        source_name = f"{args.iface} (live)"

    df = parse_output(raw)
    if df.empty:
        logger.warning("No frames matched the given filters.")
        sys.exit(0)

    t_span = df['timestamp'].max() - df['timestamp'].min()
    logger.info(f"Loaded {len(df):,} frames  span {t_span:.1f}s")

    # --- Station profile (computed before windowing so it uses full df) ---
    station_profile: Optional[Dict] = None
    station_windows: Optional[List[Dict]] = None
    if args.station:
        station_mac = args.station.lower()
        logger.info(f"Computing station profile for {station_mac.upper()} …")
        station_profile = compute_station_profile(
            df, station_mac, t_span if t_span > 0 else 1.0
        )
        station_windows = compute_station_windows(df, station_mac, args.interval)

    # --- Per-window stats ---
    windows = compute_windows(df, args.interval)

    if not args.quiet:
        for i, w in enumerate(windows, 1):
            print_window(w, i, args.top_n)

    # --- Overall stats ---
    overall = compute_stats(df, t_span if t_span > 0 else 1.0)
    overall['window_start'] = datetime.fromtimestamp(
        df['timestamp'].min(), tz=timezone.utc
    ).strftime('%H:%M:%S')
    print_summary(overall, windows, args.top_n)

    # --- Station profile output ---
    if station_profile is not None:
        print_station_profile(station_profile, overall)

    # --- Save reports ---
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        filters = {
            'channel': args.channel,
            'bssid': args.bssid,
            'mac': args.mac,
            'station': args.station,
        }
        save_json(overall, windows, str(out) + '.json',
                  station_profile, station_windows)
        save_html(overall, windows, str(out) + '_report.html',
                  source_name, filters,
                  station_profile, station_windows)
    else:
        logger.info("Tip: use --out results/<name> to save JSON + HTML reports")


if __name__ == '__main__':
    main()
