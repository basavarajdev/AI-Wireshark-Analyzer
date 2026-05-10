"""
WLAN/WiFi Protocol Analyzer
Analyzes 802.11 wireless frames for WiFi-specific issues and security threats
"""

import argparse
import pyshark
import pandas as pd
import numpy as np
from pathlib import Path
from loguru import logger
import yaml
import json
from collections import defaultdict
from typing import Dict, List, Any

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))


# 802.11 frame type/subtype mapping
FRAME_SUBTYPES = {
    '0x0000': 'Association Request',
    '0x0001': 'Association Response',
    '0x0002': 'Reassociation Request',
    '0x0003': 'Reassociation Response',
    '0x0004': 'Probe Request',
    '0x0005': 'Probe Response',
    '0x0006': 'Timing Advertisement',
    '0x0008': 'Beacon',
    '0x0009': 'ATIM',
    '0x000a': 'Disassociation',
    '0x000b': 'Authentication',
    '0x000c': 'Deauthentication',
    '0x000d': 'Action',
    '0x000e': 'Action No Ack',
    '0x0015': 'VHT/HE NDP Announcement',
    '0x0018': 'Block Ack Request',
    '0x0019': 'Block Ack',
    '0x001a': 'PS-Poll',
    '0x001b': 'RTS',
    '0x001c': 'CTS',
    '0x001d': 'ACK',
    '0x001e': 'CF-End',
    '0x001f': 'CF-End + CF-Ack',
    '0x0020': 'Data',
    '0x0021': 'Data + CF-Ack',
    '0x0022': 'Data + CF-Poll',
    '0x0024': 'Null (No Data)',
    '0x0028': 'QoS Data',
    '0x002c': 'QoS Null',
}

# Management frame subtypes (type=0)
MGMT_SUBTYPES = {'0x0000', '0x0001', '0x0002', '0x0003', '0x0004', '0x0005',
                  '0x0006', '0x0008', '0x0009', '0x000a', '0x000b', '0x000c',
                  '0x000d', '0x000e'}
# Control frame subtypes (type=1)
CTRL_SUBTYPES = {'0x0018', '0x0019', '0x001a', '0x001b', '0x001c', '0x001d',
                 '0x001e', '0x001f'}
# Data frame subtypes (type=2)
DATA_SUBTYPES = {'0x0020', '0x0021', '0x0022', '0x0024', '0x0028', '0x002c'}

# 802.11 Status Codes (used in association/reassociation/authentication responses)
STATUS_CODES = {
    0: 'Success',
    1: 'Unspecified failure',
    10: 'Cannot support all requested capabilities',
    11: 'Reassociation denied – no prior association exists',
    12: 'Association denied (other reason)',
    13: 'Authentication algorithm not supported',
    14: 'Unexpected authentication sequence number',
    15: 'Authentication rejected – challenge failure (wrong credentials)',
    16: 'Authentication rejected – timeout',
    17: 'AP unable to handle additional STAs',
    23: '802.1X authentication failed',
    37: 'Invalid RSN IE capabilities',
    39: 'Requested TCLAS processing not supported',
    40: 'TS Schedule conflict / resource unavailable',
    43: 'Rejected with suggested changes to TS',
    44: 'Rejected – MCCAOP reservation conflict',
    46: 'Invalid contents of RSNE (Robust Security Network Element)',
    53: 'Invalid Pairwise Master Key Identifier (PMKID)',
    54: 'Invalid MDE (Mobility Domain Element)',
    55: 'Invalid FTE (Fast BSS Transition Element)',
    72: 'SAE authentication rejected',
    73: 'SAE commit rejected',
    74: 'SAE confirm rejected',
    76: 'Unknown Password Identifier (WPA3-SAE)',
    77: 'SAE Anti-Clogging Token Required',
    78: 'SAE Finite Cyclic Group not supported',
    79: 'Cannot find alternative TBTT',
    82: 'DENIED_WITH_SUGGESTED_BAND_AND_CHANNEL',
    83: 'Rejected with suggested BSS Transition',
    84: 'Rejected due to next-TBTT without exact value',
    93: 'Association denied — no HE support',
}

# 802.11 Reason Codes (IEEE 802.11-2020, used in deauthentication/disassociation frames)
REASON_CODES = {
    1:  'Unspecified reason',
    2:  'Previous authentication no longer valid (STA inactive/re-keying)',
    3:  'STA is leaving or has left the BSS (intentional disconnect)',
    4:  'Disassociated – AP inactivity timeout (no frames received)',
    5:  'AP unable to handle all currently associated STAs (capacity)',
    6:  'Class 2 frame received from non-authenticated STA',
    7:  'Class 3 frame received from non-associated STA',
    8:  'STA has left or is leaving the BSS (normal teardown)',
    9:  'Requesting STA is not authenticated with responding STA',
    10: 'Unacceptable Power Capability IE',
    11: 'Unacceptable Supported Channels IE',
    12: 'Disassociated – BSS Transition Management (roaming)',
    13: 'Invalid Information Element (malformed IE)',
    14: '4-way handshake MIC failure / timeout (wrong PSK)',
    15: 'Group key handshake timeout (GTK renewal failure) — NOTE: some AP firmware (e.g. TP-Link) also sends this code for 4-way handshake Msg1/Msg2 failure caused by wrong PSK',
    # Note: strict delineation between codes 14 and 15 depends on AP vendor firmware.
    16: 'IE mismatch between 4-way handshake and assoc/probe (PSK error)',
    17: 'Invalid group cipher in RSN IE',
    18: 'Invalid pairwise cipher in RSN IE',
    19: 'Invalid AKMP (authentication key management protocol)',
    20: 'Unsupported RSN IE version',
    21: 'Invalid RSN IE capabilities',
    22: 'IEEE 802.1X authentication failed',
    23: 'Cipher suite rejected by security policy',
    24: 'TDLS direct-link teardown – peer unreachable',
    25: 'TDLS direct-link teardown requested by peer',
    28: 'Lack of SSP roaming agreement',
    29: 'Requested service not allowed (SSP cipher/AKM requirement)',
    30: 'Requested service not authorized at this location',
    31: 'QoS: AP lacks sufficient bandwidth for this QoS STA (BSS change)',
    32: 'Disassociated – unspecified QoS-related reason',
    33: 'QoS AP lacks sufficient bandwidth for the STA',
    34: 'Excessive unacknowledged frames due to AP overload / poor RF',
    35: 'STA transmitting outside TXOP limits',
    36: 'Peer STA is leaving BSS or resetting',
    37: 'Peer STA does not want to use the requested mechanism',
    38: 'Peer STA received frames requiring an uncompleted setup',
    39: 'Peer STA timed out waiting for mechanism setup',
    45: 'Peer STA does not support the requested cipher suite',
    46: 'Destination STA in DLS request is not a QoS STA',
    # WPA3-SAE specific reason codes (802.11-2020)
    47: 'Disassociated — SAE PMK-ID not recognized (SAE session expired)',
    50: 'Disassociated — no SAE PT or password available',
}


def _sae_status_root_cause(status: int) -> str:
    """Map an SAE-related status code to a concise root-cause label."""
    return {
        1:  'SAE authentication rejected — unspecified failure',
        15: 'SAE Confirm MIC verification failed — wrong passphrase',
        72: 'SAE authentication rejected by AP',
        73: 'SAE Commit rejected — configuration/group mismatch',
        74: 'SAE Confirm rejected — wrong passphrase or MIC failure',
        76: 'Unknown SAE Password Identifier',
        77: 'SAE Anti-Clogging Token Required — AP rate-limiting',
        78: 'SAE Elliptic Curve Group not supported by AP',
    }.get(status, f'SAE failure (status code {status})')


def _sae_remediation(status: int) -> str:
    """Return a human-readable remediation string for an SAE status code."""
    return {
        1:  ('SAE was rejected without a specific reason. '
             'Recovery: check AP logs for details; verify WPA3 is enabled on both AP '
             'and client; update AP/client firmware.'),
        15: ('SAE Confirm MIC failed — the password used by the client does not match '
             'the AP\'s configured WPA3 passphrase. '
             'Recovery: re-enter the correct WPA3 passphrase on the client. '
             'Ensure the passphrase is UTF-8 normalised (RFC 8265 PRECIS).'),
        72: ('AP explicitly rejected the SAE authentication request. '
             'Recovery: check AP for WPA3-SAE support; verify passphrase; check client '
             'driver/firmware supports SAE commit/confirm exchange (auth_alg=3).'),
        73: ('AP rejected SAE Commit — possible EC group mismatch or unsupported feature. '
             'Recovery: ensure both AP and client support EC group 19 (P-256, mandatory for WPA3); '
             'update AP firmware; try disabling non-standard SAE groups on client.'),
        74: ('SAE Confirm exchange failed. '
             'Recovery: verify WPA3 passphrase (UTF-8 normalised); update AP/client firmware; '
             'if anti-clogging was involved, ensure client correctly retried with token.'),
        76: ('Client sent an unknown Password Identifier. '
             'Recovery: remove or correct the "password ID" field in the client\'s WPA3 config; '
             'ensure AP and client use the same password identifier (or none).'),
        77: ('Anti-Clogging Token Required: the AP is rate-limiting SAE Commit processing. '
             'This is a DoS-protection mechanism, not a credential error. '
             'Recovery: client must resend SAE Commit with the provided token. '
             'If persistent, investigate SAE flooding (rogue clients) targeting the AP.'),
        78: ('Finite Cyclic Group (elliptic curve) not supported. '
             'Recovery: configure both AP and client to use EC group 19 (P-256). '
             'Disable exotic/non-standard groups; update AP firmware.'),
    }.get(status, (f'SAE failure status {status}. '
                   'Recovery: check AP and client WPA3-SAE configuration and firmware.'))


class WLANAnalyzer:
    """Analyze WLAN/WiFi traffic for wireless-specific issues"""

    def __init__(self, config_path: str = "config/default.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.wlan_config = self.config.get('protocols', {}).get('wlan', {})

    def analyze(self, pcap_file: str, display_filter: str = None) -> Dict[str, Any]:
        """
        Analyze WLAN traffic from PCAP file.

        Args:
            pcap_file: Path to PCAP file
            display_filter: Optional additional Wireshark display filter

        Returns:
            Dictionary with WLAN analysis results
        """
        logger.info(f"Analyzing WLAN traffic in {pcap_file}")

        if not Path(pcap_file).exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

        packets = self._parse_wlan_packets(pcap_file, display_filter=display_filter)

        if not packets:
            logger.warning("No WLAN packets found")
            return {"error": "No WLAN packets found"}

        df = pd.DataFrame(packets)
        logger.info(f"Parsed {len(df)} WLAN frames")

        results = {
            "total_packets": len(df),
            "statistics": self._calculate_statistics(df),
            "connection_events": self._analyze_connection_events(df),
            "threats": self._detect_threats(df),
        }

        return results

    def _parse_wlan_packets(self, pcap_file: str, display_filter: str = None) -> List[Dict]:
        """Parse WLAN packets directly from PCAP using PyShark."""
        packets_data = []
        wlan_filter = f'wlan && ({display_filter})' if display_filter else 'wlan'

        try:
            capture = pyshark.FileCapture(
                pcap_file,
                display_filter=wlan_filter,
            )

            for i, pkt in enumerate(capture):
                try:
                    features = self._extract_wlan_features(pkt)
                    if features:
                        packets_data.append(features)
                except Exception as e:
                    logger.debug(f"Error parsing WLAN packet {i}: {e}")
                    continue

            capture.close()
        except Exception as e:
            logger.error(f"Error reading PCAP for WLAN analysis: {e}")
            raise

        return packets_data

    def _extract_wlan_features(self, pkt) -> Dict:
        """Extract WLAN-specific features from a packet."""
        features: Dict[str, Any] = {}

        # Timestamp
        try:
            features['timestamp'] = float(pkt.sniff_timestamp)
        except Exception:
            features['timestamp'] = 0.0

        # Frame length
        try:
            features['length'] = int(pkt.length)
        except Exception:
            features['length'] = 0

        # --- wlan layer ---
        if not hasattr(pkt, 'wlan'):
            return {}

        wlan = pkt.wlan

        # Frame type/subtype
        try:
            features['type_subtype'] = getattr(wlan, 'type_subtype', 'unknown')
        except Exception:
            features['type_subtype'] = 'unknown'

        # Addresses
        for addr_field in ('sa', 'da', 'ta', 'ra', 'bssid'):
            try:
                features[addr_field] = getattr(wlan, addr_field, None)
            except Exception:
                features[addr_field] = None

        # Sequence number
        try:
            features['seq'] = int(getattr(wlan, 'seq', 0))
        except Exception:
            features['seq'] = 0

        # Duration
        try:
            features['duration'] = int(getattr(wlan, 'duration', 0))
        except Exception:
            features['duration'] = 0

        # Retry flag
        try:
            fc_tree = wlan.fc_tree
            features['retry'] = 0
            features['protected'] = int(getattr(fc_tree, 'protected', '0'))
        except Exception:
            features['retry'] = 0
            features['protected'] = 0

        # --- wlan_radio layer ---
        if hasattr(pkt, 'wlan_radio'):
            radio = pkt.wlan_radio
            try:
                features['signal_dbm'] = int(getattr(radio, 'signal_dbm', 0))
            except Exception:
                features['signal_dbm'] = 0
            try:
                features['noise_dbm'] = int(getattr(radio, 'noise_dbm', 0))
            except Exception:
                features['noise_dbm'] = 0
            try:
                features['channel'] = int(getattr(radio, 'channel', 0))
            except Exception:
                features['channel'] = 0
            try:
                features['frequency'] = int(getattr(radio, 'frequency', 0))
            except Exception:
                features['frequency'] = 0
            try:
                features['data_rate'] = float(getattr(radio, 'data_rate', 0))
            except Exception:
                features['data_rate'] = 0.0
            try:
                features['phy'] = getattr(radio, 'phy', 'unknown')
            except Exception:
                features['phy'] = 'unknown'

        # --- SSID from wlan.mgt layer ---
        features['ssid'] = None
        for layer in pkt.layers:
            if layer.layer_name == 'wlan.mgt':
                try:
                    ssid = getattr(layer, 'ssid', None)
                    if ssid:
                        features['ssid'] = str(ssid)
                except Exception:
                    pass
                break

        return features

    # ------------------------------------------------------------------
    #  Statistics
    # ------------------------------------------------------------------

    def _calculate_statistics(self, df: pd.DataFrame) -> Dict:
        stats: Dict[str, Any] = {}

        stats['total_frames'] = len(df)

        # Frame type distribution
        type_counts = df['type_subtype'].value_counts().to_dict()
        stats['frame_type_distribution'] = {
            FRAME_SUBTYPES.get(k, f'Unknown ({k})'): int(v)
            for k, v in type_counts.items()
        }

        # Categorize into management / control / data
        df['frame_category'] = df['type_subtype'].apply(self._categorize_frame)
        cat_counts = df['frame_category'].value_counts().to_dict()
        stats['management_frames'] = int(cat_counts.get('Management', 0))
        stats['control_frames'] = int(cat_counts.get('Control', 0))
        stats['data_frames'] = int(cat_counts.get('Data', 0))
        stats['unknown_frames'] = int(cat_counts.get('Unknown', 0))

        # BSSIDs
        bssids = df['bssid'].dropna()
        stats['unique_bssids'] = int(bssids.nunique())
        stats['top_bssids'] = bssids.value_counts().head(10).to_dict()

        # SSIDs
        ssids = df['ssid'].dropna()
        if not ssids.empty:
            stats['unique_ssids'] = int(ssids.nunique())
            stats['detected_ssids'] = ssids.value_counts().to_dict()
        else:
            stats['unique_ssids'] = 0
            stats['detected_ssids'] = {}

        # Source/destination addresses
        sas = df['sa'].dropna()
        stats['unique_transmitters'] = int(sas.nunique())
        stats['top_transmitters'] = sas.value_counts().head(10).to_dict()

        das = df['da'].dropna()
        stats['unique_receivers'] = int(das.nunique())
        stats['broadcast_frames'] = int((das == 'ff:ff:ff:ff:ff:ff').sum())

        # Channel distribution
        if 'channel' in df.columns:
            ch = df['channel'].dropna()
            ch = ch[ch > 0]
            if not ch.empty:
                stats['channels_used'] = sorted(ch.unique().tolist())
                stats['channel_distribution'] = ch.value_counts().to_dict()

        # Signal strength
        if 'signal_dbm' in df.columns:
            sig = df['signal_dbm'].dropna()
            sig = sig[sig != 0]
            if not sig.empty:
                stats['signal_min_dbm'] = int(sig.min())
                stats['signal_max_dbm'] = int(sig.max())
                stats['signal_mean_dbm'] = float(round(sig.mean(), 1))
                stats['signal_std_dbm'] = float(round(sig.std(), 1))

        # Noise
        if 'noise_dbm' in df.columns:
            noise = df['noise_dbm'].dropna()
            noise = noise[noise != 0]
            if not noise.empty:
                stats['noise_mean_dbm'] = float(round(noise.mean(), 1))

        # Data rate
        if 'data_rate' in df.columns:
            dr = df['data_rate'].dropna()
            dr = dr[dr > 0]
            if not dr.empty:
                stats['data_rate_min_mbps'] = float(dr.min())
                stats['data_rate_max_mbps'] = float(dr.max())
                stats['data_rate_mean_mbps'] = float(round(dr.mean(), 1))

        # PHY types
        if 'phy' in df.columns:
            phy_map = {
                '1': '802.11b (DSSS)', '2': '802.11a (OFDM)',
                '4': '802.11g', '5': '802.11n (HT)',
                '6': '802.11ac (VHT)', '7': '802.11ax (HE)',
            }
            phy_counts = df['phy'].value_counts().to_dict()
            stats['phy_distribution'] = {
                phy_map.get(str(k), f'PHY {k}'): int(v)
                for k, v in phy_counts.items()
            }

        # Retry frames
        if 'retry' in df.columns:
            stats['retry_frames'] = int(df['retry'].sum())
            stats['retry_rate'] = float(round(df['retry'].mean() * 100, 2))

        # Protected frames
        if 'protected' in df.columns:
            stats['protected_frames'] = int(df['protected'].sum())
            stats['unprotected_data_frames'] = int(
                ((df['frame_category'] == 'Data') & (df['protected'] == 0)).sum()
            )

        # Packet size stats
        if 'length' in df.columns:
            stats['avg_frame_size'] = float(round(df['length'].mean(), 1))
            stats['max_frame_size'] = int(df['length'].max())
            stats['min_frame_size'] = int(df['length'].min())

        return stats

    @staticmethod
    def _categorize_frame(type_subtype: str) -> str:
        if type_subtype in MGMT_SUBTYPES:
            return 'Management'
        if type_subtype in CTRL_SUBTYPES:
            return 'Control'
        if type_subtype in DATA_SUBTYPES:
            return 'Data'
        return 'Unknown'

    # ------------------------------------------------------------------
    #  Connection event analysis
    # ------------------------------------------------------------------

    def _analyze_connection_events(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze WLAN connection lifecycle events: associations, disconnections,
        roaming, channel switches, and band switches."""
        events: Dict[str, Any] = {}

        # --- Associations (0x0000 = Assoc Req, 0x0001 = Assoc Resp) ---
        assoc_req = df[df['type_subtype'] == '0x0000']
        assoc_resp = df[df['type_subtype'] == '0x0001']
        events['association_requests'] = len(assoc_req)
        events['association_responses'] = len(assoc_resp)
        if not assoc_req.empty and 'sa' in assoc_req.columns:
            events['associating_clients'] = assoc_req['sa'].nunique()
            events['association_by_client'] = assoc_req['sa'].value_counts().head(10).to_dict()

        # --- Reassociations / Roaming (0x0002 = Reassoc Req, 0x0003 = Reassoc Resp) ---
        reassoc_req = df[df['type_subtype'] == '0x0002']
        reassoc_resp = df[df['type_subtype'] == '0x0003']
        events['reassociation_requests'] = len(reassoc_req)
        events['reassociation_responses'] = len(reassoc_resp)

        # Roaming: client (sa) sending reassociation requests to different BSSIDs
        roaming_clients = {}
        if not reassoc_req.empty and 'sa' in reassoc_req.columns and 'bssid' in reassoc_req.columns:
            for client, grp in reassoc_req.groupby('sa'):
                bssids = grp['bssid'].dropna().unique().tolist()
                if len(bssids) >= 1:
                    roaming_clients[client] = bssids
        events['roaming_clients'] = len(roaming_clients)
        events['roaming_details'] = {k: v for k, v in list(roaming_clients.items())[:10]}

        # --- Disconnections (deauth 0x000c + disassoc 0x000a counted as events) ---
        deauth = df[df['type_subtype'] == '0x000c']
        disassoc = df[df['type_subtype'] == '0x000a']
        events['deauthentication_frames'] = len(deauth)
        events['disassociation_frames'] = len(disassoc)
        events['total_disconnections'] = len(deauth) + len(disassoc)
        # Who initiated the disconnections
        disconnect_all = pd.concat([deauth, disassoc], ignore_index=True)
        if not disconnect_all.empty and 'sa' in disconnect_all.columns:
            events['disconnect_sources'] = disconnect_all['sa'].value_counts().head(10).to_dict()

        # --- Authentication frames (0x000b) ---
        auth = df[df['type_subtype'] == '0x000b']
        events['authentication_frames'] = len(auth)
        if not auth.empty and 'sa' in auth.columns:
            events['auth_clients'] = auth['sa'].nunique()

        # --- Channel switching detection ---
        # A client (sa) seen transmitting on more than one channel
        channel_switches = {}
        if 'channel' in df.columns and 'sa' in df.columns:
            client_channels = df[df['channel'] > 0].groupby('sa')['channel'].apply(
                lambda x: sorted(x.unique().tolist())
            )
            for client, channels in client_channels.items():
                if len(channels) > 1:
                    channel_switches[client] = channels
        events['channel_switch_clients'] = len(channel_switches)
        events['channel_switch_details'] = {k: v for k, v in list(channel_switches.items())[:10]}

        # --- Band switching (2.4 GHz vs 5 GHz) ---
        band_switches = {}
        if 'frequency' in df.columns and 'sa' in df.columns:
            freq_df = df[df['frequency'] > 0].copy()
            if not freq_df.empty:
                freq_df['band'] = freq_df['frequency'].apply(
                    lambda f: '2.4GHz' if f < 3000 else '5GHz' if f < 6000 else '6GHz'
                )
                client_bands = freq_df.groupby('sa')['band'].apply(
                    lambda x: sorted(x.unique().tolist())
                )
                for client, bands in client_bands.items():
                    if len(bands) > 1:
                        band_switches[client] = bands
        events['band_switch_clients'] = len(band_switches)
        events['band_switch_details'] = {k: v for k, v in list(band_switches.items())[:10]}

        return events

    # ------------------------------------------------------------------
    #  Threat detection
    # ------------------------------------------------------------------

    def _detect_threats(self, df: pd.DataFrame) -> Dict:
        threats = {}

        conn_failures = self._detect_connection_failures(df)
        if conn_failures['detected']:
            threats['connection_failures'] = conn_failures

        beacon_loss = self._detect_beacon_losses(df)
        if beacon_loss['detected']:
            threats['beacon_loss'] = beacon_loss

        probe_fail = self._detect_probe_failures(df)
        if probe_fail['detected']:
            threats['probe_failures'] = probe_fail

        scan_fail = self._detect_scan_failures(df)
        if scan_fail['detected']:
            threats['scan_failures'] = scan_fail

        weak_signal = self._detect_weak_signal(df)
        if weak_signal['detected']:
            threats['weak_signal_coverage'] = weak_signal

        unprotected = self._detect_unprotected_traffic(df)
        if unprotected['detected']:
            threats['unprotected_traffic'] = unprotected

        ip_fail = self._detect_ip_connectivity_failure(df)
        if ip_fail['detected']:
            threats['ip_connectivity_failure'] = ip_fail

        wpa3_fail = self._detect_wpa3_sae_failures(df)
        if wpa3_fail['detected']:
            threats['wpa3_sae_failures'] = wpa3_fail

        high_retry = self._detect_high_retry(df)
        if high_retry['detected']:
            threats['high_retry_rate'] = high_retry

        action_issues = self._detect_action_frame_issues(df)
        if action_issues['detected']:
            threats['action_frame_issues'] = action_issues

        ctrl_issues = self._detect_control_frame_issues(df)
        if ctrl_issues['detected']:
            threats['control_frame_issues'] = ctrl_issues

        ps_issues = self._detect_power_save_issues(df)
        if ps_issues['detected']:
            threats['power_save_issues'] = ps_issues

        conn_delays = self._detect_connection_delays(df)
        if conn_delays['detected']:
            threats['connection_delays'] = conn_delays

        return threats

    def _detect_connection_failures(self, df: pd.DataFrame) -> Dict:
        """Detect 802.11 connection failures with root-cause classification and frame detail."""
        result = {"detected": False, "severity": "info"}
        failures = []
        failure_summary: Dict[str, int] = {}

        # Root-cause categories and IEEE 802.11-aligned recovery remediations
        # Keys shared by both status codes and reason codes use the same integer value;
        # the is_reason flag selects the right interpretation at call time.
        ROOT_CAUSE = {
            # ── Association / Authentication STATUS CODES ──────────────────────────────
            10:  ('Capability mismatch',
                  'Align 802.11 mode/band between AP and client (HT/VHT/HE). '
                  'Disable proprietary features that the peer may not support. '
                  'Recovery: disconnect, update driver/firmware, reconnect.'),
            11:  ('Reassoc without prior association',
                  'Client sent Reassociation Request with no existing association. '
                  'Recovery: force a full de-association and fresh Association Request. '
                  'Check supplicant state machine for stale state.'),
            12:  ('Association denied – AP policy/capacity',
                  'AP rejected the request due to load limits, ACL, or BSS policy. '
                  'Recovery: reduce AP client count, check MAC ACL, review BSS admission-control settings.'),
            13:  ('Auth algorithm mismatch',
                  'Security mode incompatibility (Open/WPA/WPA2/WPA3/SAE). '
                  'Recovery: align AP and client security settings. '
                  'Ensure the client supports the negotiated AKM suite.'),
            14:  ('Unexpected authentication sequence',
                  'State machine desync — auth sequence number out of order. '
                  'Recovery: deauthenticate and restart the full auth exchange. '
                  'Check for duplicate or retransmitted auth frames.'),
            15:  ('Wrong PSK / credentials',
                  'Passphrase or pre-shared key is incorrect. '
                  'Recovery: re-enter the correct WPA/WPA2/WPA3 passphrase on the client. '
                  'On WPA3-SAE ensure both sides use UTF-8 normalised password.'),
            16:  ('Authentication timeout',
                  'AP did not receive a valid authentication response in time. '
                  'Recovery: check AP load and RF link quality. '
                  'Increase auth-timeout on the AP if RF path is marginal; move client closer.'),
            17:  ('AP at STA capacity',
                  'AP has reached its maximum simultaneous STA limit. '
                  'Recovery: add another AP or increase per-radio STA cap in AP config. '
                  'Enable BSS load-balancing or band-steering to distribute clients.'),
            23:  ('802.1X / EAP authentication failure',
                  'RADIUS server rejected the credentials or certificate. '
                  'Recovery: verify EAP identity, password, and server certificate chain. '
                  'Check RADIUS server logs; ensure system clock is synchronised (cert expiry).'),
            37:  ('RSN IE capability mismatch (status)',
                  'Advertised cipher suite or AKMP in RSN IE is not mutually supported. '
                  'Recovery: align WPA2/WPA3 cipher (CCMP/GCMP) and AKM on both AP and client. '
                  'Upgrade firmware if a newer suite is needed.'),
            53:  ('Invalid PMKID — stale PMKSA cache',
                  'Client presented a cached Pairwise Master Key Identifier (PMKID) in the '
                  'Association Request RSN IE, but the AP does not recognise it. '
                  'This occurs when: (1) the AP rebooted and lost its PMKSA cache, '
                  '(2) the client roamed away for too long and the PMKSA entry expired on the AP, '
                  '(3) the client used Open System auth (auth_alg=0) but included an SAE-derived '
                  'PMKID — skipping SAE Commit/Confirm — hoping to fast-reconnect via PMKSA caching. '
                  'Recovery: client should clear its PMKSA cache and retry with a full '
                  'SAE (auth_alg=3) Commit/Confirm exchange (WPA3) or fresh 4-way handshake (WPA2). '
                  'On the AP side: increase PMKSA cache lifetime if clients frequently roam back.'),
            54:  ('Invalid MDE (Mobility Domain Element)',
                  'Fast BSS Transition (802.11r/FT) failed due to invalid Mobility Domain IE. '
                  'Recovery: ensure AP and client have consistent FT/MDE configuration; '
                  'disable 802.11r on the network if not all APs in the roaming domain are correctly configured.'),
            55:  ('Invalid FTE (Fast BSS Transition Element)',
                  'Fast BSS Transition (802.11r/FT) failed due to invalid Fast Transition IE. '
                  'Recovery: check FT key hierarchy (R0KH-ID, R1KH-ID) on AP; '
                  'ensure all APs in the mobility domain share the same PMK-R0 name/key.'),
            72:  ('WPA3-SAE rejected',
                  'SAE authentication was rejected by the AP. '
                  'Recovery: verify WPA3 passphrase; check AP for WPA3/WPA3-SAE support. '
                  'Ensure client Wi-Fi driver supports SAE commit/confirm exchange.'),
            73:  ('WPA3-SAE commit rejected',
                  'SAE commit message was refused — possible config mismatch or downgrade attack. '
                  'Recovery: check for WPA3-Enterprise vs Personal mismatch; verify passphrase; '
                  'update AP firmware against known SAE vulnerabilities.'),
            74:  ('WPA3-SAE confirm rejected',
                  'SAE confirm exchange failed. '
                  'Recovery: verify WPA3 passphrase normalisation (UTF-8); update AP/client firmware; '
                  'check for SAE anti-clogging token issues on high-load APs.'),
            76:  ('Unknown SAE password identifier',
                  'Client sent a Password Identifier element that the AP does not recognise. '
                  'Recovery: remove or correct the password identifier in client 802.11 config; '
                  'ensure AP and client are configured with the same password identifier (if used).'),
            77:  ('SAE Anti-Clogging Token Required',
                  'AP is under high load and requires an anti-clogging token before processing SAE Commit. '
                  'This is a rate-limiting protection mechanism, not a failure of credentials. '
                  'Recovery: client must restart SAE with the token; check AP load; '
                  'if persistent, check for denial-of-service activity targeting the AP.'),
            78:  ('SAE Elliptic Curve Group not supported',
                  'The finite cyclic group (elliptic curve) selected by the client is not supported by the AP. '
                  'Recovery: align EC group selection (group 19/P-256 is mandatory for WPA3-SAE); '
                  'update AP/client firmware to support required groups.'),

            # ── Deauthentication / Disassociation REASON CODES ─────────────────────────
            1:   ('Unspecified disconnection',
                  'Check AP and client syslogs/debug logs for context around disconnect time. '
                  'Recovery: reconnect; enable verbose Wi-Fi logging to capture next occurrence.'),
            2:   ('Authentication expired / STA inactive',
                  'AP invalidated the STA′s authentication session (key expiry or SA timeout). '
                  'Recovery: reconnect immediately; shorten GTK/PMK lifetime on AP if frequent; '
                  'ensure client sends keep-alive frames before session expires.'),
            3:   ('STA leaving BSS intentionally',
                  'Normal, client-initiated teardown — no failure. '
                  'Recovery: not required. If unexpected, verify supplicant auto-reconnect policy.'),
            4:   ('AP inactivity timeout',
                  'AP received no frames from the STA within the configured idle timer. '
                  'Recovery: reduce AP idle-timeout threshold or enable null-data keep-alives on client. '
                  'Check for power-save modes suppressing uplink traffic.'),
            5:   ('AP overloaded – STA limit reached',
                  'AP cannot accommodate another associated STA. '
                  'Recovery: enable dynamic load balancing, add APs, or raise per-BSS STA limit. '
                  'Use 5 GHz / 6 GHz band-steering to distribute load.'),
            6:   ('Unauthenticated STA sent Class 2 / 3 frame',
                  'Frame received without a valid authentication or association context. '
                  'Recovery: client must restart authentication from scratch (802.11 open auth → assoc → 4-way). '
                  'Check for stale driver state after suspend/resume.'),
            7:   ('Non-associated STA sent Class 3 frame',
                  'Data frame arrived before association completed. '
                  'Recovery: verify that the association handshake completed before data is sent. '
                  'Reset the supplicant state machine and re-associate.'),
            8:   ('STA leaving BSS (normal teardown)',
                  'Orderly disconnect initiated by the STA. '
                  'Recovery: not required. If unexpected, investigate supplicant/driver crash.'),
            9:   ('STA not authenticated with responding STA',
                  'AP received a frame from an STA that was not in authenticated state. '
                  'Recovery: perform full authentication sequence; check for race conditions '
                  'between disassoc and new assoc in roaming scenarios.'),
            10:  ('Unacceptable Power Capability IE',
                  'AP rejected the STA because the advertised TX power is outside regulatory limits. '
                  'Recovery: update country code / regulatory domain setting on client driver.'),
            11:  ('Unacceptable Supported Channels IE',
                  'STA′s Supported Channels IE is incompatible with the AP′s operating channels. '
                  'Recovery: verify regional channel plan; update client driver country setting.'),
            12:  ('BSS Transition Management (roaming)',
                  'AP requested the STA to roam to another BSS via 802.11v BTM. '
                  'Recovery: confirm the roaming candidate AP is reachable; check BTM config; '
                  'if unwanted, disable 802.11v BTM on the AP or client.'),
            13:  ('Malformed / invalid Information Element',
                  'An IE in the management frame contains invalid or unexpected content. '
                  'Recovery: update AP and client firmware; check for driver bugs affecting IE construction.'),
            14:  ('4-way handshake MIC failure / timeout',
                  'WPA2/WPA3 PTK negotiation failed — wrong passphrase or RF-induced packet loss. '
                  'Recovery: (1) verify the WPA2 PSK matches on AP and client. '
                  '(2) Improve RF link quality (move client closer, reduce interference). '
                  '(3) Increase eapol-key retry count on AP for marginal RF environments.'),
            15:  ('Group key (GTK) renewal timeout OR wrong PSK (vendor-dependent)',
                  'This code is AMBIGUOUS: strictly it means GTK renewal failed, but many AP '
                  'implementations (including TP-Link) also send code 15 when the 4-way '
                  'handshake is stuck at Message 1 ↔ Message 2 because the PSK is wrong. '
                  'How to distinguish: if EAPOL Msg1/Msg2 repeats are visible before the deauth '
                  'and Msg3 never appears, the root cause is a wrong passphrase. '
                  'Recovery – if wrong PSK: (1) re-enter the correct WPA2/WPA3 passphrase on the client. '
                  '(2) On WPA3-SAE verify passphrase is UTF-8 normalised. '
                  'Recovery – if GTK renewal: (1) tune AP GTK renewal interval (default 3600 s). '
                  '(2) Prevent deep power-save on client during GTK exchange. '
                  '(3) Enable EAPOL retransmission on AP; update AP firmware.'),
            16:  ('RSN IE mismatch during 4-way handshake',
                  'RSN IE seen in the 4-way handshake differs from the one in (Re)Assoc/Probe. '
                  'Recovery: (1) confirm PSK is correct — mismatch often indicates wrong password. '
                  '(2) Disable and re-enable Wi-Fi on client to clear stale IE cache. '
                  '(3) Ensure AP firmware is not advertising conflicting cipher suites.'),
            17:  ('Invalid group cipher',
                  'Group cipher in RSN IE is not supported by one endpoint. '
                  'Recovery: align group cipher on AP and client (prefer CCMP; disable TKIP). '
                  'Upgrade legacy devices that do not support CCMP group cipher.'),
            18:  ('Invalid pairwise cipher',
                  'Pairwise cipher mismatch (e.g., client wants GCMP, AP only offers CCMP). '
                  'Recovery: configure matching pairwise ciphers (CCMP-128 recommended for WPA2; '
                  'CCMP-256/GCMP-256 for WPA3). Update firmware if needed.'),
            19:  ('Invalid AKMP',
                  'Authentication key management protocol is unrecognised or unsupported. '
                  'Recovery: align AKM suite — PSK (2) for WPA2-Personal, SAE (8) for WPA3-Personal, '
                  '802.1X (1) for Enterprise. Update client/AP firmware for newer AKMs (OWE, FT-SAE).'),
            20:  ('Unsupported RSN IE version',
                  'RSN version in IE is not recognised. '
                  'Recovery: update AP or client firmware to support RSN version 1 (only version defined in 802.11).'),
            21:  ('Invalid RSN IE capabilities',
                  'RSN capability bits are incompatible (e.g., MFP required vs not supported). '
                  'Recovery: check Management Frame Protection (802.11w/MFP) settings — ensure both sides '
                  'agree on Optional/Required/Disabled. Update firmware for PMF support.'),
            22:  ('IEEE 802.1X authentication failed',
                  'RADIUS/EAP exchange was rejected. '
                  'Recovery: verify EAP method, identity, password, or certificate; '
                  'check RADIUS logs; sync system clocks (certificate validity).'),
            23:  ('Cipher suite rejected by security policy',
                  'AP′s local security policy prohibits the negotiated cipher. '
                  'Recovery: update AP security policy to permit the required cipher, '
                  'or upgrade client to use a permitted cipher suite.'),
            24:  ('TDLS teardown – peer unreachable',
                  'TDLS direct link was torn down because the peer became unreachable. '
                  'Recovery: check if TDLS is needed; disable TDLS on client if causing issues. '
                  'Ensure both TDLS peers are within direct RF range.'),
            25:  ('TDLS teardown – requested by peer',
                  'Peer initiated TDLS teardown intentionally. '
                  'Recovery: let TDLS reconnect automatically, or disable TDLS if not required.'),
            28:  ('Lack of SSP roaming agreement',
                  'Roaming was rejected because no Shared Security Policy agreement exists between the APs. '
                  'Recovery: configure matching SSP/RSNA policy across the roaming infrastructure.'),
            31:  ('QoS: AP lacks bandwidth for WMMSSTA (BSS change)',
                  'AP cannot meet QoS requirements after a BSS service change. '
                  'Recovery: re-negotiate TSPEC; reduce QoS stream requirements; check for AP overload.'),
            32:  ('Unspecified QoS-related disassociation',
                  'Recovery: re-associate; check AP WMM/QoS configuration for conflicts.'),
            33:  ('QoS AP lacks bandwidth for the STA',
                  'AP cannot allocate sufficient medium time. '
                  'Recovery: reduce number of active TSPEC streams; upgrade to an 802.11ac/ax AP with higher throughput.'),
            34:  ('Excessive unacknowledged frames / poor RF',
                  'Too many frames went unacknowledged — AP dropped the STA due to channel quality. '
                  'Recovery: improve RF coverage (add APs, reposition client); check for 2.4 GHz interference; '
                  'enable automatic channel selection on AP.'),
            35:  ('STA exceeding TXOP limits',
                  'STA transmitted beyond its allocated Transmission Opportunity. '
                  'Recovery: update client driver; reset QoS/WMM parameters; check for rogue TXOP abuse.'),
            36:  ('Peer STA leaving/resetting',
                  'Remote STA is leaving the BSS or performing an internal reset. '
                  'Recovery: wait for peer to rejoin; check peer power state and connectivity.'),
            37:  ('Peer does not want to use the mechanism',
                  'Peer rejected an optional mechanism (e.g., BA agreement, fast BSS transition). '
                  'Recovery: disable the feature on initiating side or update peer firmware.'),
            38:  ('Peer received frames requiring incomplete setup',
                  'A frame was sent for a feature that was never fully negotiated. '
                  'Recovery: re-initialise the relevant protocol (Block Ack / FT / TDLS) with a fresh setup exchange.'),
            39:  ('Peer mechanism setup timeout',
                  'Setup handshake for a feature did not complete in time. '
                  'Recovery: retry the setup; check for heavy congestion delaying management frames; '
                  'increase setup timeout if allowed by driver.'),
            45:  ('Peer does not support requested cipher suite',
                  'Peer rejected a cipher that it does not implement. '
                  'Recovery: configure a mutually supported cipher (CCMP-128 is universally supported in WPA2).'),
            46:  ('DLS target STA is not a QoS STA',
                  'Direct-Link Setup attempted with a non-QoS STA. '
                  'Recovery: disable DLS or ensure all participants support WMM/QoS.'),
        }

        def _classify(code: int, is_reason: bool) -> tuple:
            entry = ROOT_CAUSE.get(code)
            if entry:
                return entry[0], entry[1]
            scope = 'Reason' if is_reason else 'Status'
            return f'{scope} code {code}', f'Refer to IEEE 802.11 {scope.lower()} code {code}'

        def _frame_info(row) -> Dict:
            info = {
                'frame': int(row.get('frame_number', 0)) if 'frame_number' in row.index else None,
                'timestamp': float(row.get('timestamp', 0)),
                'sa': row.get('sa'),
                'bssid': row.get('bssid'),
            }
            if 'signal_dbm' in row.index and row.get('signal_dbm', 0) != 0:
                info['signal_dbm'] = int(row['signal_dbm'])
            return info

        # -- Association / Reassociation response failures (status code != 0) --
        for subtype, label in [('0x0001', 'Association'), ('0x0003', 'Reassociation')]:
            resp_df = df[df['type_subtype'] == subtype]
            if not resp_df.empty and 'status_code' in resp_df.columns:
                fail_df = resp_df[resp_df['status_code'] > 0]
                for _, row in fail_df.iterrows():
                    code = int(row['status_code'])
                    cat, remediation = _classify(code, is_reason=False)
                    entry = {
                        'type': f'{label} Response Failure',
                        'root_cause': cat,
                        'remediation': remediation,
                        'code': code,
                        'reason': STATUS_CODES.get(code, f'Status code {code}'),
                        **_frame_info(row),
                    }
                    failures.append(entry)
                    failure_summary[cat] = failure_summary.get(cat, 0) + 1

        # -- Authentication response failures --
        auth_df = df[df['type_subtype'] == '0x000b']
        if not auth_df.empty and 'status_code' in auth_df.columns:
            auth_fail_df = auth_df[auth_df['status_code'] > 0]
            for _, row in auth_fail_df.iterrows():
                code = int(row['status_code'])
                cat, remediation = _classify(code, is_reason=False)
                entry = {
                    'type': 'Authentication Failure',
                    'root_cause': cat,
                    'remediation': remediation,
                    'code': code,
                    'reason': STATUS_CODES.get(code, f'Status code {code}'),
                    **_frame_info(row),
                }
                failures.append(entry)
                failure_summary[cat] = failure_summary.get(cat, 0) + 1

        # -- Deauthentication with reason codes --
        deauth_df = df[df['type_subtype'] == '0x000c']
        if not deauth_df.empty and 'reason_code' in deauth_df.columns:
            deauth_coded = deauth_df[deauth_df['reason_code'] > 0]
            for _, row in deauth_coded.iterrows():
                code = int(row['reason_code'])
                cat, remediation = _classify(code, is_reason=True)
                entry = {
                    'type': 'Deauthentication',
                    'root_cause': cat,
                    'remediation': remediation,
                    'code': code,
                    'reason': REASON_CODES.get(code, f'Reason code {code}'),
                    **_frame_info(row),
                }
                failures.append(entry)
                failure_summary[cat] = failure_summary.get(cat, 0) + 1

        # -- Disassociation with reason codes --
        disassoc_df = df[df['type_subtype'] == '0x000a']
        if not disassoc_df.empty and 'reason_code' in disassoc_df.columns:
            disassoc_coded = disassoc_df[disassoc_df['reason_code'] > 0]
            for _, row in disassoc_coded.iterrows():
                code = int(row['reason_code'])
                cat, remediation = _classify(code, is_reason=True)
                entry = {
                    'type': 'Disassociation',
                    'root_cause': cat,
                    'remediation': remediation,
                    'code': code,
                    'reason': REASON_CODES.get(code, f'Reason code {code}'),
                    **_frame_info(row),
                }
                failures.append(entry)
                failure_summary[cat] = failure_summary.get(cat, 0) + 1

        # -- EAPOL 4-way handshake stall detection (wrong PSK indicator) --
        # tshark field wlan_rsna_eapol.keydes.msgnr gives message number 1-4 directly:
        #   Msg1 (AP→STA):  ANonce delivery — starts the handshake
        #   Msg2 (STA→AP):  SNonce + MIC (MIC computed from PSK-derived PTK)
        #   Msg3 (AP→STA):  PTK install — AP only sends this if Msg2 MIC was valid
        #   Msg4 (STA→AP):  Confirmation
        # If only Msg1+Msg2 seen (no Msg3) → AP kept rejecting Msg2 MIC → wrong PSK
        if 'eapol_msg_nr' in df.columns:
            eapol_df = df[df['eapol_msg_nr'] > 0].copy()
            if not eapol_df.empty:
                msg1 = eapol_df[eapol_df['eapol_msg_nr'] == 1]
                msg2 = eapol_df[eapol_df['eapol_msg_nr'] == 2]
                msg3 = eapol_df[eapol_df['eapol_msg_nr'] == 3]

                if len(msg1) > 0 and len(msg2) > 0 and len(msg3) == 0:
                    # Classic wrong-PSK pattern
                    result['eapol_handshake_analysis'] = {
                        'pattern': '4-way handshake stalled at Msg1/Msg2 — Msg3 never received',
                        'msg1_count': int(len(msg1)),
                        'msg2_count': int(len(msg2)),
                        'msg3_count': 0,
                        'wrong_psk_likely': True,
                        'note': (
                            'AP retransmitted Msg1 and client kept sending Msg2, '
                            'but AP never sent Msg3. This means AP rejected the '
                            'MIC in Msg2 — the PSK used by the client does not '
                            'match the AP. Some APs (TP-Link, Netgear) incorrectly '
                            'report reason code 15 for this failure instead of '
                            'the correct code 14 (MIC failure).'
                        ),
                        'immediate_action': 'Verify and re-enter the WPA2/WPA3 passphrase on the client device.',
                    }
                    # Override the root_cause label for existing reason-15 failures
                    for f in failures:
                        if f.get('code') == 15:
                            f['root_cause'] = 'Wrong PSK (4-way handshake Msg1/Msg2 stall — vendor sends code 15)'
                            f['remediation'] = (
                                'Re-enter the correct WPA2/WPA3 passphrase on the client. '
                                'The AP (vendor firmware) reported GTK timeout (code 15) but '
                                'EAPOL frame analysis confirms Msg3 was never sent — wrong PSK.'
                            )
                        failure_summary.pop('Group key (GTK) renewal timeout OR wrong PSK (vendor-dependent)', None)
                    failure_summary['Wrong PSK — 4-way handshake stall (AP sent code 15)'] = len(msg1)

                elif len(msg1) > 0 and len(msg3) > 0:
                    result['eapol_handshake_analysis'] = {
                        'pattern': '4-way handshake progressed to Msg3 (association likely succeeded)',
                        'msg1_count': int(len(msg1)),
                        'msg2_count': int(len(msg2)),
                        'msg3_count': int(len(msg3)),
                        'wrong_psk_likely': False,
                        'note': 'Handshake reached Msg3 — passphrase appears correct. '
                                'Disconnection may be due to GTK renewal or other reason.',
                    }

        # -- Fallback: unanswered association requests --
        if 'status_code' not in df.columns:
            assoc_req_count = len(df[df['type_subtype'] == '0x0000'])
            assoc_resp_count = len(df[df['type_subtype'] == '0x0001'])
            unanswered = max(0, assoc_req_count - assoc_resp_count)
            if unanswered > 0:
                failure_summary['No association response (AP unreachable / timeout)'] = unanswered

        if failures or failure_summary:
            total = len(failures)
            wpa_failures = sum(1 for f in failures
                               if f.get('code') in {6, 14, 15, 16, 23, 72, 73, 74})
            severity = 'critical' if wpa_failures > 0 else 'high'
            result['detected'] = True
            result['severity'] = severity
            result['total_failures'] = total
            result['failure_breakdown'] = dict(
                sorted(failure_summary.items(), key=lambda x: x[1], reverse=True)
            )
            top3 = sorted(failure_summary.items(), key=lambda x: x[1], reverse=True)[:3]
            result['message'] = (
                f"{total} connection failure event(s): "
                + ', '.join(f'{v}\u00d7 {k}' for k, v in top3)
            )

            # Unique remediations keyed by root-cause category
            seen_cats: set = set()
            remediations = {}
            for f in failures:
                cat = f.get('root_cause', '')
                if cat and cat not in seen_cats:
                    remediations[cat] = f.get('remediation', '')
                    seen_cats.add(cat)
            result['remediations'] = remediations

            # Per-client timeline (sorted by timestamp)
            client_timelines: Dict[str, list] = defaultdict(list)
            for f in failures:
                client = f.get('sa') or f.get('bssid') or 'unknown'
                client_timelines[client].append({
                    'frame': f.get('frame'),
                    'type': f['type'],
                    'root_cause': f['root_cause'],
                    'code': f['code'],
                    'reason': f['reason'],
                    'timestamp': f.get('timestamp'),
                    'signal_dbm': f.get('signal_dbm'),
                })
            for client in client_timelines:
                client_timelines[client].sort(key=lambda x: x.get('timestamp') or 0)
            result['client_timelines'] = dict(client_timelines)

            result['failure_details'] = sorted(failures, key=lambda x: x.get('timestamp') or 0)[:30]

        # -- Per-client connection flow analysis --
        result['connection_flows'] = self._build_connection_flows(df)

        # Update failure entries with validated reasons from session diagnoses
        for flow_client, sessions in result['connection_flows'].items():
            for session in sessions:
                terminal_evt = next((e for e in reversed(session.get('events', []))
                                     if e.get('is_terminal')), None)
                if not terminal_evt:
                    continue
                validated = terminal_evt.get('validated_reason', '')
                evidence   = terminal_evt.get('evidence', [])
                if not validated:
                    continue
                # Apply validated reason to matching failure entries
                for f in failures:
                    if (f.get('sa') == flow_client or f.get('bssid') == flow_client) and \
                            f.get('frame') == terminal_evt.get('frame'):
                        f['root_cause'] = validated
                        f['remediation'] = session.get('diagnosis', {}).get(
                            'recommended_action', f.get('remediation', ''))
                        f['evidence'] = evidence
                        f['connection_phase'] = session.get('diagnosis', {}).get('phase', '')

        return result

    # ------------------------------------------------------------------
    #  Connection flow builder (per-client session lifecycle)
    # ------------------------------------------------------------------

    def _build_connection_flows(self, df: pd.DataFrame) -> Dict[str, List[Dict]]:
        """Build per-client 802.11 connection lifecycle flows for every client
        involved in a deauth, disassociation, or association failure event."""

        disconnect_types = {'0x000c', '0x000a'}
        disconnect_df = df[df['type_subtype'].isin(disconnect_types)]

        # Also include clients that had association/reassociation failures
        assoc_resp_types = {'0x0001', '0x0003'}
        assoc_fail_df = df[(df['type_subtype'].isin(assoc_resp_types)) & (df['status_code'] > 0)]

        if disconnect_df.empty and assoc_fail_df.empty:
            return {}

        # Collect client MACs (the non-AP, non-broadcast party in disconnect frames)
        client_macs: set = set()
        for _, row in disconnect_df.iterrows():
            bssid = row.get('bssid') or ''
            for ac in ('sa', 'da'):
                addr = row.get(ac)
                if isinstance(addr, str) and addr and addr != bssid and addr != 'ff:ff:ff:ff:ff:ff':
                    client_macs.add(addr)

        # Also collect clients that received association failure responses
        for _, row in assoc_fail_df.iterrows():
            da = row.get('da')
            if isinstance(da, str) and da and da != 'ff:ff:ff:ff:ff:ff':
                client_macs.add(da)

        EAPOL_STEPS = {
            1: ('EAPOL Msg1 — ANonce',
                'AP sends random ANonce to start 4-way handshake'),
            2: ('EAPOL Msg2 — SNonce+MIC',
                'Client sends SNonce + MIC derived from PSK. AP validates MIC to verify PSK.'),
            3: ('EAPOL Msg3 — PTK Install',
                'AP accepted client MIC \u2192 PSK is correct. Sends GTK and triggers PTK install.'),
            4: ('EAPOL Msg4 — Confirm',
                'Client confirms PTK installed. Session keys now active.'),
        }

        flows: Dict[str, List[Dict]] = {}

        for client_mac in sorted(client_macs):
            cmask = (df['sa'] == client_mac) | (df['da'] == client_mac)
            client_df = df[cmask].sort_values('timestamp').reset_index(drop=True)
            if client_df.empty:
                continue

            sessions: List[Dict] = []
            cur: Dict = {'events': [], 'ap_bssid': None, 'start_frame': None,
                         'data_frames': 0, '_last_data_ts': None}

            for _, row in client_df.iterrows():
                subtype  = row.get('type_subtype', '')
                ts       = float(row.get('timestamp', 0) or 0)
                fn       = int(row.get('frame_number', 0) or 0)
                sa       = row.get('sa')
                da       = row.get('da')
                bssid    = row.get('bssid')
                signal   = int(row.get('signal_dbm', 0) or 0) or None
                status   = int(row.get('status_code', 0) or 0)
                reason   = int(row.get('reason_code', 0) or 0)
                eapol_nr = int(row.get('eapol_msg_nr', 0) or 0)
                auth_seq = int(row.get('auth_seq', 0) or 0)
                is_from  = (sa == client_mac)
                is_data  = subtype in {'0x0020', '0x0021', '0x0022',
                                       '0x0024', '0x0028', '0x002c'}
                # EAPOL frames ride inside QoS-Data (0x0028) — must check BEFORE
                # the generic data-frame skip below
                is_eapol = eapol_nr > 0

                # New session boundary: client sends Auth Request
                # SAE Commit (auth_alg=3, seq=1) also starts a new session
                auth_alg_val = int(row.get('auth_alg', 0) or 0) if 'auth_alg' in row.index else 0
                is_sae_frame = (auth_alg_val == 3)
                if subtype == '0x000b' and is_from and auth_seq in (0, 1):
                    if cur['events']:
                        cur.pop('_last_data_ts', None)
                        sessions.append(cur)
                    cur = {'events': [], 'ap_bssid': bssid, 'start_frame': fn,
                           'data_frames': 0, '_last_data_ts': None,
                           'auth_protocol': 'WPA3-SAE' if is_sae_frame else 'WPA2'}

                if cur['start_frame'] is None:
                    cur['start_frame'] = fn
                if cur['ap_bssid'] is None and bssid:
                    cur['ap_bssid'] = bssid

                # Data frames: count + track last timestamp, don't list individually
                # But skip this if it's actually an EAPOL frame inside QoS-Data
                if is_data and not is_eapol:
                    cur['data_frames'] += 1
                    cur['_last_data_ts'] = ts
                    continue

                # Build event dict for management / EAPOL frames
                evt: Dict[str, Any] = {
                    'frame': fn,
                    'timestamp': ts,
                    'signal_dbm': signal,
                    'direction': 'client\u2192AP' if is_from else 'AP\u2192client',
                }

                if is_eapol:
                    label, note = EAPOL_STEPS.get(eapol_nr,
                                                  (f'EAPOL Msg{eapol_nr}', ''))
                    evt.update({'step': label, 'note': note, 'category': 'eapol'})

                elif subtype == '0x0004' and is_from:
                    ssid = row.get('ssid')
                    ssid = str(ssid) if ssid and not (isinstance(ssid, float) and pd.isna(ssid)) else ''
                    evt.update({'step': 'Probe Request',
                                'note': f'Scanning for {"\"" + ssid + "\"" if ssid else "any network (wildcard)"}',
                                'category': 'scan'})

                elif subtype == '0x0005' and not is_from:
                    ssid = row.get('ssid')
                    ssid = str(ssid) if ssid and not (isinstance(ssid, float) and pd.isna(ssid)) else ''
                    evt.update({'step': 'Probe Response',
                                'note': f'AP responded{chr(32)+"(SSID: "+ssid+")" if ssid else ""}',
                                'category': 'scan'})

                elif subtype == '0x000b':
                    auth_alg_val = int(row.get('auth_alg', 0) or 0) if 'auth_alg' in row.index else 0
                    is_sae = (auth_alg_val == 3)
                    if is_sae:
                        # SAE (WPA3) uses auth_seq 1=Commit, 2=Confirm
                        seq_label = {1: 'Commit', 2: 'Confirm'}.get(auth_seq, f'seq={auth_seq}')
                        direction_label = 'Client → AP' if is_from else 'AP → Client'
                        ok = (status == 0)
                        if is_from:
                            evt.update({
                                'step': f'SAE {seq_label} ({direction_label})',
                                'note': f'WPA3-SAE {seq_label}: client initiating Dragonfly handshake step {auth_seq}',
                                'category': 'auth',
                                'auth_protocol': 'WPA3-SAE',
                            })
                        else:
                            evt.update({
                                'step': f'SAE {seq_label} Response ({direction_label})',
                                'status': status,
                                'note': (f'WPA3-SAE {seq_label} accepted'
                                         if ok else
                                         f'WPA3-SAE {seq_label} REJECTED — '
                                         f'{STATUS_CODES.get(status, "status " + str(status))}'),
                                'category': 'success' if ok else 'failure',
                                'auth_protocol': 'WPA3-SAE',
                            })
                    else:
                        if is_from:
                            evt.update({'step': 'Auth Request (Open/WPA2)',
                                        'note': 'Client requesting 802.11 Open/WPA2 authentication',
                                        'category': 'auth'})
                        else:
                            ok = (status == 0)
                            evt.update({
                                'step': 'Auth Response',
                                'status': status,
                                'note': 'Authentication accepted' if ok
                                        else f'Authentication REJECTED \u2014 {STATUS_CODES.get(status, "status " + str(status))}',
                                'category': 'success' if ok else 'failure',
                            })

                elif subtype in ('0x0000', '0x0002') and is_from:
                    label = 'Association Request' if subtype == '0x0000' \
                            else 'Reassociation Request'
                    evt.update({'step': label,
                                'note': 'Client requesting to join BSS',
                                'category': 'assoc'})

                elif subtype in ('0x0001', '0x0003') and not is_from:
                    label = 'Association Response' if subtype == '0x0001' \
                            else 'Reassociation Response'
                    ok = (status == 0)
                    evt.update({
                        'step': label,
                        'status': status,
                        'note': 'Client joined BSS successfully' if ok
                                else f'Association REJECTED \u2014 {STATUS_CODES.get(status, "status " + str(status))}',
                        'category': 'success' if ok else 'failure',
                    })
                    # Treat association failure as a terminal event for diagnosis
                    if not ok:
                        evt['is_terminal'] = True
                        evt['status_code'] = status
                        cur['events'].append(evt)
                        # Diagnose the association failure session
                        diag = self._diagnose_assoc_failure_session(cur, client_mac, status)
                        cur['diagnosis'] = diag
                        evt['validated_reason'] = diag.get('validated_reason', '')
                        evt['evidence'] = diag.get('evidence', [])
                        cur.pop('_last_data_ts', None)
                        sessions.append(cur)
                        cur = {'events': [], 'ap_bssid': None, 'start_frame': None,
                               'data_frames': 0, '_last_data_ts': None}
                        continue  # already appended evt above

                elif subtype in ('0x000c', '0x000a'):
                    frame_type  = 'Deauthentication' if subtype == '0x000c' \
                                  else 'Disassociation'
                    initiator   = 'Client' if is_from else 'AP'
                    reason_txt  = REASON_CODES.get(reason, f'Reason code {reason}')
                    evt.update({
                        'step': frame_type,
                        'reason_code': reason,
                        'reason_text': reason_txt,
                        'note': f'{initiator} terminated connection \u2014 {reason_txt}',
                        'category': 'disconnect',
                        'is_terminal': True,
                    })
                    # Append session data-frame summary before diagnosis
                    if cur['data_frames'] > 0:
                        cur['data_frame_summary'] = {
                            'count': cur['data_frames'],
                            'last_data_ts': cur['_last_data_ts'],
                        }
                    cur['events'].append(evt)
                    # Diagnose and annotate terminal event
                    diag = self._diagnose_connection_session(cur, client_mac)
                    cur['diagnosis'] = diag
                    evt['validated_reason'] = diag.get('validated_disconnect', reason_txt)
                    evt['evidence'] = diag.get('evidence', [])
                    cur.pop('_last_data_ts', None)
                    sessions.append(cur)
                    cur = {'events': [], 'ap_bssid': None, 'start_frame': None,
                           'data_frames': 0, '_last_data_ts': None}
                    continue  # already appended evt above
                else:
                    continue   # skip control frames etc.

                cur['events'].append(evt)

            # Trailing open session (no terminal event captured)
            if cur['events']:
                cur.pop('_last_data_ts', None)
                sessions.append(cur)

            if sessions:
                flows[client_mac] = sessions

        return flows

    def _diagnose_connection_session(self, session: Dict, client_mac: str) -> Dict:
        """Validate the true disconnect reason using frame-sequence evidence for one session."""
        events  = session.get('events', [])
        diagnosis: Dict[str, Any] = {}

        def _has(step_substr: str) -> bool:
            return any(step_substr in e.get('step', '') for e in events)

        def _first(step_substr: str) -> Any:
            return next((e for e in events if step_substr in e.get('step', '')), None)

        def _last_terminal() -> Any:
            return next((e for e in reversed(events) if e.get('is_terminal')), None)

        auth_resp  = _first('Auth Response') or _first('SAE Confirm Response')
        assoc_resp = _first('Association Response') or _first('Reassociation Response')
        terminal   = _last_terminal()

        # SAE-specific: check Commit and Confirm steps
        sae_commit_ok   = _first('SAE Commit Response') and \
                          _first('SAE Commit Response').get('status', 0) == 0
        sae_confirm_ok  = _first('SAE Confirm Response') and \
                          _first('SAE Confirm Response').get('status', 0) == 0
        is_wpa3_session = (session.get('auth_protocol') == 'WPA3-SAE') or \
                          _has('SAE Commit') or _has('SAE Confirm')

        auth_ok  = sae_confirm_ok if is_wpa3_session else \
                   ((auth_resp is None) or (auth_resp.get('status', 0) == 0))
        assoc_ok = assoc_resp is not None and assoc_resp.get('status', 0) == 0
        mc = {i: sum(1 for e in events if f'EAPOL Msg{i}' in e.get('step', ''))
              for i in range(1, 5)}
        eapol_seen = mc[1] > 0 or mc[2] > 0

        diagnosis.update({
            'authenticated':    auth_ok,
            'associated':       assoc_ok,
            'eapol_stats':      mc,
            'data_frames':      session.get('data_frames', 0),
            'auth_protocol':    'WPA3-SAE' if is_wpa3_session else 'WPA2',
            'sae_commit_ok':    sae_commit_ok if is_wpa3_session else None,
            'sae_confirm_ok':   sae_confirm_ok if is_wpa3_session else None,
        })

        # Connection phase at the moment of failure
        if is_wpa3_session and not sae_commit_ok:
            diagnosis['phase'] = 'Failed at WPA3-SAE Commit'
        elif is_wpa3_session and not sae_confirm_ok:
            diagnosis['phase'] = 'Failed at WPA3-SAE Confirm'
        elif not auth_ok:
            diagnosis['phase'] = 'Failed at Authentication'
        elif not assoc_ok and not eapol_seen:
            diagnosis['phase'] = 'Failed at Association'
        elif eapol_seen and mc[3] == 0:
            diagnosis['phase'] = 'Failed during 4-way Handshake'
        elif eapol_seen and mc[4] == 0 and mc[3] > 0:
            diagnosis['phase'] = 'Failed at EAPOL Msg4 (PTK confirm)'
        elif assoc_ok and session.get('data_frames', 0) > 0:
            diagnosis['phase'] = 'Disconnected after active data session'
        else:
            diagnosis['phase'] = 'Disconnected after association'

        if terminal is None:
            return diagnosis

        reason_code = terminal.get('reason_code', 0)
        evidence: List[str] = []
        validated = terminal.get('reason_text', REASON_CODES.get(reason_code, f'Reason code {reason_code}'))

        # ── Validated reason logic per reason code ──────────────────────────
        m1, m2, m3, m4 = mc[1], mc[2], mc[3], mc[4]

        if reason_code in (14, 15, 16):
            if m1 > 0 and m2 > 0 and m3 == 0:
                evidence += [
                    f'EAPOL sequence: {m1}\u00d7 Msg1 (ANonce), {m2}\u00d7 Msg2 (SNonce+MIC), 0\u00d7 Msg3',
                    'AP never sent Msg3 (PTK Install) \u2014 MIC validation of Msg2 failed',
                    'Msg2 MIC is derived from the PSK \u2014 mismatch means wrong passphrase on client',
                ]
                if reason_code == 15:
                    evidence.append(
                        'AP reported reason code 15 (GTK renewal timeout) \u2014 '
                        'this is a known TP-Link / vendor firmware quirk; '
                        'real cause is wrong PSK (IEEE 802.11 requires code 14 for this case)')
                elif reason_code == 16:
                    evidence.append(
                        'Code 16 (IE mismatch) can also indicate wrong PSK when RSN IEs '
                        'differ after a stale assoc cache \u2014 EAPOL stall confirms wrong PSK')
                validated = ('Wrong PSK \u2014 4-way handshake stalled '
                             '(AP rejected Msg2 MIC; Msg3 never sent)')
                diagnosis['recommended_action'] = (
                    'Re-enter the correct WPA2/WPA3 passphrase on the client device. '
                    'On WPA3-SAE verify passphrase is UTF-8 normalised.')

            elif m1 > 0 and m3 > 0 and m4 == 0:
                evidence += [
                    f'EAPOL: Msg1\u2192Msg2\u2192Msg3 received, Msg4 not captured',
                    'Client did not confirm PTK installation \u2014 possible RF loss or client driver bug',
                ]
                validated = 'Handshake incomplete \u2014 Msg4 missing (client did not confirm PTK)'
                diagnosis['recommended_action'] = (
                    'Check RF stability; update client Wi-Fi driver. '
                    'Increase EAPOL retransmit count on AP.')

            elif m1 > 0 and m4 > 0 and reason_code == 15:
                evidence += [
                    f'Full 4-way handshake observed: {m1}/{m2}/{m3}/{m4} Msg 1\u20134',
                    'Handshake was completed \u2014 PSK is correct',
                    'AP disconnected during periodic GTK renewal (Group Temporal Key refresh)',
                ]
                validated = ('GTK renewal timeout \u2014 4-way handshake had completed; '
                             'PSK is correct')
                diagnosis['recommended_action'] = (
                    'Tune AP GTK renewal interval (default 3600 s). '
                    'Ensure client is not in deep power-save during GTK exchange. '
                    'Update AP firmware and enable EAPOL retransmission.')

            elif not eapol_seen and reason_code == 15:
                evidence.append(
                    'No EAPOL frames captured in this session \u2014 '
                    'cannot confirm PSK status from frame evidence')
                validated = 'GTK / 4-way handshake failure (EAPOL frames not captured \u2014 check passphrase)'
                diagnosis['recommended_action'] = (
                    'Verify WPA2/WPA3 passphrase; check AP inactivity or GTK timer settings.')

        elif reason_code == 1:
            if m1 > 0 and m3 == 0:
                evidence += [
                    'EAPOL Msg3 never seen despite Msg1/Msg2 \u2014 likely wrong PSK',
                    'AP used unspecified code 1 instead of correct code 14/15',
                ]
                validated = 'Likely wrong PSK \u2014 EAPOL stall indicates MIC failure (code 1 = vendor fallback)'
            elif not auth_ok:
                evidence.append('Authentication response showed failure status')
                validated = 'Connection failed at authentication (code 1 used as generic failure)'
            else:
                evidence.append('No specific frame evidence; check AP syslog for detail')
                validated = 'Unspecified \u2014 no conclusive frame-level evidence found'
            diagnosis['recommended_action'] = (
                'Enable verbose 802.11 logging on AP; verify passphrase and RSN config.')

        elif reason_code in (2, 4):
            last_data_ts = session.get('data_frame_summary', {}).get('last_data_ts')
            term_ts      = terminal.get('timestamp', 0)
            if last_data_ts:
                idle = term_ts - last_data_ts
                evidence.append(f'Last data frame: {idle:.1f}s before deauth/disassoc')
                evidence.append(
                    'AP inactivity timer fired \u2014 no uplink traffic received')
                if eapol_seen:
                    evidence.append(
                        'EAPOL frames were in progress during idle period \u2014 '
                        'check whether power-save mode suppressed data frames')
                validated = f'AP inactivity timeout \u2014 client silent for {idle:.0f}s'
                diagnosis['recommended_action'] = (
                    f'Reduce AP idle-timeout or enable null-data keepalives on client. '
                    f'Disable deep power-save if EAPOL was concurrent.')
            else:
                evidence.append('No data frames observed in this session')
                validated = 'AP inactivity timeout \u2014 client never sent data frames'
                diagnosis['recommended_action'] = (
                    'Check if client ever associated fully; verify power-save settings.')

        elif reason_code == 3:
            direction = terminal.get('direction', '')
            if 'client\u2192AP' in direction:
                evidence.append('Deauth/Disassoc sent BY the client (SA = client MAC) \u2014 voluntary')
                validated = 'Client voluntarily disconnected (normal teardown, code 3)'
                diagnosis['recommended_action'] = (
                    'No action needed. If unexpected, check supplicant auto-reconnect policy.')
            else:
                evidence.append('AP sent code 3 (STA-leaving) \u2014 normally client-initiated; verify AP logs')
                validated = 'AP sent code 3 \u2014 possible AP-side reset or authentication expiry'
                diagnosis['recommended_action'] = 'Check AP firmware and BSS policy; confirm no forced deauth rule.'

        elif reason_code == 5:
            evidence.append('AP reached its maximum simultaneous STA limit')
            validated = 'AP overloaded \u2014 maximum STA count reached; client was ejected'
            diagnosis['recommended_action'] = (
                'Increase per-radio STA limit on AP, add another AP, or enable band-steering.')

        elif reason_code in (6, 7, 9):
            if not auth_ok or not assoc_ok:
                evidence.append('Auth/Assoc did not complete before restricted frame was sent')
            evidence.append(
                'Client transmitted a Class 2/3 frame outside authenticated or associated state')
            validated = (f'Unauthenticated STA frame \u2014 class 2/3 violation '
                         f'(reason {reason_code})')
            diagnosis['recommended_action'] = (
                'Reset client Wi-Fi driver; check for stale state after suspend/resume. '
                'Re-authenticate from scratch.')

        elif reason_code == 12:
            evidence.append('AP used 802.11v BSS Transition Management to request roaming')
            validated = 'BSS Transition (802.11v) \u2014 AP directed client to roam to a better AP'
            diagnosis['recommended_action'] = (
                'Verify BTM candidate AP is reachable and configured correctly. '
                'If unwanted, disable 802.11v BTM on AP or client supplicant.')

        elif reason_code == 13:
            evidence.append('A management frame contained a malformed or unexpected Information Element')
            validated = 'Malformed IE \u2014 driver or firmware generating invalid 802.11 IEs'
            diagnosis['recommended_action'] = 'Update AP and client firmware; file driver bug report if repeatable.'

        elif reason_code == 34:
            sig = terminal.get('signal_dbm')
            if sig and sig < -70:
                evidence.append(f'Signal at deauth: {sig} dBm (below -70 dBm threshold)')
                validated = f'Poor RF conditions \u2014 excessive unacknowledged frames (signal {sig} dBm)'
            elif sig:
                evidence.append(f'Signal at deauth: {sig} dBm (moderate \u2014 may be interference)')
                validated = f'AP-reported poor channel conditions (signal {sig} dBm)'
            else:
                validated = 'Poor channel conditions \u2014 check RF coverage and interference'
            diagnosis['recommended_action'] = (
                'Improve RF coverage: reposition AP/client, reduce 2.4 GHz interference, '
                'enable automatic channel selection on AP.')

        else:
            # Provide structural context for uncategorised codes
            if not auth_ok:
                evidence.append('Authentication did not complete')
            if assoc_ok:
                evidence.append('Association was established before failure')
            if eapol_seen:
                evidence.append(f'EAPOL activity: {m1}/{m2}/{m3}/{m4} Msg 1\u20134')
            validated = REASON_CODES.get(reason_code, f'Reason code {reason_code}')
            diagnosis['recommended_action'] = (
                f'Refer to IEEE 802.11 reason code {reason_code}; '
                f'collect AP syslog and client debug logs at time of failure.')

        diagnosis['validated_disconnect'] = validated
        diagnosis['evidence'] = evidence
        return diagnosis

    def _diagnose_assoc_failure_session(self, session: Dict, client_mac: str, status_code: int) -> Dict:
        """Diagnose the root cause of an association failure by examining the full
        authentication→association frame sequence within the session.

        This provides detailed root-cause analysis for failures like:
        - Status 53: Invalid PMKID (stale PMKSA cache / auth method mismatch)
        - Status 37: RSN IE mismatch
        - Other association rejections with frame-level evidence
        """
        events = session.get('events', [])
        diagnosis: Dict[str, Any] = {
            'status_code': status_code,
            'status_text': STATUS_CODES.get(status_code, f'Status code {status_code}'),
        }
        evidence: List[str] = []
        validated = STATUS_CODES.get(status_code, f'Status code {status_code}')

        # Determine auth method used in this session
        auth_events = [e for e in events if 'auth' in e.get('category', '') or 'Auth' in e.get('step', '')]
        sae_events = [e for e in events if 'SAE' in e.get('step', '')]
        open_auth_events = [e for e in events if 'Open/WPA2' in e.get('step', '')]

        used_sae = len(sae_events) > 0
        used_open_auth = len(open_auth_events) > 0
        auth_protocol = 'WPA3-SAE' if used_sae else ('WPA2/Open' if used_open_auth else 'unknown')

        diagnosis['auth_protocol_used'] = auth_protocol
        diagnosis['phase'] = 'Failed at Association'

        # ── Status Code 53: Invalid PMKID ────────────────────────────────────
        if status_code == 53:
            evidence.append(
                'AP rejected association with Status Code 53: Invalid PMKID')

            if used_open_auth and not used_sae:
                evidence.append(
                    'Client used Open System authentication (auth_alg=0) before this '
                    'Association Request — NOT SAE (auth_alg=3)')
                evidence.append(
                    'Client likely included a cached PMKID in the RSN IE of the Association '
                    'Request, attempting PMKSA caching to skip full SAE authentication')
                evidence.append(
                    'The AP did not recognise the PMKID — the cached PMK is stale or invalid')
                evidence.append(
                    'Root Cause: PMKSA cache mismatch — client attempted fast-reconnect '
                    'with a stale/expired PMK instead of performing full SAE exchange')
                validated = ('Invalid PMKID — client attempted PMKSA-cached reconnection '
                             'with Open auth (skipping SAE) but AP\'s PMKSA cache entry expired or '
                             'was invalidated (AP reboot, cache timeout, or client roamed away too long)')
                diagnosis['recommended_action'] = (
                    '(1) Client should clear PMKSA cache and retry with full SAE '
                    '(auth_alg=3 Commit/Confirm) authentication. '
                    '(2) On AP: increase PMKSA cache lifetime if clients frequently roam back. '
                    '(3) On client: reduce PMKSA cache timeout to avoid attempting stale entries. '
                    '(4) If AP was recently rebooted, all clients must re-authenticate — '
                    'this is expected behavior.')
                diagnosis['pmkid_analysis'] = {
                    'auth_method_used': 'Open System (auth_alg=0)',
                    'expected_for_wpa3': 'SAE (auth_alg=3)',
                    'pmksa_cache_hit': False,
                    'likely_cause': 'Stale PMKSA cache — AP does not have matching PMK entry',
                    'mismatch_detail': (
                        'Client sent Open Auth + Association Request with SAE AKM and cached PMKID. '
                        'This is valid for PMKSA-cached reconnection (IEEE 802.11-2020 §12.7.2) '
                        'but requires the AP to still hold the PMK. When AP rejects with status=53, '
                        'the client must fall back to full SAE authentication.'),
                }
            elif used_sae:
                evidence.append(
                    'Client used SAE authentication before this Association Request')
                evidence.append(
                    'SAE completed but PMKID derived from it did not match AP expectation')
                evidence.append(
                    'Possible firmware bug or PMKID derivation mismatch between client/AP')
                validated = ('Invalid PMKID after SAE — PMKID derivation mismatch despite '
                             'successful SAE exchange (firmware issue)')
                diagnosis['recommended_action'] = (
                    'Update AP and client firmware. '
                    'Disable PMKID inclusion in Association Request if possible. '
                    'Report as a potential interop bug.')
            else:
                evidence.append(
                    'Authentication method could not be determined from captured frames')
                validated = 'Invalid PMKID — AP rejected cached PMKID in Association Request'
                diagnosis['recommended_action'] = (
                    'Clear PMKSA cache on client and retry. '
                    'Perform full authentication (SAE for WPA3, 4-way handshake for WPA2).')

            # Check if a subsequent successful attempt exists in later sessions
            # (this info will be populated in the caller via connection_flows)

        # ── Status Code 37: RSN IE capability mismatch ───────────────────────
        elif status_code == 37:
            evidence.append('AP rejected association due to incompatible RSN IE capabilities')
            if used_sae:
                evidence.append(
                    'SAE authentication was used — RSN mismatch is likely in cipher/MFP settings')
                validated = 'RSN IE mismatch — cipher suite or MFP requirement incompatibility'
            else:
                validated = 'RSN IE capability mismatch between client and AP'
            diagnosis['recommended_action'] = (
                'Verify cipher suite alignment (CCMP/GCMP), MFP (802.11w) settings, '
                'and AKM type match on both AP and client. Update firmware.')

        # ── Status Code 17: AP at capacity ───────────────────────────────────
        elif status_code == 17:
            evidence.append('AP has reached maximum STA limit')
            validated = 'AP at capacity — cannot accept additional stations'
            diagnosis['recommended_action'] = (
                'Increase per-radio STA limit, add another AP, or enable load-balancing/band-steering.')

        # ── Status Code 12: Association denied (policy) ──────────────────────
        elif status_code == 12:
            evidence.append('AP denied association due to local policy or capacity')
            validated = 'Association denied by AP policy (MAC ACL, load limit, or admission control)'
            diagnosis['recommended_action'] = (
                'Check MAC ACL whitelist on AP, BSS admission control settings, '
                'and per-BSS client limits.')

        # ── Generic fallback ─────────────────────────────────────────────────
        else:
            evidence.append(f'Association rejected with status code {status_code}')
            if used_open_auth:
                evidence.append('Open System authentication was used before association')
            if used_sae:
                evidence.append('SAE authentication was completed before association')
            diagnosis['recommended_action'] = (
                f'Refer to IEEE 802.11 status code {status_code}. '
                'Collect AP syslog and verify security/capability configuration match.')

        # Check for retry pattern (did client retry and succeed?)
        assoc_events = [e for e in events if 'Association' in e.get('step', '')]
        success_after = any(e.get('status', 1) == 0 and 'Response' in e.get('step', '')
                           for e in assoc_events)
        if success_after:
            evidence.append('Client successfully associated in a later attempt within this session')
            diagnosis['retry_succeeded'] = True

        diagnosis['validated_reason'] = validated
        diagnosis['evidence'] = evidence
        return diagnosis

    def _detect_beacon_losses(self, df: pd.DataFrame) -> Dict:
        """Detect excessive beacon losses (large timestamp gaps in per-BSSID beacon stream)."""
        result = {"detected": False, "severity": "info"}
        beacons = df[df['type_subtype'] == '0x0008'].copy()

        if beacons.empty or 'timestamp' not in beacons.columns or 'bssid' not in beacons.columns:
            return result

        beacon_losses: Dict[str, Any] = {}
        # 802.11 std beacon interval = 100 TU = 102.4 ms; gap > 5× = ~512 ms indicates loss
        threshold = self.wlan_config.get('beacon_loss_gap_sec', 0.512)

        for bssid, grp in beacons.groupby('bssid'):
            if bssid is None:
                continue
            times = grp['timestamp'].sort_values().values
            if len(times) < 3:
                continue
            intervals = np.diff(times)
            large_gaps = intervals[intervals > threshold]
            if len(large_gaps) > 0:
                beacon_losses[bssid] = {
                    'loss_events': int(len(large_gaps)),
                    'max_gap_sec': float(round(float(large_gaps.max()), 3)),
                    'avg_gap_sec': float(round(float(large_gaps.mean()), 3)),
                    'total_beacons': int(len(times)),
                }

        if beacon_losses:
            total_events = sum(v['loss_events'] for v in beacon_losses.values())
            max_gap = max(v['max_gap_sec'] for v in beacon_losses.values())
            severity = 'high' if total_events > 100 or max_gap > 10 else 'medium'
            result['detected'] = True
            result['severity'] = severity
            result['affected_bssid_count'] = len(beacon_losses)
            result['total_loss_events'] = total_events
            result['max_gap_sec'] = float(round(max_gap, 3))
            result['message'] = (
                f"Beacon loss on {len(beacon_losses)} BSSID(s): "
                f"{total_events} gap event(s), largest gap {max_gap:.2f}s"
            )
            top = sorted(beacon_losses.items(), key=lambda x: x[1]['loss_events'], reverse=True)[:10]
            result['bssid_detail'] = {k: v for k, v in top}

        return result

    def _detect_probe_failures(self, df: pd.DataFrame) -> Dict:
        """Detect probe request / response imbalance indicating failed network scans."""
        result = {"detected": False, "severity": "info"}
        probe_req = df[df['type_subtype'] == '0x0004']
        probe_resp = df[df['type_subtype'] == '0x0005']
        total_reqs = len(probe_req)
        total_resp = len(probe_resp)

        if total_reqs < 5:
            return result

        response_rate = total_resp / total_reqs if total_reqs > 0 else 1.0
        if response_rate < 0.5:
            severity = 'high' if response_rate < 0.1 else 'medium'
            result['detected'] = True
            result['severity'] = severity
            result['probe_requests'] = total_reqs
            result['probe_responses'] = total_resp
            result['response_rate_pct'] = float(round(response_rate * 100, 1))
            result['message'] = (
                f"Low probe response rate: {total_resp}/{total_reqs} answered "
                f"({response_rate * 100:.0f}%)"
            )
            if 'sa' in probe_req.columns:
                result['top_scanning_devices'] = probe_req['sa'].value_counts().head(10).to_dict()

        return result

    def _detect_weak_signal(self, df: pd.DataFrame) -> Dict:
        """Detect clients with weak signal strength (connectivity issues)."""
        result = {"detected": False, "severity": "info"}

        if 'signal_dbm' not in df.columns:
            return result

        sig = df['signal_dbm'].dropna()
        sig = sig[sig != 0]
        if sig.empty:
            return result

        weak_threshold = self.wlan_config.get('weak_signal_dbm', -75)
        weak_frames = df[df['signal_dbm'] < weak_threshold]

        if len(weak_frames) > 0:
            weak_ratio = len(weak_frames) / len(df)
            if weak_ratio > 0.2:
                result['detected'] = True
                result['severity'] = 'medium'
                result['weak_frame_count'] = len(weak_frames)
                result['weak_ratio'] = float(round(weak_ratio, 3))
                result['message'] = (
                    f"Weak signal coverage: {weak_ratio*100:.1f}% of frames below "
                    f"{weak_threshold} dBm ({len(weak_frames):,} frames)"
                )
                # Which BSSIDs have weak signals
                if 'bssid' in weak_frames.columns:
                    result['weak_bssids'] = (
                        weak_frames['bssid'].value_counts().head(5).to_dict()
                    )

        return result

    def _detect_unprotected_traffic(self, df: pd.DataFrame) -> Dict:
        """Detect unencrypted data frames, with context-aware severity for WPA2/WPA3 captures.
        Null (0x0024) and QoS-Null (0x002c) frames are always legitimately unprotected
        per IEEE 802.11 and are excluded from the unprotected count."""
        result = {"detected": False, "severity": "info"}

        df_cat = df.copy()
        df_cat['frame_category'] = df_cat['type_subtype'].apply(self._categorize_frame)
        # Null and QoS-Null frames carry no data and are legitimately unencrypted
        NULL_SUBTYPES = {'0x0024', '0x002c'}
        data_frames = df_cat[
            (df_cat['frame_category'] == 'Data') &
            (~df_cat['type_subtype'].isin(NULL_SUBTYPES))
        ]

        if data_frames.empty:
            return result

        if 'protected' not in data_frames.columns:
            return result

        unprotected = data_frames[data_frames['protected'] == 0]
        null_frames = df_cat[df_cat['type_subtype'].isin(NULL_SUBTYPES)]

        if len(unprotected) == 0:
            return result

        ratio = len(unprotected) / len(data_frames)
        if ratio <= 0.1:
            return result

        # Detect whether any AP in this capture advertises WPA2/WPA3 via RSN IE
        wpa2_wpa3_in_use = False
        security_note = ''
        if 'rsn_version' in df.columns:
            rsn_frames = df[df['rsn_version'] > 0]
            if not rsn_frames.empty:
                wpa2_wpa3_in_use = True
                security_note = (
                    'RSN (WPA2/WPA3) advertised in this capture. '
                    'Unprotected frames during association/handshake phase are '
                    'expected — the WPA key exchange (EAPOL) itself is unencrypted. '
                    'Data frames will only be encrypted after a successful 4-way handshake.'
                )

        result['detected'] = True
        result['unprotected_count'] = len(unprotected)
        result['total_data_frames'] = len(data_frames)
        result['null_frames_excluded'] = int(len(null_frames))
        result['unprotected_ratio'] = float(round(ratio, 3))

        if wpa2_wpa3_in_use:
            result['severity'] = 'info'
            result['message'] = (
                f"{len(unprotected):,} of {len(data_frames):,} non-null data frames "
                f"({ratio*100:.1f}%) have no protected bit — expected in a "
                "WPA2/WPA3 network (pre-authentication / EAPOL frames)"
            )
            result['security_context'] = security_note
        else:
            result['severity'] = 'high'
            result['message'] = (
                f"Unprotected data traffic: {len(unprotected):,} of "
                f"{len(data_frames):,} data frames ({ratio*100:.1f}%) are unencrypted "
                "and no WPA2/WPA3 RSN IE was detected — network may be open/WEP"
            )

        return result

    def _detect_ip_connectivity_failure(self, df: pd.DataFrame) -> Dict:
        """Detect post-handshake IP connectivity failure:
        EAPOL 4-way handshake completed (Msg4 seen) but no unicast protected data
        received from AP within the session — indicates DHCP failure, AP isolation,
        or uplink loss at the AP after successful 802.11 + WPA2 association."""
        result = {"detected": False, "severity": "info"}

        if 'eapol_msg_nr' not in df.columns:
            return result

        # Find sessions where Msg4 was seen
        msg4_frames = df[df['eapol_msg_nr'] == 4]
        if msg4_frames.empty:
            return result

        DATA_SUBTYPES = {'0x0020', '0x0021', '0x0022', '0x0028'}
        # QoS-Null / Null do NOT count as real data exchange
        sessions_with_issue: List[Dict] = []

        for _, msg4 in msg4_frames.iterrows():
            client_mac = msg4.get('sa')
            ap_bssid   = msg4.get('bssid') or msg4.get('da')
            msg4_ts    = float(msg4.get('timestamp', 0) or 0)
            msg4_fn    = int(msg4.get('frame_number', 0) or 0)

            if not (client_mac and ap_bssid):
                continue

            # Frames after EAPOL Msg4, in the same BSS, involving our client
            post_df = df[
                (df['timestamp'] > msg4_ts) &
                (df['bssid'] == ap_bssid) &
                (df['type_subtype'].isin(DATA_SUBTYPES)) &
                (df['protected'] == 1)
            ]

            # Separate: data FROM client vs data TO client FROM AP
            from_client = post_df[post_df['sa'] == client_mac]
            to_client   = post_df[post_df['da'] == client_mac]

            # Count QoS-Null polls — client repeatedly waking up with no reply
            null_polls = df[
                (df['timestamp'] > msg4_ts) &
                (df['bssid'] == ap_bssid) &
                (df['sa'] == client_mac) &
                (df['type_subtype'] == '0x002c')
            ]

            # Failure criterion:
            # (a) AP sent no unicast protected data to client — nothing coming back, OR
            # (b) Client only sends non-unicast (multicast 33:33:*/01:* + broadcast ff:ff:*) —
            #     IPv6 DAD/RS/mDNS + ARP broadcasts = no IP address assigned, no real traffic.
            unicast_from_client = from_client[
                ~from_client['da'].fillna('').str.startswith(('33:33:', '01:', 'ff:ff:'))
            ] if len(from_client) > 0 else from_client

            # multicast_only: client sent frames but NONE were unicast
            # (covers 33:33:*, 01:*, ff:ff:ff:ff:ff:ff — all non-unicast)
            multicast_only = len(from_client) > 0 and len(unicast_from_client) == 0

            ap_unicast_significant = len(to_client) > 5 and not multicast_only
            no_ip_connectivity = multicast_only or not ap_unicast_significant

            if no_ip_connectivity:
                observations: List[str] = []
                if len(from_client) > 0:
                    # Count breakdown
                    n_ipv6_mc = from_client['da'].fillna('').str.startswith('33:33:').sum()
                    n_ipv4_mc = from_client['da'].fillna('').str.startswith('01:').sum()
                    n_bcast   = (from_client['da'].fillna('') == 'ff:ff:ff:ff:ff:ff').sum()
                    if multicast_only:
                        observations.append(
                            f'Client sent {len(from_client)} protected data frame(s) — '
                            f'ALL non-unicast: {n_ipv6_mc} IPv6 multicast (33:33:*/DAD/RS/mDNS), '
                            f'{n_ipv4_mc} IPv4 multicast (01:*/mDNS/SSDP), {n_bcast} broadcast (ff:ff:*/ARP/DHCP). '
                            'Zero unicast data sent by client = DHCP/IP assignment failed'
                        )
                    else:
                        obs_u = len(unicast_from_client)
                        observations.append(
                            f'Client sent {len(from_client)} protected frame(s) '
                            f'({obs_u} unicast, {len(from_client)-obs_u} multicast)'
                        )
                observations.append(
                    f'AP sent {len(to_client)} protected unicast frame(s) to client after handshake '
                    f'{"(minimal — no sustained data exchange)" if 0 < len(to_client) <= 5 else ""}'
                    if len(to_client) > 0 else
                    'AP sent 0 protected unicast data frames to client after handshake'
                )
                if len(null_polls) > 5:
                    observations.append(
                        f'{len(null_polls)} QoS-Null power-save poll(s) from client — '
                        'AP repeatedly has no downlink data queued for client'
                    )
                if multicast_only:
                    observations.append(
                        'Non-unicast-only traffic pattern (IPv6 DAD/RS/mDNS + ARP/DHCP broadcasts) '
                        'confirms client never received an IP address — '
                        'typical L3 connectivity failure after successful 802.11+WPA2 auth'
                    )
                sessions_with_issue.append({
                    'client': client_mac,
                    'ap_bssid': ap_bssid,
                    'eapol_msg4_frame': msg4_fn,
                    'from_client_frames': int(len(from_client)),
                    'to_client_frames': int(len(to_client)),
                    'null_polls': int(len(null_polls)),
                    'multicast_only_client': multicast_only,
                    'observations': observations,
                })

        if sessions_with_issue:
            result['detected'] = True
            result['severity'] = 'high'
            result['affected_sessions'] = len(sessions_with_issue)
            result['sessions'] = sessions_with_issue
            top = sessions_with_issue[0]
            result['message'] = (
                f'{len(sessions_with_issue)} session(s) where WPA2 handshake succeeded '
                f'but AP sent no unicast data — likely DHCP/IP connectivity failure '
                f'(client: {top["client"]}, AP: {top["ap_bssid"]})'
            )
            result['root_cause_candidates'] = [
                'DHCP server not responding or unreachable from AP',
                'AP has no uplink / internet gateway is down',
                'Client IP address pool exhausted on AP',
                'VLAN or firewall policy blocking client after auth',
                'AP in isolated BSS mode (no L3 routing)',
            ]
            result['recommended_actions'] = [
                'Check DHCP server status and available lease pool on AP',
                'Verify AP uplink/WAN port and gateway connectivity',
                'Check for VLAN assignment or firewall rules applied post-auth',
                'Test by connecting another device to the same SSID',
                'Review AP system logs for DHCP relay or IP assignment errors',
            ]

        return result



    def _detect_high_retry(self, df: pd.DataFrame) -> Dict:
        """Detect high retry rate in data frames, indicating interference or congestion.

        Intentionally excludes management frames (probe requests/responses, beacons)
        and control frames — their retries are less indicative of actual connectivity
        problems. Management retries (e.g., AP re-sending a probe response) are normal
        and should not be attributed as a network health issue.
        """
        result = {"detected": False, "severity": "info"}

        if 'retry' not in df.columns or 'type_subtype' not in df.columns:
            return result

        DATA_SUBTYPES = {'0x0020', '0x0021', '0x0022', '0x0028', '0x002c', '0x002d'}
        data_df = df[df['type_subtype'].isin(DATA_SUBTYPES)]

        if data_df.empty:
            # No data frames — capture is management/control only, retry rate not meaningful
            return result

        retry_rate = data_df['retry'].mean()
        threshold = self.wlan_config.get('max_retry_rate', 0.15)

        if retry_rate > threshold:
            result['detected'] = True
            result['severity'] = 'medium'
            result['retry_rate'] = float(round(retry_rate, 4))
            result['retry_count'] = int(data_df['retry'].sum())
            result['total_data_frames'] = int(len(data_df))
            result['message'] = (
                f"High retry rate: {retry_rate*100:.1f}% of data frames are retries "
                f"(threshold: {threshold*100:.0f}%)"
            )

        return result

    def _detect_wpa3_sae_failures(self, df: pd.DataFrame) -> Dict:
        """Detect WPA3-SAE (Simultaneous Authentication of Equals) connection failures.

        WPA3-Personal uses SAE (the Dragonfly handshake) instead of PSK for the
        authentication phase.  The SAE exchange sits entirely within 802.11
        Authentication frames (subtype 0x000b) before Association, using algorithm 3.

        SAE flow (IEEE 802.11-2020 §12.4):
          Client → AP : Auth frame, auth_alg=SAE(3), auth_seq=1  [SAE Commit]
          AP → Client : Auth frame, auth_alg=SAE(3), auth_seq=1  [SAE Commit]
          Client → AP : Auth frame, auth_alg=SAE(3), auth_seq=2  [SAE Confirm]
          AP → Client : Auth frame, auth_alg=SAE(3), auth_seq=2, status=0  [SAE Confirm]
          → If all four above succeed, proceed to normal Association + 4-way EAPOL PTK.

        Detection covers:
          A. SAE Commit rejected by AP (status ≠ 0 on AP's seq=1 response)
          B. SAE Confirm rejected by AP (status ≠ 0 on AP's seq=2 response)
          C. Anti-clogging token required (status=77) — rate-limiting, not a credential error
          D. Group not supported (status=78)
          E. Unknown password identifier (status=76)
          F. SAE Commit→Commit loop (no Confirm seen) — strong wrong-password indicator
          G. Post-SAE 4-way handshake failure (SAE succeeded but EAPOL PTK failed)
          H. Transition mode downgrade (AP advertises both WPA2-PSK and WPA3-SAE and
             client used WPA2 auth_alg=0 despite SAE being available)
        """
        result: Dict = {'detected': False, 'severity': 'info'}

        auth_df = df[df['type_subtype'] == '0x000b'].copy()
        if auth_df.empty:
            return result

        # Resolve auth_alg — may be 0=Open, 1=SharedKey, 3=SAE
        has_auth_alg = 'auth_alg' in df.columns

        # Detect any SAE auth frames (either side)
        if has_auth_alg:
            sae_auth_df = auth_df[auth_df['auth_alg'] == 3]
        else:
            # Fallback: no auth_alg field — check status codes 72/73/74/76/77/78
            sae_status_codes = {72, 73, 74, 76, 77, 78}
            sae_auth_df = auth_df[
                auth_df['status_code'].isin(sae_status_codes) |
                (auth_df['auth_seq'] == 2)  # SAE Confirm sequence
            ]

        # Also check AKM type from Beacon/Probe-Response RSN IE (8=SAE, 18=OWE)
        sae_akm_present = False
        owe_akm_present = False
        if 'akm_type' in df.columns:
            akm_vals = df['akm_type'].dropna().unique()
            sae_akm_present = 8.0 in akm_vals or 9.0 in akm_vals   # 8=SAE, 9=FT-SAE
            owe_akm_present = 18.0 in akm_vals                       # 18=OWE

        sae_sessions:  List[Dict] = []
        issues:        List[str]  = []
        failure_counts: Dict[str, int] = {}

        def _bump(key: str) -> None:
            failure_counts[key] = failure_counts.get(key, 0) + 1

        # --- Walk SAE auth frames per BSSID+client pair ---
        # Group by (bssid, client_mac) to handle multiple pairs in one capture
        all_auth_for_analysis = sae_auth_df if not sae_auth_df.empty else auth_df

        # Collect all BSSID+client pairs that had SAE auth frames
        for _, row in all_auth_for_analysis.iterrows():
            bssid  = row.get('bssid') or ''
            sa     = row.get('sa')    or ''
            da     = row.get('da')    or ''
            status = int(row.get('status_code', 0) or 0)
            seq    = int(row.get('auth_seq', 0) or 0)
            alg    = int(row.get('auth_alg', 3) or 3) if has_auth_alg else 3
            fn     = int(row.get('frame_number', 0) or 0)
            ts     = float(row.get('timestamp', 0) or 0)
            signal = int(row.get('signal_dbm', 0) or 0) or None

            if alg != 3 and not sae_auth_df.empty:
                continue  # Other auth algorithms handled by _detect_connection_failures

            # AP → client SAE Commit response (seq=1) with failure
            if seq == 1 and status != 0 and sa == bssid:
                _bump('SAE Commit rejected by AP')
                diag = {
                    'frame': fn, 'timestamp': ts, 'signal_dbm': signal,
                    'client': da, 'ap_bssid': bssid,
                    'failure_phase': 'SAE Commit (seq=1)',
                    'status_code': status,
                    'status_text': STATUS_CODES.get(status, f'Status {status}'),
                    'root_cause':  _sae_status_root_cause(status),
                    'remediation': _sae_remediation(status),
                }
                sae_sessions.append(diag)

            # AP → client SAE Confirm response (seq=2) with failure
            elif seq == 2 and status != 0 and sa == bssid:
                _bump('SAE Confirm rejected by AP')
                diag = {
                    'frame': fn, 'timestamp': ts, 'signal_dbm': signal,
                    'client': da, 'ap_bssid': bssid,
                    'failure_phase': 'SAE Confirm (seq=2)',
                    'status_code': status,
                    'status_text': STATUS_CODES.get(status, f'Status {status}'),
                    'root_cause':  _sae_status_root_cause(status),
                    'remediation': _sae_remediation(status),
                }
                sae_sessions.append(diag)

        # --- SAE Commit→Commit loop (no Confirm seen for a BSSID pair) ---
        # Group by BSSID to find loops
        if not sae_auth_df.empty:
            bssid_groups = sae_auth_df.groupby('bssid')
        else:
            bssid_groups = auth_df[auth_df['auth_alg'] == 3].groupby('bssid') \
                if has_auth_alg else pd.DataFrame().groupby([])

        for bssid_val, bss_df in bssid_groups:
            commits  = bss_df[bss_df['auth_seq'] == 1]
            confirms = bss_df[bss_df['auth_seq'] == 2]
            if len(commits) >= 2 and len(confirms) == 0:
                _bump('SAE Commit loop — no Confirm (wrong password)')
                sae_sessions.append({
                    'client': commits[commits['sa'] != bssid_val]['sa'].iloc[0]
                              if len(commits[commits['sa'] != bssid_val]) else None,
                    'ap_bssid': str(bssid_val),
                    'failure_phase': 'SAE Commit loop — Commit repeated but Confirm never seen',
                    'commit_count': int(len(commits)),
                    'confirm_count': 0,
                    'root_cause': 'Wrong WPA3 passphrase',
                    'remediation': (
                        'AP kept resending SAE Commit but never sent SAE Confirm — '
                        'this pattern means the AP could not validate the client\'s SAE Commit '
                        '(wrong passphrase). '
                        'Action: re-enter the correct WPA3 passphrase on the client. '
                        'Ensure passphrase is UTF-8 encoded (no non-ASCII characters unless both '
                        'sides handle RFC 8265 PRECIS normalization).'
                    ),
                    'note': (
                        f'SAE Commit seen {len(commits)}× (from both sides) but '
                        'SAE Confirm never exchanged — unambiguous wrong-password indicator for WPA3.'
                    ),
                })

        # --- Anti-clogging token pattern ---
        anti_clog_df = auth_df[auth_df['status_code'] == 77]
        if not anti_clog_df.empty:
            _bump('SAE Anti-Clogging Token Required')
            issues.append(
                f'{len(anti_clog_df)} SAE Anti-Clogging Token Required (status=77) response(s): '
                'AP is rate-limiting SAE requests due to high load or possible DoS attack. '
                'Client should restart SAE with the provided token. '
                'If persistent: check for SAE flooding from rogue clients targeting this AP.'
            )

        # --- Post-SAE 4-way handshake failure ---
        # SAE reached Confirm (seq=2 status=0) but EAPOL Msg3 never arrived
        if 'eapol_msg_nr' in df.columns:
            eapol_df = df[df['eapol_msg_nr'] > 0]
            # Only match SAE Confirm (auth_alg=3, seq=2, status=0) — not WPA2 Open auth
            sae_confirm_filter = (auth_df['auth_seq'] == 2) & (auth_df['status_code'] == 0)
            if has_auth_alg:
                sae_confirm_filter = sae_confirm_filter & (auth_df['auth_alg'] == 3)
            sae_confirms_ok = auth_df[sae_confirm_filter]
            if not sae_confirms_ok.empty and not eapol_df.empty:
                msg1 = eapol_df[eapol_df['eapol_msg_nr'] == 1]
                msg3 = eapol_df[eapol_df['eapol_msg_nr'] == 3]
                msg4 = eapol_df[eapol_df['eapol_msg_nr'] == 4]
                if len(msg1) > 0 and len(msg3) == 0:
                    _bump('Post-SAE 4-way handshake stall')
                    sae_sessions.append({
                        'failure_phase': 'Post-SAE 4-way EAPOL PTK handshake stalled',
                        'root_cause': 'SAE succeeded but EAPOL Msg1/Msg2 stall — PTK derivation failed',
                        'eapol_msg1_count': int(len(msg1)),
                        'eapol_msg3_count': 0,
                        'remediation': (
                            'SAE (WPA3 auth) completed successfully but the subsequent 4-way '
                            'EAPOL/PTK handshake did not progress to Msg3. '
                            'This is unusual for WPA3 (SAE guarantees the PMK from password, '
                            'so Msg2 MIC should be valid). Possible causes: '
                            '(1) PMKSA cache inconsistency — disable PMKID caching and retry. '
                            '(2) AP firmware bug in transitioning from SAE to EAPOL. '
                            '(3) RF packet loss dropped Msg2 — check signal quality. '
                            'Action: update AP/client firmware; try disabling PMKSA cache on client.'
                        ),
                    })
                elif len(msg4) > 0:
                    # Full handshake succeeded
                    issues.append(
                        'WPA3-SAE + 4-way EAPOL handshake completed successfully '
                        f'(Msg1–Msg4 all seen, {len(sae_confirms_ok)} SAE Confirm(s) with status=0).'
                    )

        # --- WPA2/WPA3 transition mode: client used Open/PSK while SAE available ---
        if sae_akm_present and has_auth_alg:
            wpa2_auths = auth_df[auth_df['auth_alg'] == 0]  # Open auth (pre-WPA2 or PSK)
            if not wpa2_auths.empty and not sae_auth_df.empty:
                _bump('WPA3 transition mode — some clients using WPA2')

                # Check if any PMKID failures (status 53) correlate with the Open auth attempts
                pmkid_failures = df[
                    (df['type_subtype'].isin({'0x0001', '0x0003'})) &
                    (df['status_code'] == 53)
                ]
                pmkid_note = ''
                if not pmkid_failures.empty:
                    pmkid_note = (
                        f' Additionally, {len(pmkid_failures)} association(s) were rejected '
                        'with Status Code 53 (Invalid PMKID). This is directly caused by '
                        'the transition-mode behavior: the client used Open auth (auth_alg=0) '
                        'and included a stale SAE-derived PMKID in the Association Request, '
                        'attempting PMKSA-cached fast reconnection. The AP rejected it because '
                        'the cached PMK entry had expired. The client should have performed a '
                        'full SAE exchange (auth_alg=3) instead of relying on the stale cache.'
                    )

                issues.append(
                    f'{len(wpa2_auths)} auth frame(s) used Open/WPA2 auth (auth_alg=0) '
                    'while SAE (WPA3) is also advertised in the BSS RSN IE. '
                    'This indicates the BSS is running in WPA3 Transition Mode (mixed WPA2+WPA3). '
                    'Ensure WPA3-only clients connect with SAE; legacy WPA2 clients will use PSK. '
                    'To enforce WPA3-only: disable WPA2-PSK on the AP once all clients support SAE.'
                    + pmkid_note
                )

        # --- OWE (Opportunistic Wireless Encryption) detection ---
        if owe_akm_present:
            owe_assoc_resp = df[
                (df['type_subtype'].isin({'0x0001', '0x0003'})) &
                (df['status_code'] > 0)
            ]
            if not owe_assoc_resp.empty:
                _bump('OWE association failure')
                issues.append(
                    f'{len(owe_assoc_resp)} OWE association response(s) failed (status≠0). '
                    'OWE (Enhanced Open/AKM=18) provides encryption on open networks. '
                    'Possible causes: OWE DH group mismatch, client does not support OWE. '
                    'Recovery: check client OS supports OWE (Win 11, Android 10+, iOS 15+); '
                    'update AP/client firmware; verify AP is not in OWE transition mode issues.'
                )

        if not sae_sessions and not issues and not failure_counts:
            # Still note if SAE AKM was advertised (positive detection of WPA3 network)
            if sae_akm_present:
                result['wpa3_network_detected'] = True
                result['sae_akm_advertised'] = True
                result['owe_advertised'] = owe_akm_present
            return result

        result['detected']         = True
        result['sae_sessions']     = sae_sessions
        result['issues']           = issues
        result['failure_counts']   = failure_counts
        result['wpa3_network_detected'] = True
        result['sae_akm_advertised']    = sae_akm_present
        result['owe_advertised']        = owe_akm_present

        total_failures = sum(failure_counts.values())
        if total_failures == 0 and issues:
            # Only informational issues (e.g., transition mode notes)
            result['severity'] = 'info'
        elif 'SAE Commit loop — no Confirm (wrong password)' in failure_counts or \
             'SAE Confirm rejected by AP' in failure_counts:
            result['severity'] = 'high'
        elif 'SAE Anti-Clogging Token Required' in failure_counts or \
             'Post-SAE 4-way handshake stall' in failure_counts:
            result['severity'] = 'high'
        else:
            result['severity'] = 'high'

        top = sorted(failure_counts.items(), key=lambda x: x[1], reverse=True)[:2]
        result['message'] = (
            f'WPA3-SAE analysis: {total_failures} failure event(s) — '
            + ', '.join(f'{v}× {k}' for k, v in top)
        ) if top else (
            f'WPA3-SAE: {len(issues)} advisory notice(s) — {issues[0][:80]}...'
            if issues else 'WPA3-SAE session detected'
        )

        return result

    def _detect_scan_failures(self, df: pd.DataFrame) -> Dict:
        """Detect devices that probe/scan but never attempt to associate.

        Fires when the filtered view contains probe requests but no auth/assoc
        frames — indicating the client is in scanning mode only (e.g., power-save
        wake-to-scan cycle, no target SSID found, or AP selection deferred).
        Threshold is 1 device minimum for MAC-filtered captures.
        """
        result = {"detected": False, "severity": "info"}

        if 'sa' not in df.columns:
            return result

        probe_req  = df[df['type_subtype'] == '0x0004']
        probe_resp = df[df['type_subtype'] == '0x0005']
        assoc_req  = df[df['type_subtype'] == '0x0000']
        auth_req   = df[df['type_subtype'] == '0x000b']

        if probe_req.empty:
            return result

        probe_sources = set(probe_req['sa'].dropna().unique())
        assoc_sources = set(assoc_req['sa'].dropna().unique()) | set(auth_req['sa'].dropna().unique())
        scan_only = probe_sources - assoc_sources
        # Threshold=1 so a MAC-filtered single-device capture fires correctly
        threshold = self.wlan_config.get('scan_failure_device_threshold', 1)

        if len(scan_only) >= threshold:
            result['detected'] = True
            result['severity'] = 'medium'
            result['scan_only_devices'] = len(scan_only)
            result['total_probing_devices'] = len(probe_sources)
            result['message'] = (
                f"Scan-only behaviour: {len(scan_only)}/{len(probe_sources)} device(s) "
                "sent Probe Requests but never attempted to authenticate or associate"
            )

            details: List[Dict] = []
            for client in list(scan_only)[:10]:
                client_probes = probe_req[probe_req['sa'] == client]
                # Power-save bit on probe requests — scanning while in PS mode
                power_save_scan = False
                if 'pwrmgt' in df.columns:
                    ps_vals = pd.to_numeric(client_probes['pwrmgt'], errors='coerce').fillna(0)
                    power_save_scan = bool(ps_vals.sum() > 0)

                # APs that responded to this client (probe responses from APs)
                responses_to_client = probe_resp[probe_resp['da'] == client]
                responding_aps: List[Dict] = []
                for ap_bssid, grp in responses_to_client.groupby('sa'):
                    # Decode SSID hex if needed
                    raw_ssid = grp['ssid'].dropna().iloc[0] if ('ssid' in grp.columns and not grp['ssid'].dropna().empty) else ''
                    try:
                        decoded = bytes.fromhex(raw_ssid).decode('utf-8', errors='replace') if raw_ssid and all(c in '0123456789abcdefABCDEF' for c in raw_ssid) and len(raw_ssid) % 2 == 0 else raw_ssid
                    except Exception:
                        decoded = raw_ssid
                    responding_aps.append({'bssid': str(ap_bssid), 'ssid': decoded, 'responses': int(len(grp))})

                details.append({
                    'client': client,
                    'probe_requests': int(len(client_probes)),
                    'power_save_scanning': power_save_scan,
                    'responding_aps': responding_aps,
                    'interpretation': (
                        'Client woke from power-save to scan then returned to sleep without connecting'
                        if power_save_scan else
                        'Client scanned for networks but did not attempt to connect'
                    ),
                })

            result['scan_only_details'] = details

        return result

    # ------------------------------------------------------------------
    #  Action Frame Analysis
    # ------------------------------------------------------------------

    def _detect_action_frame_issues(self, df: pd.DataFrame) -> Dict:
        """Analyze 802.11 Action frames (type 0x000d / 0x000e) for WiFi operational issues.

        Action frames carry management negotiation for:
        - Spectrum Management (cat=0): Channel Switch Announcements, TPC
        - QoS (cat=1): TSPEC admission control
        - Block Ack (cat=3): ADDBA/DELBA aggregation management
        - Radio Measurement (cat=5): 802.11k Neighbor Reports
        - Fast BSS Transition (cat=6): 802.11r fast roaming
        - HT (cat=7): SM Power Save, channel width changes
        - SA Query (cat=8): 802.11w MFP validation
        - WNM (cat=10): 802.11v BSS Transition Management
        - VHT (cat=21): Operating Mode Notification
        """
        result: Dict[str, Any] = {'detected': False, 'severity': 'info'}

        ACTION_SUBTYPES = {'0x000d', '0x000e'}
        action_df = df[df['type_subtype'].isin(ACTION_SUBTYPES)]

        if action_df.empty or 'category_code' not in df.columns:
            return result

        CATEGORY_NAMES = {
            0: 'Spectrum Management', 1: 'QoS', 2: 'DLS (Direct-Link Setup)',
            3: 'Block Ack', 4: 'Public', 5: 'Radio Measurement (802.11k)',
            6: 'Fast BSS Transition (802.11r)', 7: 'HT',
            8: 'SA Query (802.11w)', 9: 'Protected Dual of Public Action',
            10: 'WNM (802.11v)', 11: 'Unprotected WNM',
            12: 'Mesh', 13: 'Multihop', 14: 'Self-protected', 15: 'DMG',
            21: 'VHT', 22: 'S1G (HaLow)',
            126: 'Vendor-specific Protected', 127: 'Vendor-specific',
        }

        has_action_code = 'action_code' in df.columns
        issues: List[Dict] = []
        summary: Dict[str, Any] = {}

        # Category distribution
        cat_counts = action_df['category_code'].value_counts().to_dict()
        category_distribution = {
            CATEGORY_NAMES.get(int(k), f'Category {int(k)}'): int(v)
            for k, v in cat_counts.items()
        }

        # --- Spectrum Management (cat=0): CSA, TPC ---
        spectrum_df = action_df[action_df['category_code'] == 0]
        if not spectrum_df.empty:
            summary['spectrum_management_frames'] = len(spectrum_df)
            if has_action_code:
                csa_df = spectrum_df[spectrum_df['action_code'] == 4]
                if not csa_df.empty:
                    csa_bssids = csa_df['bssid'].dropna().unique().tolist()
                    issues.append({
                        'category': 'Spectrum Management',
                        'issue': 'Channel Switch Announcement (CSA)',
                        'severity': 'medium',
                        'count': len(csa_df),
                        'affected_bssids': csa_bssids[:10],
                        'description': (
                            f'{len(csa_df)} CSA frame(s) from {len(csa_bssids)} AP(s). '
                            'APs are changing operating channel — likely due to radar detection (DFS), '
                            'interference avoidance, or manual reconfiguration. '
                            'Clients must follow the AP to the new channel or risk disconnection.'
                        ),
                        'impact': 'Brief connectivity interruption during channel switch; '
                                  'clients with poor CSA support may disconnect.',
                        'remediation': (
                            'If frequent: check for DFS radar events on 5 GHz channels; '
                            'consider using non-DFS channels (36-48). '
                            'Verify all clients support CSA (802.11h). '
                            'Check for co-channel interference triggering automatic channel changes.'
                        ),
                    })
                tpc_df = spectrum_df[spectrum_df['action_code'].isin([2, 3])]
                if not tpc_df.empty:
                    summary['tpc_frames'] = len(tpc_df)

        # --- Block Ack (cat=3): ADDBA/DELBA ---
        ba_action_df = action_df[action_df['category_code'] == 3]
        if not ba_action_df.empty:
            summary['block_ack_action_frames'] = len(ba_action_df)
            if has_action_code:
                addba_req = ba_action_df[ba_action_df['action_code'] == 0]
                addba_resp = ba_action_df[ba_action_df['action_code'] == 1]
                delba = ba_action_df[ba_action_df['action_code'] == 2]
                summary['addba_requests'] = len(addba_req)
                summary['addba_responses'] = len(addba_resp)
                summary['delba_frames'] = len(delba)

                if len(addba_req) > 0 and len(addba_resp) == 0:
                    issues.append({
                        'category': 'Block Ack',
                        'issue': 'ADDBA negotiation failure — no response',
                        'severity': 'medium',
                        'count': len(addba_req),
                        'description': (
                            f'{len(addba_req)} ADDBA Request(s) sent but no ADDBA Response received. '
                            'A-MPDU aggregation is not being established — '
                            'this severely limits throughput on 802.11n/ac/ax.'
                        ),
                        'impact': 'Without Block Ack, frames are sent individually '
                                  'instead of aggregated, losing 50-80% of potential throughput.',
                        'remediation': (
                            'Check if the peer device supports A-MPDU aggregation. '
                            'Update driver/firmware on both sides. '
                            'Verify Block Ack is not disabled in AP or client configuration.'
                        ),
                    })
                elif len(addba_req) > 0 and len(addba_resp) > 0:
                    unanswered = max(0, len(addba_req) - len(addba_resp))
                    if unanswered > len(addba_req) * 0.3:
                        issues.append({
                            'category': 'Block Ack',
                            'issue': 'Partial ADDBA negotiation failure',
                            'severity': 'low',
                            'count': unanswered,
                            'description': (
                                f'{unanswered} of {len(addba_req)} ADDBA Request(s) went unanswered '
                                f'({len(addba_resp)} responses received). '
                                'Some aggregation sessions are failing to establish.'
                            ),
                            'remediation': 'Check for intermittent RF issues; update firmware.',
                        })

                if len(delba) > 5:
                    delba_ratio = len(delba) / max(len(addba_req), 1)
                    if delba_ratio > 0.5 or len(delba) > 20:
                        issues.append({
                            'category': 'Block Ack',
                            'issue': 'Frequent Block Ack teardowns (DELBA)',
                            'severity': 'medium',
                            'count': len(delba),
                            'description': (
                                f'{len(delba)} DELBA frame(s) — Block Ack sessions are being torn down '
                                f'frequently. Ratio: {len(delba)} teardowns vs {len(addba_req)} setups.'
                            ),
                            'impact': 'Repeated aggregation teardown/rebuild cycles degrade throughput '
                                      'and add management overhead.',
                            'remediation': (
                                'Investigate cause: interference, incompatible A-MPDU sizes, or '
                                'driver bugs. Check BA buffer size compatibility between AP and client. '
                                'Reduce A-MPDU length limit if frames are being corrupted.'
                            ),
                        })

        # --- Radio Measurement / 802.11k (cat=5) ---
        rm_df = action_df[action_df['category_code'] == 5]
        if not rm_df.empty:
            summary['radio_measurement_frames'] = len(rm_df)
            if has_action_code:
                nr_req = rm_df[rm_df['action_code'] == 4]
                nr_resp = rm_df[rm_df['action_code'] == 5]
                if len(nr_req) > 0:
                    summary['neighbor_report_requests'] = len(nr_req)
                    summary['neighbor_report_responses'] = len(nr_resp)
                    unanswered_nr = max(0, len(nr_req) - len(nr_resp))
                    if unanswered_nr > len(nr_req) * 0.3:
                        issues.append({
                            'category': 'Radio Measurement (802.11k)',
                            'issue': 'Unanswered Neighbor Report requests',
                            'severity': 'low',
                            'count': unanswered_nr,
                            'description': (
                                f'{unanswered_nr} of {len(nr_req)} Neighbor Report Request(s) went '
                                'unanswered. Clients cannot discover roaming targets efficiently.'
                            ),
                            'impact': 'Slower roaming: client must perform active scanning instead '
                                      'of using AP-provided neighbor list.',
                            'remediation': (
                                'Enable 802.11k on the AP. Verify AP supports and advertises '
                                'Radio Measurement capabilities in its Extended Capabilities IE.'
                            ),
                        })

        # --- Fast BSS Transition / 802.11r (cat=6) ---
        ft_df = action_df[action_df['category_code'] == 6]
        if not ft_df.empty:
            summary['ft_action_frames'] = len(ft_df)
            if has_action_code:
                ft_req = ft_df[ft_df['action_code'] == 1]
                ft_resp = ft_df[ft_df['action_code'] == 2]
                summary['ft_requests'] = len(ft_req)
                summary['ft_responses'] = len(ft_resp)

                if len(ft_req) > 0 and len(ft_resp) == 0:
                    issues.append({
                        'category': 'Fast BSS Transition (802.11r)',
                        'issue': 'FT Request with no FT Response',
                        'severity': 'medium',
                        'count': len(ft_req),
                        'description': (
                            f'{len(ft_req)} FT Request(s) sent but no FT Response received. '
                            '802.11r fast roaming is failing — client will fall back to full '
                            're-authentication (slower roaming with noticeable latency).'
                        ),
                        'impact': 'Roaming latency increases from ~50ms (FT) to 200-500ms (full reauth). '
                                  'VoIP/video calls may drop during roam.',
                        'remediation': (
                            'Verify 802.11r (FT) is enabled on all APs in the roaming domain. '
                            'Ensure all APs share the same mobility domain ID and FT key hierarchy. '
                            'Check AP firmware for FT-over-DS vs FT-over-Air configuration.'
                        ),
                    })
                elif len(ft_req) > 0:
                    unanswered_ft = max(0, len(ft_req) - len(ft_resp))
                    if unanswered_ft > 0:
                        issues.append({
                            'category': 'Fast BSS Transition (802.11r)',
                            'issue': 'Partial FT failure',
                            'severity': 'low',
                            'count': unanswered_ft,
                            'description': (
                                f'{unanswered_ft} of {len(ft_req)} FT Request(s) unanswered. '
                                'Some fast roaming attempts are failing.'
                            ),
                            'remediation': 'Check target AP FT configuration and key distribution.',
                        })

        # --- SA Query / 802.11w MFP (cat=8) ---
        sa_df = action_df[action_df['category_code'] == 8]
        if not sa_df.empty:
            summary['sa_query_frames'] = len(sa_df)
            if has_action_code:
                sa_req = sa_df[sa_df['action_code'] == 0]
                sa_resp = sa_df[sa_df['action_code'] == 1]
                summary['sa_query_requests'] = len(sa_req)
                summary['sa_query_responses'] = len(sa_resp)

                if len(sa_req) > 2:
                    unanswered_sa = max(0, len(sa_req) - len(sa_resp))
                    if unanswered_sa > len(sa_req) * 0.3:
                        issues.append({
                            'category': 'SA Query (802.11w)',
                            'issue': 'Unanswered SA Query — possible deauth attack',
                            'severity': 'high',
                            'count': unanswered_sa,
                            'description': (
                                f'{unanswered_sa} of {len(sa_req)} SA Query Request(s) unanswered. '
                                'SA Query is used by 802.11w (MFP) to verify that a deauthentication '
                                'frame was genuinely sent by the AP and not spoofed. '
                                'Unanswered queries may indicate a deauthentication attack.'
                            ),
                            'impact': 'MFP cannot validate deauth/disassoc frames — '
                                      'client may be vulnerable to spoofed disconnections.',
                            'remediation': (
                                'Investigate deauth frames around the same time for spoofed sources. '
                                'Ensure AP has MFP (802.11w) enabled and configured as Required. '
                                'If deauth attack confirmed: enable WPA3 (mandates MFP).'
                            ),
                        })

                if len(sa_req) > 50:
                    issues.append({
                        'category': 'SA Query (802.11w)',
                        'issue': 'SA Query storm — repeated MFP validation',
                        'severity': 'medium',
                        'count': len(sa_req),
                        'description': (
                            f'{len(sa_req)} SA Query Request(s) detected — unusually high rate '
                            'indicates the client is repeatedly receiving possibly-spoofed '
                            'deauth/disassoc frames, triggering MFP verification.'
                        ),
                        'impact': 'Management overhead from repeated SA Queries; '
                                  'indicates ongoing deauth attack attempts.',
                        'remediation': (
                            'Enable wireless IDS/IPS to detect and locate the rogue device. '
                            'Enforce WPA3-SAE with MFP Required on all BSSIDs.'
                        ),
                    })

        # --- WNM / 802.11v BSS Transition Management (cat=10) ---
        wnm_df = action_df[action_df['category_code'] == 10]
        if not wnm_df.empty:
            summary['wnm_frames'] = len(wnm_df)
            if has_action_code:
                btm_req = wnm_df[wnm_df['action_code'] == 7]
                btm_resp = wnm_df[wnm_df['action_code'] == 8]
                summary['btm_requests'] = len(btm_req)
                summary['btm_responses'] = len(btm_resp)

                if len(btm_req) > 0:
                    steering_aps = btm_req['sa'].dropna().value_counts().head(5).to_dict()
                    steered_clients = btm_req['da'].dropna().value_counts().head(5).to_dict()

                    if len(btm_req) > 10:
                        issues.append({
                            'category': 'WNM (802.11v)',
                            'issue': 'Frequent BSS Transition Management steering',
                            'severity': 'medium',
                            'count': len(btm_req),
                            'steering_aps': steering_aps,
                            'steered_clients': steered_clients,
                            'btm_responses': len(btm_resp),
                            'description': (
                                f'{len(btm_req)} BTM Request(s) from AP(s) directing client(s) to roam. '
                                'High BTM rate suggests aggressive steering — possibly due to AP overload, '
                                'poor RF conditions, or band-steering policy.'
                            ),
                            'impact': 'Frequent roaming disrupts client connections; '
                                      'real-time applications (VoIP, video) may experience drops.',
                            'remediation': (
                                'Review AP controller roaming/steering policy thresholds (RSSI, load). '
                                'Check for RF coverage gaps causing ping-pong roaming. '
                                'If band-steering: verify 5 GHz coverage is adequate before forcing '
                                'clients off 2.4 GHz.'
                            ),
                        })

                    btm_rejected = max(0, len(btm_req) - len(btm_resp))
                    if btm_rejected > len(btm_req) * 0.3 and len(btm_req) > 3:
                        issues.append({
                            'category': 'WNM (802.11v)',
                            'issue': 'BSS Transition rejected by clients',
                            'severity': 'low',
                            'count': btm_rejected,
                            'description': (
                                f'{btm_rejected} BTM Request(s) were not accepted by clients. '
                                'Clients are refusing to roam to the suggested target AP.'
                            ),
                            'remediation': (
                                'Check if target AP is reachable with acceptable signal. '
                                'Verify client supports 802.11v. '
                                'Consider BTM with disassociation-imminent flag for mandatory steering.'
                            ),
                        })

        # --- HT/VHT operation actions (cat=7, 21) ---
        ht_vht_df = action_df[action_df['category_code'].isin([7, 21])]
        if not ht_vht_df.empty:
            summary['ht_vht_action_frames'] = len(ht_vht_df)
            if has_action_code:
                # SM Power Save (HT action 1) — MIMO power save transitions
                smps = ht_vht_df[
                    (ht_vht_df['category_code'] == 7) & (ht_vht_df['action_code'] == 1)
                ]
                if len(smps) > 10:
                    issues.append({
                        'category': 'HT',
                        'issue': 'Frequent SM Power Save transitions',
                        'severity': 'low',
                        'count': len(smps),
                        'description': (
                            f'{len(smps)} SM Power Save (SMPS) action frame(s). '
                            'Client is frequently switching between single-stream and '
                            'multi-stream MIMO, reducing throughput during power-save.'
                        ),
                        'impact': 'Transient throughput drops when client enters single-stream mode.',
                        'remediation': (
                            'Check client power-save settings; disable aggressive SMPS in driver. '
                            'Update client firmware.'
                        ),
                    })
                # Operating Mode Notification (VHT action 2)
                opmode = ht_vht_df[
                    (ht_vht_df['category_code'] == 21) & (ht_vht_df['action_code'] == 2)
                ]
                if len(opmode) > 5:
                    summary['vht_opmode_notifications'] = len(opmode)

        # --- Compile result ---
        if issues:
            severity_rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
            max_sev = max(issues, key=lambda i: severity_rank.get(i.get('severity', 'info'), 0))
            result['detected'] = True
            result['severity'] = max_sev.get('severity', 'medium')
            result['total_action_frames'] = len(action_df)
            result['category_distribution'] = category_distribution
            result['summary'] = summary
            result['issues'] = issues
            result['message'] = (
                f"{len(action_df)} action frame(s) across "
                f"{len(category_distribution)} categor"
                f"{'y' if len(category_distribution) == 1 else 'ies'}: "
                f"{len(issues)} issue(s) found"
            )
        elif len(action_df) > 0:
            result['total_action_frames'] = len(action_df)
            result['category_distribution'] = category_distribution
            result['summary'] = summary

        return result

    # ------------------------------------------------------------------
    #  Control Frame Health Analysis
    # ------------------------------------------------------------------

    def _detect_control_frame_issues(self, df: pd.DataFrame) -> Dict:
        """Detect control frame anomalies indicating medium access or hidden node problems.

        Analyses:
        - RTS/CTS imbalance → hidden node indicator
        - PS-Poll storms → excessive power-save buffered frame retrieval
        - Block Ack window efficiency → aggregation health
        - Duration/NAV abuse → medium hogging
        """
        result: Dict[str, Any] = {'detected': False, 'severity': 'info'}
        issues: List[Dict] = []
        ctrl_summary: Dict[str, Any] = {}

        rts_df = df[df['type_subtype'] == '0x001b']
        cts_df = df[df['type_subtype'] == '0x001c']
        ack_df = df[df['type_subtype'] == '0x001d']
        pspoll_df = df[df['type_subtype'] == '0x001a']
        ba_req_df = df[df['type_subtype'] == '0x0018']
        ba_resp_df = df[df['type_subtype'] == '0x0019']
        cfend_df = df[df['type_subtype'].isin({'0x001e', '0x001f'})]

        ctrl_summary['rts_frames'] = len(rts_df)
        ctrl_summary['cts_frames'] = len(cts_df)
        ctrl_summary['ack_frames'] = len(ack_df)
        ctrl_summary['ps_poll_frames'] = len(pspoll_df)
        ctrl_summary['block_ack_requests'] = len(ba_req_df)
        ctrl_summary['block_ack_responses'] = len(ba_resp_df)
        ctrl_summary['cf_end_frames'] = len(cfend_df)

        # --- RTS/CTS Analysis (hidden node detection) ---
        if len(rts_df) > 0:
            if len(cts_df) == 0:
                issues.append({
                    'category': 'RTS/CTS',
                    'issue': 'RTS frames without any CTS — hidden node indicator',
                    'severity': 'high',
                    'rts_count': len(rts_df),
                    'cts_count': 0,
                    'description': (
                        f'{len(rts_df)} RTS frame(s) captured but 0 CTS responses. '
                        'Strong indicator of a hidden node problem: the RTS sender cannot '
                        'hear the CTS from the target, causing collisions. '
                        'Note: in monitor mode, CTS from a distant STA may not be captured.'
                    ),
                    'impact': 'Hidden node collisions cause frame loss, retransmissions, '
                              'and severely degraded throughput for affected stations.',
                    'remediation': (
                        'Enable RTS/CTS threshold on AP (set below typical frame size). '
                        'Reposition APs to improve coverage overlap. '
                        'Consider adding an AP between hidden nodes. '
                        'Lower RTS threshold on client drivers.'
                    ),
                })
            else:
                cts_ratio = len(cts_df) / len(rts_df)
                if cts_ratio < 0.5:
                    issues.append({
                        'category': 'RTS/CTS',
                        'issue': 'Low CTS response rate — potential hidden node',
                        'severity': 'medium',
                        'rts_count': len(rts_df),
                        'cts_count': len(cts_df),
                        'cts_ratio': float(round(cts_ratio, 3)),
                        'description': (
                            f'CTS response rate is {cts_ratio*100:.1f}% '
                            f'({len(cts_df)}/{len(rts_df)}). Many RTS frames are going '
                            'unanswered, suggesting medium contention or hidden node conditions.'
                        ),
                        'impact': 'Frames following unanswered RTS are not sent, '
                                  'reducing throughput.',
                        'remediation': (
                            'Check for hidden nodes; improve AP placement; '
                            'reduce CCA threshold if supported.'
                        ),
                    })

            if 'ta' in rts_df.columns:
                ctrl_summary['top_rts_senders'] = (
                    rts_df['ta'].dropna().value_counts().head(5).to_dict()
                )

        # --- PS-Poll Analysis ---
        if len(pspoll_df) > 10:
            pspoll_by_client = (
                pspoll_df['ta'].dropna().value_counts()
                if 'ta' in pspoll_df.columns else pd.Series(dtype=int)
            )
            data_count = len(df[df['type_subtype'].isin(DATA_SUBTYPES)])
            pspoll_ratio = len(pspoll_df) / max(data_count, 1)

            if pspoll_ratio > 0.3 or len(pspoll_df) > 100:
                severity = 'medium' if pspoll_ratio > 0.5 or len(pspoll_df) > 500 else 'low'
                issues.append({
                    'category': 'PS-Poll',
                    'issue': 'Excessive PS-Poll frames — aggressive power-save',
                    'severity': severity,
                    'count': len(pspoll_df),
                    'pspoll_to_data_ratio': float(round(pspoll_ratio, 3)),
                    'top_clients': (
                        pspoll_by_client.head(5).to_dict()
                        if not pspoll_by_client.empty else {}
                    ),
                    'description': (
                        f'{len(pspoll_df)} PS-Poll frame(s) '
                        f'({pspoll_ratio*100:.1f}% of data frames). '
                        'Clients use legacy PS-Poll to retrieve buffered frames from AP. '
                        'High PS-Poll rate indicates aggressive power-save with frequent wakes.'
                    ),
                    'impact': (
                        'Each PS-Poll retrieves only one buffered frame — inefficient vs '
                        'WMM-PS (UAPSD). Increases latency and management overhead.'
                    ),
                    'remediation': (
                        'Enable WMM-PS (U-APSD) on both AP and client to replace legacy PS-Poll. '
                        'Adjust client power-save to use WMM-PS trigger delivery. '
                        'For latency-sensitive use: reduce DTIM interval or disable PS on client.'
                    ),
                })

            ctrl_summary['pspoll_by_client'] = (
                pspoll_by_client.head(10).to_dict()
                if not pspoll_by_client.empty else {}
            )

        # --- Block Ack (Control Frame) Analysis ---
        if len(ba_req_df) > 0 or len(ba_resp_df) > 0:
            if len(ba_req_df) > 0 and len(ba_resp_df) == 0:
                issues.append({
                    'category': 'Block Ack',
                    'issue': 'Block Ack Requests without responses',
                    'severity': 'medium',
                    'ba_req_count': len(ba_req_df),
                    'ba_resp_count': 0,
                    'description': (
                        f'{len(ba_req_df)} Block Ack Request (BAR) frame(s) without any BA '
                        'response. Receiver is not acknowledging aggregated frame bursts.'
                    ),
                    'impact': 'A-MPDU frames are not being acknowledged — '
                              'sender will retransmit entire aggregates.',
                    'remediation': (
                        'Check receiver firmware for Block Ack support. '
                        'Reduce A-MPDU aggregate size. '
                        'Investigate RF conditions causing BA frame loss.'
                    ),
                })
            elif len(ba_req_df) > 0:
                ba_ratio = len(ba_resp_df) / len(ba_req_df)
                if ba_ratio < 0.7:
                    issues.append({
                        'category': 'Block Ack',
                        'issue': 'Low Block Ack response rate',
                        'severity': 'low',
                        'ba_req_count': len(ba_req_df),
                        'ba_resp_count': len(ba_resp_df),
                        'ba_ratio': float(round(ba_ratio, 3)),
                        'description': (
                            f'BA response rate: {ba_ratio*100:.1f}% '
                            f'({len(ba_resp_df)}/{len(ba_req_df)}). '
                            'Some aggregate acknowledgements are being lost.'
                        ),
                        'remediation': 'Check for RF interference; reduce aggregate size.',
                    })

            # BA buffer size analysis
            if 'ba_buffer_size' in df.columns:
                ba_sizes = df.loc[
                    df['type_subtype'] == '0x0019', 'ba_buffer_size'
                ]
                ba_sizes = ba_sizes[ba_sizes > 0]
                if not ba_sizes.empty:
                    ctrl_summary['ba_buffer_size_min'] = int(ba_sizes.min())
                    ctrl_summary['ba_buffer_size_max'] = int(ba_sizes.max())
                    ctrl_summary['ba_buffer_size_mean'] = float(round(ba_sizes.mean(), 1))
                    if ba_sizes.max() < 32:
                        issues.append({
                            'category': 'Block Ack',
                            'issue': 'Small BA buffer size limiting aggregation',
                            'severity': 'low',
                            'max_buffer_size': int(ba_sizes.max()),
                            'description': (
                                f'Maximum BA buffer size is {int(ba_sizes.max())} MPDUs '
                                '(802.11n supports 64, 802.11ac/ax supports 256). '
                                'Small buffer limits the benefit of A-MPDU aggregation.'
                            ),
                            'remediation': (
                                'Update client/AP firmware to support larger BA window. '
                                'Check for 802.11n vs 802.11ac negotiation — '
                                'if falling back to HT, buffer is capped at 64.'
                            ),
                        })

        # --- Duration/NAV Analysis ---
        if 'duration' in df.columns:
            dur = df['duration'].dropna()
            dur = dur[dur > 0]
            if not dur.empty:
                ctrl_summary['avg_duration_us'] = float(round(dur.mean(), 1))
                ctrl_summary['max_duration_us'] = int(dur.max())
                # Excessive NAV values (>5ms unusual for normal traffic)
                excessive_nav = dur[dur > 5000]
                if len(excessive_nav) > 10:
                    excessive_sources = {}
                    if 'ta' in df.columns:
                        nav_frames = df[(df['duration'] > 5000)]
                        excessive_sources = (
                            nav_frames['ta'].dropna().value_counts().head(5).to_dict()
                        )
                    issues.append({
                        'category': 'NAV/Duration',
                        'issue': 'Excessive NAV duration values',
                        'severity': 'medium',
                        'count': len(excessive_nav),
                        'max_duration_us': int(dur.max()),
                        'sources': excessive_sources,
                        'description': (
                            f'{len(excessive_nav)} frame(s) with NAV > 5ms '
                            f'(max: {int(dur.max())} \u03bcs). '
                            'Excessively large Duration/NAV values can starve other stations '
                            'from accessing the medium (virtual carrier sense abuse).'
                        ),
                        'impact': 'Other stations defer transmission for the NAV duration, '
                                  'causing unfair medium access and throughput starvation.',
                        'remediation': (
                            'Identify source of excessive NAV values (check TA field). '
                            'Update driver/firmware. '
                            'If intentional: possible NAV attack — enable AP-side protection.'
                        ),
                    })

        # --- Compile result ---
        if issues:
            severity_rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
            max_sev = max(issues, key=lambda i: severity_rank.get(i.get('severity', 'info'), 0))
            result['detected'] = True
            result['severity'] = max_sev.get('severity', 'medium')
            result['control_frame_summary'] = ctrl_summary
            result['issues'] = issues
            result['message'] = (
                f"Control frame analysis: {len(issues)} issue(s) — "
                f"{ctrl_summary.get('rts_frames', 0)} RTS, "
                f"{ctrl_summary.get('cts_frames', 0)} CTS, "
                f"{ctrl_summary.get('ps_poll_frames', 0)} PS-Poll, "
                f"{ctrl_summary.get('block_ack_requests', 0)} BAR"
            )
        elif any(v > 0 for v in ctrl_summary.values()
                 if isinstance(v, (int, float))):
            result['control_frame_summary'] = ctrl_summary

        return result

    # ------------------------------------------------------------------
    #  Power Management Anomaly Detection
    # ------------------------------------------------------------------

    def _detect_power_save_issues(self, df: pd.DataFrame) -> Dict:
        """Detect power management anomalies in WiFi operations.

        Analyses:
        - Null Data / QoS Null keepalive patterns and storms
        - Per-client null polling with no AP data response
        - Excessive power-save mode transitions per client
        - Correlation of PS transitions with connectivity
        """
        result: Dict[str, Any] = {'detected': False, 'severity': 'info'}
        issues: List[Dict] = []
        ps_summary: Dict[str, Any] = {}

        # --- Null / QoS-Null frame analysis ---
        null_df = df[df['type_subtype'] == '0x0024']
        qos_null_df = df[df['type_subtype'] == '0x002c']
        null_total = len(null_df) + len(qos_null_df)

        ps_summary['null_frames'] = len(null_df)
        ps_summary['qos_null_frames'] = len(qos_null_df)
        ps_summary['total_null_frames'] = null_total

        real_data_subtypes = {'0x0020', '0x0021', '0x0022', '0x0028'}
        real_data_df = df[df['type_subtype'].isin(real_data_subtypes)]
        ps_summary['real_data_frames'] = len(real_data_df)

        if null_total > 0 and len(real_data_df) > 0:
            null_ratio = null_total / (null_total + len(real_data_df))
            ps_summary['null_to_data_ratio'] = float(round(null_ratio, 3))

            if null_ratio > 0.5 and null_total > 50:
                issues.append({
                    'category': 'Null Data',
                    'issue': 'Null/QoS-Null frames dominate data traffic',
                    'severity': 'medium',
                    'null_count': null_total,
                    'data_count': len(real_data_df),
                    'null_ratio': float(round(null_ratio, 3)),
                    'description': (
                        f'Null/QoS-Null frames are {null_ratio*100:.1f}% of all data-type '
                        f'frames ({null_total} null vs {len(real_data_df)} real data). '
                        'Excessive null frames indicate clients are in power-save most of the '
                        'time, spending more time on PS signaling than data transfer.'
                    ),
                    'impact': 'Network overhead from PS management; indicates idle or '
                              'poorly-configured clients wasting airtime.',
                    'remediation': (
                        'Review client power-save configuration. '
                        'Adjust DTIM interval on AP (longer DTIM = fewer wakeups). '
                        'For active clients: disable aggressive power-save in driver.'
                    ),
                })
        elif null_total > 0 and len(real_data_df) == 0:
            ps_summary['null_to_data_ratio'] = 1.0
            issues.append({
                'category': 'Null Data',
                'issue': 'Only Null/QoS-Null frames — no real data transfer',
                'severity': 'medium',
                'null_count': null_total,
                'data_count': 0,
                'description': (
                    f'{null_total} Null/QoS-Null frame(s) but zero real data frames. '
                    'Client is associated and maintaining power-save keepalive but never '
                    'exchanging actual application data.'
                ),
                'impact': 'No useful data throughput; client may have IP/DHCP failure '
                          'or application-layer issue.',
                'remediation': (
                    'Check IP connectivity (DHCP lease, gateway reachability). '
                    'Verify application on client is actually generating traffic. '
                    'Check for captive portal or 802.1X post-auth issues.'
                ),
            })

        # Per-client Null frame analysis
        null_all = pd.concat([null_df, qos_null_df], ignore_index=True)
        if not null_all.empty and 'sa' in null_all.columns:
            null_by_client = null_all['sa'].dropna().value_counts()
            ps_summary['top_null_senders'] = null_by_client.head(10).to_dict()

            # One-sided pattern: client polls with QoS-Null but gets no data back
            for client_mac, null_count in null_by_client.head(10).items():
                if null_count < 30:
                    continue
                ap_to_client = real_data_df[real_data_df['da'] == client_mac]
                if len(ap_to_client) == 0:
                    issues.append({
                        'category': 'Null Data',
                        'issue': f'Client polling with no AP data response',
                        'severity': 'medium',
                        'client': str(client_mac),
                        'null_polls': int(null_count),
                        'ap_data_to_client': 0,
                        'description': (
                            f'Client {client_mac} sent {null_count} Null/QoS-Null poll(s) '
                            'but AP sent no data frames back. Client is repeatedly waking from '
                            'power-save to check for buffered data, but AP has nothing queued.'
                        ),
                        'impact': 'Wasted airtime and client battery on futile PS-poll cycles.',
                        'remediation': (
                            'If client expects data: check AP uplink connectivity and DHCP/IP status. '
                            'If client is idle: increase DTIM period to reduce wakeup frequency. '
                            'Check AP is correctly buffering multicast/broadcast for PS clients.'
                        ),
                    })

        # --- Power Management bit transitions ---
        if 'pwrmgt' in df.columns and 'sa' in df.columns:
            pm_transitions: Dict[str, Dict] = {}
            for client, grp in df.groupby('sa'):
                if client is None or len(grp) < 10:
                    continue
                pm_vals = pd.to_numeric(
                    grp['pwrmgt'], errors='coerce'
                ).fillna(0).astype(int)
                transitions = int((pm_vals.diff().abs() > 0).sum())
                ps_on = int((pm_vals == 1).sum())
                ps_off = int((pm_vals == 0).sum())
                if transitions > 0:
                    pm_transitions[client] = {
                        'transitions': transitions,
                        'frames_in_ps': ps_on,
                        'frames_active': ps_off,
                        'total_frames': len(grp),
                    }

            if pm_transitions:
                sorted_clients = sorted(
                    pm_transitions.items(),
                    key=lambda x: x[1]['transitions'], reverse=True
                )
                ps_summary['pm_transitions_by_client'] = {
                    k: v for k, v in sorted_clients[:10]
                }

                for client, stats in sorted_clients[:10]:
                    transition_rate = stats['transitions'] / max(stats['total_frames'], 1)
                    client_df = df[df['sa'] == client]
                    duration_span = 0.0
                    if 'timestamp' in client_df.columns and len(client_df) > 1:
                        duration_span = float(
                            client_df['timestamp'].max() - client_df['timestamp'].min()
                        )
                    transitions_per_sec = (
                        stats['transitions'] / duration_span
                        if duration_span > 0 else 0.0
                    )

                    if stats['transitions'] > 50 and transition_rate > 0.1:
                        issues.append({
                            'category': 'Power Management',
                            'issue': f'Excessive PS transitions for {client}',
                            'severity': 'low',
                            'client': str(client),
                            'transitions': stats['transitions'],
                            'transition_rate': float(round(transition_rate, 3)),
                            'transitions_per_sec': (
                                float(round(transitions_per_sec, 2))
                                if transitions_per_sec > 0 else None
                            ),
                            'description': (
                                f'Client {client} had {stats["transitions"]} power-save '
                                f'mode transitions across {stats["total_frames"]} frames '
                                f'({transition_rate*100:.1f}% of frames are PS boundary '
                                'changes). Rapid PS transitions cause latency spikes.'
                            ),
                            'impact': 'Each PS transition adds latency (50-200ms for '
                                      'buffered frames). Rapid cycling wastes battery and airtime.',
                            'remediation': (
                                'Configure client to use WMM-PS (U-APSD) instead of legacy PS-Poll. '
                                'Adjust PS wake interval in client driver. '
                                'For latency-sensitive apps: disable power-save entirely.'
                            ),
                        })

        # --- Compile result ---
        if issues:
            severity_rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
            max_sev = max(issues, key=lambda i: severity_rank.get(i.get('severity', 'info'), 0))
            result['detected'] = True
            result['severity'] = max_sev.get('severity', 'medium')
            result['power_save_summary'] = ps_summary
            result['issues'] = issues
            result['message'] = (
                f"Power management analysis: {len(issues)} issue(s) — "
                f"{null_total} null frame(s), {len(real_data_df)} data frame(s)"
            )
        elif null_total > 0:
            result['power_save_summary'] = ps_summary

        return result

    # ------------------------------------------------------------------
    #  Connection Delay Analysis
    # ------------------------------------------------------------------

    def _detect_connection_delays(self, df: pd.DataFrame) -> Dict:
        """Detect and diagnose delays between first probe response and authentication start.

        Identifies reasons for connection delays including:
        - Multi-band scanning (client scanning 2.4 GHz and 5 GHz)
        - Weak signal causing hesitation
        - No AP response on certain bands/channels
        - Multiple scan cycles before connecting
        - Long dwell times between scan rounds
        - Roaming candidate evaluation
        """
        result = {"detected": False, "severity": "info"}

        probe_req = df[df['type_subtype'] == '0x0004'].copy()
        probe_resp = df[df['type_subtype'] == '0x0005'].copy()
        auth_frames = df[df['type_subtype'] == '0x000b'].copy()

        if probe_resp.empty or auth_frames.empty:
            return result

        # Get unique clients that eventually authenticate
        auth_clients = set()
        if 'sa' in auth_frames.columns:
            auth_clients = set(auth_frames['sa'].dropna().unique())

        delay_analyses: List[Dict] = []

        for client_mac in auth_clients:
            # Get first directed or broadcast probe that received a response
            client_probes = probe_req[probe_req['sa'] == client_mac].sort_values('timestamp')
            client_resp = probe_resp[probe_resp['da'] == client_mac].sort_values('timestamp')
            client_auth = auth_frames[
                (auth_frames['sa'] == client_mac)
            ].sort_values('timestamp')

            if client_resp.empty or client_auth.empty:
                continue

            first_resp_ts = float(client_resp.iloc[0]['timestamp'])
            first_resp_frame = int(client_resp.iloc[0]['frame_number'])
            first_auth_ts = float(client_auth.iloc[0]['timestamp'])
            first_auth_frame = int(client_auth.iloc[0]['frame_number'])

            delay_sec = first_auth_ts - first_resp_ts

            # Only flag delays > 2 seconds as notable
            if delay_sec < 2.0:
                continue

            # --- Analyze reasons for the delay ---
            reasons: List[Dict] = []

            # Get all probe/resp frames between first_resp and first_auth
            scan_window = df[
                (df['timestamp'] >= first_resp_ts) &
                (df['timestamp'] <= first_auth_ts) &
                ((df['sa'] == client_mac) | (df['da'] == client_mac))
            ].sort_values('timestamp')

            probes_in_window = scan_window[scan_window['type_subtype'] == '0x0004']
            responses_in_window = scan_window[scan_window['type_subtype'] == '0x0005']

            # 1. Multi-band scanning detection
            channels_scanned = set()
            bands_scanned = set()
            channel_detail: Dict[str, Dict] = {}  # channel -> {probes, responses, signal_range}

            if 'channel' in probes_in_window.columns:
                for ch in probes_in_window['channel'].dropna().unique():
                    ch_val = int(ch) if ch > 0 else 0
                    if ch_val == 0:
                        continue
                    channels_scanned.add(ch_val)
                    band = '2.4GHz' if ch_val <= 14 else '5GHz' if ch_val <= 177 else '6GHz'
                    bands_scanned.add(band)

                    ch_probes = probes_in_window[probes_in_window['channel'] == ch]
                    ch_responses = responses_in_window[responses_in_window['channel'] == ch]
                    signals = ch_probes['signal_dbm'].dropna()
                    signals = signals[signals != 0]

                    channel_detail[f"ch{ch_val} ({band})"] = {
                        'probes_sent': int(len(ch_probes)),
                        'responses_received': int(len(ch_responses)),
                        'signal_min': float(signals.min()) if not signals.empty else None,
                        'signal_max': float(signals.max()) if not signals.empty else None,
                        'signal_avg': float(round(signals.mean(), 1)) if not signals.empty else None,
                    }

            if len(bands_scanned) > 1:
                # Check which bands got responses
                bands_with_response = set()
                bands_without_response = set()
                for ch_label, info in channel_detail.items():
                    band_name = ch_label.split('(')[1].rstrip(')')
                    if info['responses_received'] > 0:
                        bands_with_response.add(band_name)
                    else:
                        bands_without_response.add(band_name)

                reasons.append({
                    'reason': 'multi_band_scanning',
                    'severity': 'medium',
                    'description': (
                        f"Client scanning across {len(bands_scanned)} bands "
                        f"({', '.join(sorted(bands_scanned))}). "
                        f"AP responded on: {', '.join(sorted(bands_with_response)) or 'none'}. "
                        f"No response on: {', '.join(sorted(bands_without_response)) or 'all responded'}."
                    ),
                    'impact': (
                        'Client spends time scanning bands where no AP is available, '
                        'delaying the connection decision.'
                    ),
                    'remediation': (
                        'Configure client band preference or disable unused bands. '
                        'Deploy AP on both bands if dual-band clients are expected.'
                    ),
                })

            # 2. Weak signal causing hesitation
            if 'signal_dbm' in client_resp.columns:
                resp_signals = client_resp[
                    (client_resp['timestamp'] >= first_resp_ts) &
                    (client_resp['timestamp'] <= first_auth_ts)
                ]['signal_dbm'].dropna()
                resp_signals = resp_signals[resp_signals != 0]

                if not resp_signals.empty:
                    avg_resp_signal = float(resp_signals.mean())
                    # Check if client probes on other channels had better signal
                    probe_signals_all = probes_in_window['signal_dbm'].dropna()
                    probe_signals_all = probe_signals_all[probe_signals_all != 0]

                    if avg_resp_signal < -75 and not probe_signals_all.empty:
                        best_probe_signal = float(probe_signals_all.max())
                        if best_probe_signal > avg_resp_signal + 10:
                            reasons.append({
                                'reason': 'weak_signal_hesitation',
                                'severity': 'medium',
                                'description': (
                                    f"AP responses have weak signal (avg {avg_resp_signal:.0f} dBm) "
                                    f"while client probes on other channels show stronger signal "
                                    f"(up to {best_probe_signal:.0f} dBm). Client may be waiting "
                                    f"for a stronger AP candidate."
                                ),
                                'impact': (
                                    'Client delays connection hoping a better AP will respond '
                                    'on a different channel/band.'
                                ),
                                'remediation': (
                                    'Improve 5 GHz coverage or add AP closer to client. '
                                    'Consider adjusting client roaming aggressiveness settings.'
                                ),
                            })

            # 3. No response on certain channels
            channels_no_response = []
            channels_with_response = []
            for ch_label, info in channel_detail.items():
                if info['probes_sent'] > 0 and info['responses_received'] == 0:
                    channels_no_response.append(ch_label)
                elif info['responses_received'] > 0:
                    channels_with_response.append(ch_label)

            if channels_no_response:
                total_unanswered = sum(
                    channel_detail[ch]['probes_sent'] for ch in channels_no_response
                )
                reasons.append({
                    'reason': 'unanswered_channels',
                    'severity': 'low',
                    'description': (
                        f"{total_unanswered} probes on {', '.join(channels_no_response)} "
                        f"received no AP response. AP only responds on "
                        f"{', '.join(channels_with_response)}."
                    ),
                    'impact': 'Time wasted probing channels where no AP operates.',
                    'remediation': (
                        'Use preferred channel lists on the client or deploy AP on expected channels.'
                    ),
                })

            # 4. Multiple scan cycles
            # Detect scan cycles: gaps > 1 second between probe bursts
            if len(probes_in_window) > 2:
                probe_times = probes_in_window['timestamp'].sort_values().values
                gaps = []
                for i in range(1, len(probe_times)):
                    gap = float(probe_times[i]) - float(probe_times[i - 1])
                    if gap > 1.0:
                        gaps.append(gap)

                scan_cycles = len(gaps) + 1
                if scan_cycles > 2:
                    avg_gap = sum(gaps) / len(gaps) if gaps else 0
                    max_gap = max(gaps) if gaps else 0
                    reasons.append({
                        'reason': 'multiple_scan_cycles',
                        'severity': 'medium' if scan_cycles > 3 else 'low',
                        'description': (
                            f"Client performed {scan_cycles} scan cycles before connecting. "
                            f"Average inter-cycle gap: {avg_gap:.1f}s, max gap: {max_gap:.1f}s."
                        ),
                        'impact': (
                            'Client supplicant requires multiple scan rounds to build a '
                            'stable BSS candidate list before committing to an AP.'
                        ),
                        'remediation': (
                            'Reduce scan dwell time in client driver settings. '
                            'Lower the minimum scan results threshold. '
                            'Use cached PMKSA or fast reconnect (802.11r) to skip full scanning.'
                        ),
                    })

            # 5. Channel dwell time analysis
            if 'channel' in probes_in_window.columns and len(channels_scanned) > 1:
                ch_dwell_times: Dict[int, float] = {}
                for ch_val in channels_scanned:
                    ch_frames = scan_window[
                        (scan_window['channel'] == ch_val) &
                        ((scan_window['sa'] == client_mac) | (scan_window['da'] == client_mac))
                    ]
                    if len(ch_frames) >= 2:
                        ch_ts = ch_frames['timestamp'].sort_values()
                        ch_dwell_times[ch_val] = float(ch_ts.iloc[-1]) - float(ch_ts.iloc[0])

                if ch_dwell_times:
                    total_dwell = sum(ch_dwell_times.values())
                    if total_dwell > 0:
                        # Time unaccounted for (switching between channels)
                        switch_overhead = delay_sec - total_dwell
                        if switch_overhead > 2.0:
                            reasons.append({
                                'reason': 'channel_switch_overhead',
                                'severity': 'low',
                                'description': (
                                    f"~{switch_overhead:.1f}s spent in channel switching/idle "
                                    f"(total scan dwell: {total_dwell:.1f}s vs delay: {delay_sec:.1f}s)."
                                ),
                                'impact': 'Channel transitions and passive listening add latency.',
                                'remediation': (
                                    'Reduce the number of channels in scan list. '
                                    'Use directed probes instead of passive scanning.'
                                ),
                            })

            # 6. Broadcast vs directed probe transition
            if not probes_in_window.empty:
                broadcast_probes = probes_in_window[
                    probes_in_window['da'] == 'ff:ff:ff:ff:ff:ff'
                ]
                directed_probes = probes_in_window[
                    probes_in_window['da'] != 'ff:ff:ff:ff:ff:ff'
                ]
                if len(broadcast_probes) > 0 and len(directed_probes) > 0:
                    last_broadcast_ts = float(broadcast_probes['timestamp'].max())
                    first_directed_ts = float(directed_probes['timestamp'].min())
                    transition_delay = first_directed_ts - first_resp_ts
                    if transition_delay > 3.0:
                        reasons.append({
                            'reason': 'scan_to_directed_transition',
                            'severity': 'low',
                            'description': (
                                f"Client took {transition_delay:.1f}s from first AP response "
                                f"to send a directed (unicast) probe to the AP — indicating "
                                f"AP selection evaluation phase."
                            ),
                            'impact': (
                                'Client evaluates multiple scan results before selecting '
                                'a target AP for association.'
                            ),
                            'remediation': (
                                'Configure preferred BSSID/SSID list. '
                                'Use 802.11k neighbor reports for faster AP selection.'
                            ),
                        })

            # 7. Passive scan periods (gaps with no client TX)
            if not scan_window.empty:
                client_tx = scan_window[scan_window['sa'] == client_mac].sort_values('timestamp')
                if len(client_tx) >= 2:
                    tx_times = client_tx['timestamp'].values
                    passive_gaps = []
                    for i in range(1, len(tx_times)):
                        g = float(tx_times[i]) - float(tx_times[i - 1])
                        if g > 3.0:
                            passive_gaps.append(g)
                    if passive_gaps:
                        total_passive = sum(passive_gaps)
                        reasons.append({
                            'reason': 'passive_scan_periods',
                            'severity': 'low',
                            'description': (
                                f"{len(passive_gaps)} passive listening period(s) totalling "
                                f"{total_passive:.1f}s (gaps > 3s with no client transmissions)."
                            ),
                            'impact': (
                                'Client performs passive scanning (listening for beacons) '
                                'on DFS or low-priority channels before active probing.'
                            ),
                            'remediation': (
                                'Use active scanning on all channels (where regulatory allows). '
                                'Reduce passive scan dwell time in driver configuration.'
                            ),
                        })

            # Build per-client analysis
            if reasons:
                # Determine overall severity
                severity_rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
                max_sev = max(reasons, key=lambda r: severity_rank.get(r.get('severity', 'info'), 0))

                delay_analyses.append({
                    'client': client_mac,
                    'ap_bssid': str(client_resp.iloc[0].get('sa', 'unknown')),
                    'delay_seconds': round(delay_sec, 2),
                    'first_probe_response_frame': first_resp_frame,
                    'first_probe_response_time': first_resp_ts,
                    'first_auth_frame': first_auth_frame,
                    'first_auth_time': first_auth_ts,
                    'scan_cycles': len([g for g in (gaps if 'gaps' in dir() else []) if g > 1.0]) + 1,
                    'channels_scanned': sorted(channels_scanned),
                    'bands_scanned': sorted(bands_scanned),
                    'channel_detail': channel_detail,
                    'total_probes_in_delay': int(len(probes_in_window)),
                    'total_responses_in_delay': int(len(responses_in_window)),
                    'reasons': reasons,
                    'severity': max_sev.get('severity', 'medium'),
                })

        if delay_analyses:
            severity_rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
            overall_sev = max(delay_analyses,
                              key=lambda a: severity_rank.get(a.get('severity', 'info'), 0))
            max_delay = max(a['delay_seconds'] for a in delay_analyses)

            result['detected'] = True
            result['severity'] = overall_sev.get('severity', 'medium')
            result['total_clients_with_delays'] = len(delay_analyses)
            result['max_delay_seconds'] = max_delay
            result['delay_analyses'] = delay_analyses
            result['message'] = (
                f"Connection delay detected: {len(delay_analyses)} client(s) with "
                f"delays up to {max_delay:.1f}s between first probe response and authentication"
            )

        return result


def main():
    """Standalone CLI entry point"""
    parser = argparse.ArgumentParser(description='Analyze WLAN/WiFi traffic from PCAP file')
    parser.add_argument('--input', '-i', required=True, help='Input PCAP file')
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('--html-report', '-r', help='Generate HTML report file')
    parser.add_argument('--config', '-c', default='config/default.yaml', help='Config file')

    args = parser.parse_args()

    analyzer = WLANAnalyzer(config_path=args.config)
    results = analyzer.analyze(args.input)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))

    if args.html_report:
        try:
            from src.reports.html_generator import HTMLReportGenerator
            generator = HTMLReportGenerator()
            report_path = generator.generate_report(
                results={'total_packets': results.get('total_packets', 0),
                         'protocol_analysis': {'wlan': results}},
                pcap_file=args.input,
                output_file=args.html_report,
                protocol="WLAN"
            )
            print(f"\nHTML Report generated: {report_path}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")

    if results.get('threats'):
        print("\n=== WLAN THREATS DETECTED ===")
        for name, data in results['threats'].items():
            print(f"\n[{data.get('severity', 'unknown').upper()}] {name.replace('_', ' ').title()}")
            if 'message' in data:
                print(f"  {data['message']}")


if __name__ == '__main__':
    main()
