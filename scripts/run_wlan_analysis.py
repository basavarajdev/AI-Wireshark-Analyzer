#!/usr/bin/env python3
"""
Fast WLAN analysis script using tshark for bulk field extraction
then feeding into WLANAnalyzer for threat detection and reporting.
"""

import subprocess
import json
import sys
import pandas as pd
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from loguru import logger

# Import the frame subtype maps from the wlan_analyzer module
from src.protocols.wlan_analyzer import (
    FRAME_SUBTYPES, MGMT_SUBTYPES, CTRL_SUBTYPES, DATA_SUBTYPES, WLANAnalyzer,
)

PCAP_FILE   = sys.argv[1] if len(sys.argv) > 1 else None
MAC_FILTER  = sys.argv[2] if len(sys.argv) > 2 else None   # e.g. "C8:5A:CF:FF:71:6B"

if not PCAP_FILE:
    print("Usage: python scripts/run_wlan_analysis.py <pcap_file> [mac_filter]")
    sys.exit(1)

# Auto-generate output paths from the pcap filename
_pcap_stem = Path(PCAP_FILE).stem
if MAC_FILTER:
    _mac_slug = MAC_FILTER.replace(':', '_')
    _pcap_stem = f"{_pcap_stem}_mac_{_mac_slug}"
OUTPUT_JSON = f"results/{_pcap_stem}.json"
OUTPUT_HTML = f"results/{_pcap_stem}_report.html"

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
    "wlan.seq",
    "wlan.duration",
    "wlan.fc.retry",
    "wlan.fc.protected",
    "wlan.fc.pwrmgt",
    "wlan_radio.signal_dbm",
    "wlan_radio.noise_dbm",
    "wlan_radio.channel",
    "wlan_radio.frequency",
    "wlan_radio.data_rate",
    "wlan_radio.phy",
    "wlan.ssid",
    "wlan.fixed.status_code",
    "wlan.fixed.reason_code",
    "wlan.rsn.version",
    "wlan_rsna_eapol.keydes.msgnr",
    "wlan.fixed.auth_seq",
    "wlan.fixed.auth.alg",
    "wlan.rsn.akms.type",
    "wlan.fixed.capabilities",
    "wlan.fixed.category_code",
    "wlan.fixed.baparams.buffersize",
    "wlan.fixed.action_code",
]

COLUMN_NAMES = [
    "timestamp", "length", "frame_number", "type_subtype",
    "sa", "da", "ta", "ra", "bssid",
    "seq", "duration", "retry", "protected", "pwrmgt",
    "signal_dbm", "noise_dbm", "channel", "frequency",
    "data_rate", "phy", "ssid",
    "status_code", "reason_code",
    "rsn_version", "eapol_msg_nr", "auth_seq",
    "auth_alg", "akm_type", "capabilities",
    "category_code", "ba_buffer_size", "action_code",
]


def run_tshark(pcap_file, mac_filter=None):
    """Extract WLAN fields via tshark in bulk (much faster than pyshark)."""
    field_args = []
    for f in TSHARK_FIELDS:
        field_args.extend(["-e", f])

    # Build display filter: always restrict to wlan frames; optionally add MAC
    if mac_filter:
        mac = mac_filter.lower()
        display_filter = (
            f"wlan && (wlan.sa == {mac} || wlan.da == {mac} "
            f"|| wlan.ta == {mac} || wlan.ra == {mac} || wlan.bssid == {mac})"
        )
    else:
        display_filter = "wlan"

    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-E", "header=n",
    ] + field_args

    logger.info(f"Running tshark on {pcap_file}" + (f" [MAC filter: {mac_filter}]" if mac_filter else "") + " ...")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        # tshark returns non-zero for truncated pcaps but still outputs data
        if proc.stdout.strip():
            logger.warning(f"tshark warning (continuing with partial output): {proc.stderr.strip()}")
        else:
            logger.error(f"tshark error: {proc.stderr}")
            sys.exit(1)
    return proc.stdout


def parse_tshark_output(raw_output):
    """Parse tab-separated tshark output into a DataFrame."""
    rows = []
    for line in raw_output.strip().split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        # Pad to expected length
        while len(parts) < len(COLUMN_NAMES):
            parts.append('')
        rows.append(parts[:len(COLUMN_NAMES)])

    df = pd.DataFrame(rows, columns=COLUMN_NAMES)

    def _to_numeric_hex(series: pd.Series) -> pd.Series:
        """Convert a column that may contain decimal or 0x-prefixed hex strings to float."""
        def parse_val(v):
            if not v or v == '':
                return 0.0
            try:
                return float(int(v, 0))   # handles '15', '0x000f', '0xf' etc.
            except (ValueError, TypeError):
                try:
                    return float(v)
                except (ValueError, TypeError):
                    return 0.0
        return series.apply(parse_val)

    # Plain float columns (excluding boolean fields handled separately)
    for col in ['timestamp', 'length', 'frame_number', 'seq', 'duration',
                'signal_dbm', 'noise_dbm', 'channel', 'frequency', 'data_rate']:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    # Boolean fields: tshark emits 'True'/'False' or '1'/'0' depending on version
    def _to_bool_int(series: pd.Series) -> pd.Series:
        return series.map({'True': 1, 'False': 0, 'true': 1, 'false': 0,
                           '1': 1, '0': 0}).fillna(0).astype(int)

    df['protected'] = _to_bool_int(df['protected'])
    df['retry']     = _to_bool_int(df['retry'])
    df['pwrmgt']    = _to_bool_int(df['pwrmgt'])

    # Columns that tshark may emit as hex (0x…) or decimal
    for col in ['status_code', 'reason_code', 'rsn_version']:
        df[col] = _to_numeric_hex(df[col])
    df['eapol_msg_nr'] = pd.to_numeric(df['eapol_msg_nr'], errors='coerce').fillna(0)
    df['auth_seq']     = _to_numeric_hex(df['auth_seq'])
    df['auth_alg']     = _to_numeric_hex(df['auth_alg'])
    df['akm_type']     = _to_numeric_hex(df['akm_type'])
    df['category_code'] = _to_numeric_hex(df['category_code'])
    df['ba_buffer_size'] = pd.to_numeric(df['ba_buffer_size'], errors='coerce').fillna(0)
    df['action_code'] = _to_numeric_hex(df['action_code'])

    # Convert type_subtype to hex format matching the analyzer's expected format
    def normalize_subtype(val):
        try:
            v = int(val, 0)
            return f'0x{v:04x}'
        except (ValueError, TypeError):
            return 'unknown'

    df['type_subtype'] = df['type_subtype'].apply(normalize_subtype)

    # Replace empty strings with None for address columns
    for col in ['sa', 'da', 'ta', 'ra', 'bssid']:
        df[col] = df[col].replace('', None)

    # Decode hex-encoded SSIDs to readable strings
    def decode_ssid(val):
        if not val or val == '':
            return None
        try:
            return bytes.fromhex(val).decode('utf-8', errors='replace')
        except (ValueError, TypeError):
            return val

    df['ssid'] = df['ssid'].apply(decode_ssid)

    return df


def main():
    raw = run_tshark(PCAP_FILE, mac_filter=MAC_FILTER)
    df = parse_tshark_output(raw)
    logger.info(f"Parsed {len(df)} WLAN frames via tshark")

    if df.empty:
        logger.warning("No frames matched the filter — check the MAC address.")
        sys.exit(0)

    # Use the WLANAnalyzer for statistics, connection events, and threat detection
    analyzer = WLANAnalyzer()

    results = {
        "total_packets": len(df),
        "mac_filter": MAC_FILTER,
        "statistics": analyzer._calculate_statistics(df),
        "connection_events": analyzer._analyze_connection_events(df),
        "threats": analyzer._detect_threats(df),
    }

    # Save JSON
    Path(OUTPUT_JSON).parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"JSON results saved to {OUTPUT_JSON}")

    # Generate HTML report
    try:
        from src.reports.html_generator import HTMLReportGenerator
        generator = HTMLReportGenerator()
        report_data = {
            'total_packets': results['total_packets'],
            'protocol_analysis': {'wlan': results},
        }
        proto_label = f"WLAN [MAC: {MAC_FILTER}]" if MAC_FILTER else "WLAN"
        report_path = generator.generate_report(
            results=report_data,
            pcap_file=PCAP_FILE,
            output_file=OUTPUT_HTML,
            protocol=proto_label,
        )
        logger.info(f"HTML report saved to {report_path}")
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        import traceback
        traceback.print_exc()

    # Print summary
    print("\n=== WLAN ANALYSIS SUMMARY ===")
    if MAC_FILTER:
        print(f"MAC Filter: {MAC_FILTER}")
    stats = results['statistics']
    print(f"Total frames: {stats.get('total_frames', 0)}")
    print(f"Management: {stats.get('management_frames', 0)}")
    print(f"Control: {stats.get('control_frames', 0)}")
    print(f"Data: {stats.get('data_frames', 0)}")
    print(f"Unique BSSIDs: {stats.get('unique_bssids', 0)}")
    print(f"Unique SSIDs: {stats.get('unique_ssids', 0)}")
    if stats.get('detected_ssids'):
        print(f"SSIDs: {list(stats['detected_ssids'].keys())}")

    events = results['connection_events']
    print(f"\nAssociation requests: {events.get('association_requests', 0)}")
    print(f"Deauthentication frames: {events.get('deauthentication_frames', 0)}")
    print(f"Disassociation frames: {events.get('disassociation_frames', 0)}")
    print(f"Total disconnections: {events.get('total_disconnections', 0)}")

    if results['threats']:
        print("\n=== FINDINGS DETECTED ===")
        for name, data in results['threats'].items():
            sev = data.get('severity', 'unknown').upper()
            msg = data.get('message', 'No details')
            print(f"[{sev}] {name.replace('_', ' ').title()}: {msg}")
            # Show failure breakdown if available
            if 'failure_breakdown' in data:
                for reason, count in list(data['failure_breakdown'].items())[:5]:
                    print(f"        {count}x  {reason}")
            if 'bssid_detail' in data:
                for bssid, detail in list(data['bssid_detail'].items())[:3]:
                    print(f"        {bssid}: {detail['loss_events']} gaps, max {detail['max_gap_sec']}s")

            # Action Frame Issues detail
            if name == 'action_frame_issues':
                cat_dist = data.get('category_distribution', {})
                if cat_dist:
                    print("    Category Distribution:")
                    for cat, cnt in sorted(cat_dist.items(), key=lambda x: x[1], reverse=True):
                        print(f"        {cat}: {cnt:,} frames")
                action_issues = data.get('issues', [])
                for issue in action_issues:
                    if isinstance(issue, dict):
                        print(f"      [{issue.get('severity','?').upper()}] {issue.get('category','')} — {issue.get('issue','')}")
                        if issue.get('description'):
                            # Word-wrap long descriptions for console
                            desc = issue['description']
                            print(f"           {desc[:120]}{'...' if len(desc)>120 else ''}")
                        if issue.get('remediation'):
                            print(f"           Fix: {issue['remediation'][:120]}{'...' if len(issue['remediation'])>120 else ''}")

            # Control Frame Issues detail
            elif name == 'control_frame_issues':
                ctrl_summary = data.get('control_frame_summary', {})
                if ctrl_summary:
                    rts = ctrl_summary.get('rts_frames', 0)
                    cts = ctrl_summary.get('cts_frames', 0)
                    ack = ctrl_summary.get('ack_frames', 0)
                    psp = ctrl_summary.get('ps_poll_frames', 0)
                    bar = ctrl_summary.get('block_ack_requests', 0)
                    ba = ctrl_summary.get('block_ack_responses', 0)
                    print(f"    Control Frames: RTS={rts:,}  CTS={cts:,}  ACK={ack:,}  PS-Poll={psp:,}  BAR={bar:,}  BA={ba:,}")
                    if rts > 0:
                        ratio = cts / rts
                        status = "OK" if ratio > 0.7 else ("Warning" if ratio > 0.3 else "HIDDEN NODE")
                        print(f"    RTS/CTS Ratio: {ratio*100:.1f}% [{status}]")
                    max_nav = ctrl_summary.get('max_duration_us', 0)
                    if max_nav > 0:
                        print(f"    NAV Duration: avg={ctrl_summary.get('avg_duration_us',0):.0f}us  max={max_nav:,}us")
                ctrl_issues = data.get('issues', [])
                for issue in ctrl_issues:
                    if isinstance(issue, dict):
                        print(f"      [{issue.get('severity','?').upper()}] {issue.get('category','')} — {issue.get('issue','')}")
                        if issue.get('remediation'):
                            print(f"           Fix: {issue['remediation'][:120]}{'...' if len(issue['remediation'])>120 else ''}")

            # Power Save Issues detail
            elif name == 'power_save_issues':
                ps_summary = data.get('power_save_summary', {})
                if ps_summary:
                    null_total = ps_summary.get('total_null_frames', 0)
                    real_data = ps_summary.get('real_data_frames', 0)
                    null_ratio = ps_summary.get('null_to_data_ratio', 0)
                    print(f"    Null/QoS-Null: {null_total:,} frames  |  Real Data: {real_data:,} frames  |  Ratio: {null_ratio*100:.1f}%")
                    top_null = ps_summary.get('top_null_senders', {})
                    if top_null:
                        print("    Top Null Frame Senders:")
                        for mac, cnt in sorted(top_null.items(), key=lambda x: x[1], reverse=True)[:5]:
                            print(f"        {mac}: {cnt:,} null frames")
                    pm_trans = ps_summary.get('pm_transitions_by_client', {})
                    if pm_trans:
                        print("    Power-Save Transitions:")
                        for mac, st in list(pm_trans.items())[:5]:
                            tr = st.get('transitions', 0)
                            total = st.get('total_frames', 0)
                            rate = tr / max(total, 1)
                            print(f"        {mac}: {tr:,} transitions ({rate*100:.1f}% of {total:,} frames)")
                ps_issues = data.get('issues', [])
                for issue in ps_issues:
                    if isinstance(issue, dict):
                        print(f"      [{issue.get('severity','?').upper()}] {issue.get('category','')} — {issue.get('issue','')}")
                        if issue.get('remediation'):
                            print(f"           Fix: {issue['remediation'][:120]}{'...' if len(issue['remediation'])>120 else ''}")

            # Connection Delay Analysis detail
            elif name == 'connection_delays':
                delay_analyses = data.get('delay_analyses', [])
                for analysis in delay_analyses:
                    client = analysis.get('client', 'unknown')
                    delay_s = analysis.get('delay_seconds', 0)
                    ap = analysis.get('ap_bssid', 'unknown')
                    bands = analysis.get('bands_scanned', [])
                    channels = analysis.get('channels_scanned', [])
                    print(f"\n    Client: {client} → AP: {ap}")
                    print(f"    Delay: {delay_s:.1f}s (frame {analysis.get('first_probe_response_frame','')} → frame {analysis.get('first_auth_frame','')})")
                    print(f"    Bands scanned: {', '.join(bands)}  |  Channels: {', '.join(str(c) for c in channels)}")
                    print(f"    Probes during delay: {analysis.get('total_probes_in_delay', 0)}  |  Responses: {analysis.get('total_responses_in_delay', 0)}")

                    # Channel breakdown
                    ch_detail = analysis.get('channel_detail', {})
                    if ch_detail:
                        print("    Channel Breakdown:")
                        for ch_label, info in ch_detail.items():
                            sig_str = f"signal: {info['signal_avg']:.0f} dBm avg" if info.get('signal_avg') else "no signal data"
                            resp_str = f"{info['responses_received']}/{info['probes_sent']} answered"
                            print(f"        {ch_label}: {resp_str}, {sig_str}")

                    # Reasons
                    reasons = analysis.get('reasons', [])
                    if reasons:
                        print("    Delay Reasons:")
                        for r in reasons:
                            sev = r.get('severity', 'info').upper()
                            print(f"      [{sev}] {r.get('reason', '').replace('_', ' ').title()}")
                            print(f"           {r.get('description', '')[:150]}")
                            if r.get('remediation'):
                                print(f"           Fix: {r['remediation'][:120]}{'...' if len(r['remediation'])>120 else ''}")

            # Connection failure detailed flows
            elif name == 'connection_failures':
                conn_flows = data.get('connection_flows', {})
                if conn_flows:
                    print("\n    === CONNECTION FLOW ANALYSIS ===")
                    for client, sessions in conn_flows.items():
                        print(f"\n    Client: {client}")
                        for i, session in enumerate(sessions, 1):
                            auth_proto = session.get('auth_protocol', session.get('diagnosis', {}).get('auth_protocol', ''))
                            diag = session.get('diagnosis', {})
                            phase = diag.get('phase', '')
                            print(f"      Session #{i} [{auth_proto}]{' — ' + phase if phase else ''}")
                            for evt in session.get('events', []):
                                step = evt.get('step', '')
                                note = evt.get('note', '')
                                frame = evt.get('frame', '')
                                sig = evt.get('signal_dbm')
                                direction = evt.get('direction', '')
                                sig_str = f" [{sig} dBm]" if sig else ""
                                print(f"        Frame {frame:>5} | {direction:<12} | {step}{sig_str}")
                                if note and evt.get('category') in ('failure', 'disconnect'):
                                    print(f"                       → {note[:100]}")
                            # Print evidence if available
                            evidence = diag.get('evidence', [])
                            if evidence:
                                print("      Evidence:")
                                for ev in evidence[:5]:
                                    print(f"        • {ev[:120]}")
                            action = diag.get('recommended_action', '')
                            if action:
                                print(f"      Recommended Action: {action[:150]}")
                            # Print PMKID analysis if present
                            pmkid_info = diag.get('pmkid_analysis', {})
                            if pmkid_info:
                                print("      PMKID Analysis:")
                                print(f"        Auth method used: {pmkid_info.get('auth_method_used', 'N/A')}")
                                print(f"        Expected for WPA3: {pmkid_info.get('expected_for_wpa3', 'N/A')}")
                                print(f"        Likely cause: {pmkid_info.get('likely_cause', 'N/A')}")
    else:
        print("\nNo issues detected.")


if __name__ == '__main__':
    main()
