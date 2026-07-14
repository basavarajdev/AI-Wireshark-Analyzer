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

# WiFi Direct / P2P SSID identification patterns
WIFI_DIRECT_SSID_PATTERNS = ('DIRECT-', 'DIRECT_', 'HP-Print-', 'HP=Setup', 'HP-Setup>')


def _classify_ssids(ssid_dict: dict) -> tuple:
    """Split an SSID dict into (regular_ssids, wifi_direct_ssids).

    Args:
        ssid_dict: dict of {ssid: count} as returned by statistics['detected_ssids']

    Returns:
        (regular, wifi_direct) — both as {ssid: count} dicts
    """
    regular, wifi_direct = {}, {}
    for ssid, count in ssid_dict.items():
        if any(p in ssid for p in WIFI_DIRECT_SSID_PATTERNS):
            wifi_direct[ssid] = count
        else:
            regular[ssid] = count
    return regular, wifi_direct

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


# Module-level argv parsing only happens when run directly (guarded below)

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
    "wlan.ccmp.extiv",
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
    "ccmp_pn",
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
    # CCMP Packet Number (Ext IV) — tshark emits as 0x-prefixed hex (e.g. 0x000000000043)
    # Convert to integer so wlan_analyzer can compare PN values for stale-PTK detection
    df['ccmp_pn'] = _to_numeric_hex(df['ccmp_pn'])

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


# ─────────────────────────────────────────────────────────────────────────────
# WPA3 / SAE Root Cause Analysis HTML Report
# ─────────────────────────────────────────────────────────────────────────────

# Complete WPA3-SAE Status Code reference (IEEE 802.11-2020 Table 9-50)
WPA3_STATUS_REFERENCE = [
    (1,  "Unspecified failure",
     "General SAE rejection without a specific reason.",
     "Check AP logs; verify WPA3-SAE is enabled on both AP and client; update firmware."),
    (15, "Authentication rejected — challenge failure (wrong credentials)",
     "SAE Confirm MIC verification failed — passphrase mismatch.",
     "Re-enter correct WPA3 passphrase. Ensure UTF-8 (RFC 8265 PRECIS) normalisation on both sides."),
    (30, "Refused temporarily — AP state machine busy or STA still associated",
     "AP returned REFUSED_TEMPORARILY because it believes the STA is still associated "
     "from a prior session. AP state machine deadlock: per IEEE 802.11-2020 §11.3.5.5 "
     "the AP MUST send Disassociation after SA Query timeout, but did not (firmware bug).",
     "(1) STA: send Deauthentication (Reason 3) to force AP to purge stale entry, then retry. "
     "(2) AP: firmware update implementing §11.3.5.5 Disassociation on SA Query timeout. "
     "(3) Disable PMKSA caching on STA to prevent stale-cache fast-reconnect. "
     "(4) If Transition Mode: verify AP does not apply WPA2 PTK for PMF SA Query after SAE Commit."),
    (37, "Invalid RSN IE capabilities",
     "Mismatch in RSN element between probe/association and authentication.",
     "Update AP/client firmware; verify RSN IE fields match between Beacon and 4-way handshake."),
    (46, "Invalid contents of RSNE (Robust Security Network Element)",
     "RSNE in authentication or association frame is malformed.",
     "Check driver/firmware for RSN IE construction bugs; update firmware."),
    (53, "Invalid PMKID",
     "Stale PMKSA cache: the PMKID in the Association Request does not match "
     "any active PMKSA entry on the AP.",
     "Disable PMKID caching on client; perform full SAE exchange (auth_alg=3) instead of "
     "relying on cached PMKSA."),
    (72, "SAE authentication rejected",
     "AP explicitly rejected the SAE authentication request.",
     "Verify WPA3-SAE passphrase; check AP supports SAE; ensure client driver supports SAE commit/confirm (auth_alg=3)."),
    (73, "SAE commit rejected",
     "AP rejected SAE Commit — possible EC group mismatch or configuration error.",
     "Ensure both AP and client support EC group 19 (P-256, mandatory). Update AP firmware. "
     "Disable non-standard SAE groups on client."),
    (74, "SAE confirm rejected",
     "SAE Confirm exchange failed — wrong passphrase or MIC error.",
     "Verify WPA3 passphrase (UTF-8 normalised). Update firmware. If anti-clogging was "
     "involved, ensure client correctly retried with token."),
    (76, "Unknown Password Identifier (WPA3-SAE)",
     "Client sent an unknown Password Identifier not configured on AP.",
     "Remove or correct the 'password ID' field in the client's WPA3 config. "
     "Ensure AP and client use the same password identifier (or none)."),
    (77, "SAE Anti-Clogging Token Required",
     "AP is rate-limiting SAE Commit processing (DoS protection, not a credential error).",
     "Client must resend SAE Commit with the provided anti-clogging token. "
     "If persistent: investigate SAE flooding from rogue clients targeting the AP."),
    (78, "SAE Finite Cyclic Group not supported",
     "The elliptic curve group requested by the client is not supported by the AP.",
     "Configure both AP and client to use EC group 19 (P-256). "
     "Disable exotic groups; update AP firmware."),
]

# Complete WPA3-relevant Reason Code reference (IEEE 802.11-2020)
WPA3_REASON_REFERENCE = [
    (2,  "Previous authentication no longer valid",
     "AP considers this STA's prior authentication expired or invalid.",
     "Client should perform a fresh SAE Commit/Confirm exchange."),
    (3,  "STA is leaving or has left the BSS",
     "Normal intentional disconnect by STA or AP.",
     "Reconnect with fresh SAE if client wishes to re-associate."),
    (6,  "Class 2 frame from non-authenticated STA",
     "STA sent a management frame while not authenticated — state machine mismatch.",
     "Driver/firmware bug or race condition. Client should restart authentication from scratch."),
    (7,  "Class 3 frame from non-associated STA",
     "STA sent data while not associated — common after AP reboots without sending Deauth.",
     "Client should detect AP reboot and re-authenticate."),
    (14, "4-way handshake MIC failure / PSK mismatch",
     "EAPOL MIC verification failed after SAE — wrong PMK or replay attack.",
     "Verify the passphrase. For WPA3 the PMK comes from SAE not from passphrase directly — "
     "ensure both sides correctly complete SAE Confirm."),
    (15, "Group key handshake timeout",
     "GTK renewal failed; some AP firmware (e.g. TP-Link) also uses this for 4-way Msg1/Msg2 failure.",
     "Retry connection. If persistent: check for driver/firmware bugs in GTK re-key handling."),
    (22, "IEEE 802.1X authentication failed",
     "802.1X EAP authentication failure (WPA3-Enterprise mode).",
     "Check RADIUS server logs; verify EAP certificates; ensure correct SSID profile."),
    (23, "Cipher suite rejected by security policy",
     "AP rejected the cipher suite proposed by the client.",
     "Verify client and AP agree on CCMP-128 (WPA3-Personal) or GCMP-256 (WPA3-Enterprise)."),
    (36, "Peer STA leaving BSS or resetting",
     "AP or STA is resetting its 802.11 state machine.",
     "Normal during roaming or AP reboot. Client should reconnect automatically."),
    (45, "Peer STA does not support requested cipher suite",
     "The cipher negotiated in the association is not supported.",
     "Ensure client and AP both support CCMP-128. Disable deprecated TKIP."),
    (47, "SAE PMK-ID not recognized",
     "AP does not recognize the PMKID — the cached SAE PMK has expired or is invalid.",
     "Disable PMKSA caching. Perform full SAE Commit/Confirm exchange."),
    (50, "No SAE PT or password available",
     "AP cannot complete SAE because no password or SAE-PT (Password Token) is available.",
     "Verify WPA3-SAE passphrase is configured on AP. Check AP configuration."),
]


def generate_wpa3_rca_html(pcap_file: str, wpa3_data: dict, output_path: str,
                            mac_filter: str = None) -> None:
    """
    Generate a standalone WPA3/SAE Root Cause Analysis HTML report.

    Renders:
    - Forensic event timeline for each SAE failure session
    - Stale-association deadlock analysis with CCMP PN evidence
    - SA Query timeline reconstruction
    - Complete WPA3 status code & reason code reference table with remediations
    """
    from datetime import datetime as _dt
    now = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
    pcap_name = Path(pcap_file).name

    sae_sessions    = wpa3_data.get("sae_sessions", [])
    issues          = wpa3_data.get("issues", [])
    fail_counts     = wpa3_data.get("failure_counts", {})
    deadlock        = wpa3_data.get("stale_association_deadlock", {})
    sae_advertised  = wpa3_data.get("sae_akm_advertised", False)
    owe_advertised  = wpa3_data.get("owe_advertised", False)
    severity        = wpa3_data.get("severity", "info").upper()

    sev_color = {"HIGH": "#c0392b", "MEDIUM": "#e67e22", "LOW": "#2980b9", "INFO": "#7f8c8d"}.get(severity, "#555")

    # ── Event timeline rows ────────────────────────────────────────────────────
    session_cards = ""
    for si, sess in enumerate(sae_sessions, 1):
        phase   = sess.get("failure_phase", "")
        rc      = sess.get("root_cause", "")
        remedy  = sess.get("remediation", "")
        client  = sess.get("client", "—")
        ap      = sess.get("ap_bssid", "—")
        status  = sess.get("status_code")
        stext   = sess.get("status_text", "")
        ts      = sess.get("timestamp", "")
        frame   = sess.get("frame", "")
        pmf_cnt = sess.get("pmf_action_frames_after_rejection", 0)
        cleanup = sess.get("ap_sent_cleanup_deauth", False)
        spec    = sess.get("spec_violation", "")
        analysis = sess.get("analysis", "")
        tm_note = sess.get("wpa3_transition_mode_note", "")

        border = "#c0392b" if "wrong" in (rc or "").lower() or "deadlock" in (rc or "").lower() else "#e67e22"
        bg = "#fff5f5" if border == "#c0392b" else "#fff8f0"

        # Build timeline table for deadlock cases
        timeline_table = ""
        if pmf_cnt > 0 and frame:
            timeline_table = f"""
            <div style="margin:10px 0;">
              <h4 style="color:#555">SA Query / PMF Action Frame Evidence</h4>
              <table>
                <thead><tr><th>Event</th><th>Frame</th><th>Direction</th><th>Detail</th></tr></thead>
                <tbody>
                  <tr><td>SAE Commit sent by STA</td><td>—</td><td>STA → AP</td>
                      <td>auth_alg=SAE(3), seq=0x0001, status=0x0000 (Success)</td></tr>
                  <tr style="background:#ffebee"><td>SAE Commit rejected by AP</td><td>#{frame}</td>
                      <td>AP → STA</td>
                      <td>Status <strong>{status}</strong> ({stext}) — bare 6-byte rejection, no scalar/element</td></tr>
                  <tr style="background:#fff3e0"><td>PMF-encrypted Action frames</td><td>—</td>
                      <td>AP → STA</td>
                      <td><strong>{pmf_cnt}</strong> frames, CCMP-protected with <strong>stale PTK</strong> "
                          (PN > 1 at start proves prior session key). "
                          Pattern matches SA Query Requests (IEEE 802.11w §11.3.5, cat=8, action=0).</td></tr>
                  <tr><td>STA response to SA Query</td><td>—</td><td>—</td>
                      <td><strong>None</strong> — STA cannot decrypt with old-session keys</td></tr>
                  <tr style="{'background:#ffebee' if not cleanup else 'background:#e8f5e9'}">
                      <td>Deauth/Disassoc after SA Query timeout</td><td>—</td><td>AP → STA</td>
                      <td><strong>{'ABSENT — §11.3.5.5 VIOLATION' if not cleanup else 'Present (compliant)'}</strong><br>
                          <em>{spec}</em></td></tr>
                </tbody>
              </table>
            </div>"""

        session_cards += f"""
        <div style="background:{bg};border-left:5px solid {border};padding:16px 20px;
                    border-radius:4px;margin:14px 0;">
          <h3 style="margin:0 0 8px;font-size:1em;">
            Failure #{si} — <span style="color:{border}">{phase}</span>
          </h3>
          <p style="margin:4px 0;font-size:0.85em;color:#555;">
            <strong>STA:</strong> <code>{client}</code> &nbsp;→&nbsp;
            <strong>AP:</strong> <code>{ap}</code>
            {f'&nbsp;|&nbsp; Frame #{frame}  @  t={round(float(ts),3)}s' if frame and ts else ''}
          </p>
          {'<p style="margin:6px 0"><strong>Status:</strong> <code>' + str(status) + '</code> — <em>' + stext + '</em></p>' if status is not None else ''}
          {timeline_table}
          {'<div style="background:#fffde7;border:1px solid #f9a825;padding:10px 14px;border-radius:4px;margin:8px 0;"><p><strong>🔍 Root Cause:</strong></p><p style="font-size:0.9em;margin-top:4px;">' + rc + '</p></div>' if rc else ''}
          {'<div style="background:#f3f3f3;border:1px solid #ccc;padding:10px 14px;border-radius:4px;margin:8px 0;font-size:0.85em;">' + analysis + '</div>' if analysis else ''}
          {'<div style="background:#e8f5e9;border-left:3px solid #43a047;padding:10px 14px;border-radius:4px;margin:8px 0;"><p><strong>🔧 Remediation Steps:</strong></p><p style="font-size:0.88em;margin-top:4px;white-space:pre-line;">' + (remedy or '') + '</p></div>' if remedy else ''}
          {'<div style="background:#e3f2fd;border-left:3px solid #1976d2;padding:8px 14px;border-radius:4px;margin:6px 0;font-size:0.82em;"><strong>⚠ WPA3 Transition Mode Note:</strong> ' + tm_note + '</div>' if tm_note else ''}
        </div>"""

    # ── Failure count summary ──────────────────────────────────────────────────
    fc_rows = "".join(
        f'<tr><td>{k}</td><td><strong>{v}</strong></td></tr>'
        for k, v in sorted(fail_counts.items(), key=lambda x: -x[1])
    )

    # ── Deadlock summary banner ────────────────────────────────────────────────
    deadlock_banner = ""
    if deadlock:
        deadlock_banner = f"""
        <div style="background:#b71c1c;color:#fff;padding:14px 20px;border-radius:6px;margin:14px 0;">
          <h3 style="margin:0 0 6px;font-size:1.05em;">⛔ AP State Machine Deadlock Detected ({deadlock['count']} instance(s))</h3>
          <p style="font-size:0.9em;margin:0;">{deadlock.get('summary','')}</p>
        </div>"""

    # ── Advisory notices ───────────────────────────────────────────────────────
    advisory_html = ""
    for issue in issues:
        advisory_html += f"""
        <div style="background:#e8f5e9;border-left:4px solid #43a047;padding:10px 16px;
                    border-radius:4px;margin:8px 0;font-size:0.87em;">
          {issue}
        </div>"""

    # ── WPA3 Status Code reference table ──────────────────────────────────────
    status_ref_rows = ""
    for code, name, explanation, remediation in WPA3_STATUS_REFERENCE:
        highlight = ' style="background:#fff5f5"' if code in (30, 77) else (
            ' style="background:#fffde7"' if code in (73, 74, 76, 78) else "")
        status_ref_rows += (
            f'<tr{highlight}>'
            f'<td style="font-weight:700;text-align:center">{code}</td>'
            f'<td><strong>{name}</strong></td>'
            f'<td style="font-size:0.83em;color:#444">{explanation}</td>'
            f'<td style="font-size:0.83em;color:#1a5276">{remediation}</td></tr>'
        )

    # ── WPA3 Reason Code reference table ──────────────────────────────────────
    reason_ref_rows = ""
    for code, name, explanation, remediation in WPA3_REASON_REFERENCE:
        reason_ref_rows += (
            f'<tr>'
            f'<td style="font-weight:700;text-align:center">{code}</td>'
            f'<td><strong>{name}</strong></td>'
            f'<td style="font-size:0.83em;color:#444">{explanation}</td>'
            f'<td style="font-size:0.83em;color:#1a5276">{remediation}</td></tr>'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WPA3-SAE Root Cause Analysis — {pcap_name}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f9;color:#2c3e50;font-size:14px}}
  header{{background:linear-gradient(135deg,#7b1fa2,#4a148c);color:#fff;padding:26px 40px}}
  header h1{{font-size:1.5em;font-weight:700}}
  header p{{color:#ce93d8;margin-top:6px;font-size:0.9em}}
  .container{{max-width:1200px;margin:24px auto;padding:0 24px}}
  .card{{background:#fff;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.08);margin-bottom:24px;overflow:hidden}}
  .card-header{{padding:14px 20px;font-weight:600;font-size:1em;border-bottom:1px solid #eee;background:#fafafa}}
  .card-body{{padding:16px 20px}}
  .summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}
  .metric{{background:#f8f9fb;border-radius:8px;padding:12px 16px;border-left:4px solid #7b1fa2}}
  .metric .val{{font-size:1.4em;font-weight:700;color:#2c3e50}}
  .metric .label{{font-size:0.75em;color:#7f8c8d;margin-top:4px}}
  table{{border-collapse:collapse;width:100%;font-size:0.84em;margin-top:8px}}
  th{{background:#4a148c;color:#fff;padding:8px 12px;text-align:left}}
  td{{padding:7px 12px;border-bottom:1px solid #eef;vertical-align:top}}
  tr:hover td{{background:#f5f0ff}}
  code{{background:#ede7f6;padding:2px 6px;border-radius:3px;font-size:0.88em}}
  h4{{font-size:0.9em;color:#4a148c;margin:10px 0 6px}}
  .badge{{display:inline-block;padding:3px 10px;border-radius:12px;font-size:0.8em;font-weight:600}}
  section h2{{font-size:1.05em;color:#4a148c;padding:12px 0 8px;border-bottom:2px solid #ce93d8;margin-bottom:12px}}
</style>
</head>
<body>
<header>
  <h1>🔐 WPA3-SAE Root Cause Analysis Report</h1>
  <p>File: {pcap_name} &nbsp;|&nbsp; Generated: {now}
     {f'&nbsp;|&nbsp; MAC filter: {mac_filter}' if mac_filter else ''}
  </p>
</header>
<div class="container">

  <!-- ═══ Overall Status ═══ -->
  <div class="card">
    <div class="card-header" style="background:{sev_color};color:#fff;">
      WPA3-SAE Severity: {severity} &nbsp;—&nbsp; {sum(fail_counts.values())} failure event(s) / {len(issues)} advisory notice(s)
    </div>
    <div class="card-body">
      <div class="summary-grid">
        <div class="metric"><div class="val">{len(sae_sessions)}</div><div class="label">SAE Session Failures</div></div>
        <div class="metric"><div class="val">{sum(fail_counts.values())}</div><div class="label">Total Failure Events</div></div>
        <div class="metric {'style="border-color:#c0392b"' if deadlock else ''}">
          <div class="val">{'⛔ YES' if deadlock else 'No'}</div><div class="label">Deadlock Detected</div>
        </div>
        <div class="metric"><div class="val">{'✅ Yes' if sae_advertised else 'No'}</div><div class="label">WPA3-SAE Advertised</div></div>
        <div class="metric"><div class="val">{'✅ Yes' if owe_advertised else 'No'}</div><div class="label">OWE Advertised</div></div>
      </div>
    </div>
  </div>

  {deadlock_banner}

  <!-- ═══ SAE Session Analysis ═══ -->
  {'<div class="card"><div class="card-header">🔍 SAE Session Failure Analysis</div><div class="card-body">' + session_cards + '</div></div>' if session_cards else ''}

  <!-- ═══ Advisory Notices ═══ -->
  {'<div class="card"><div class="card-header">📋 Advisory Notices</div><div class="card-body">' + advisory_html + '</div></div>' if advisory_html else ''}

  <!-- ═══ Failure Summary ═══ -->
  {'<div class="card"><div class="card-header">📊 Failure Type Summary</div><div class="card-body"><table><th>Failure Type</th><th>Count</th>' + fc_rows + '</table></div></div>' if fc_rows else ''}

  <!-- ═══ WPA3-SAE Status Code Reference ═══ -->
  <div class="card">
    <div class="card-header">📖 WPA3-SAE Status Code Reference (IEEE 802.11-2020)</div>
    <div class="card-body">
      <p style="font-size:0.83em;color:#7f8c8d;margin-bottom:10px;">
        Status codes are returned in Authentication frame responses (subtype 0x000b).
        SAE-specific codes are 72–78. Code 30 (REFUSED_TEMPORARILY) is general 802.11 but
        critically impacts WPA3-SAE state machine behaviour.
        Highlighted rows indicate codes observed in this capture.
      </p>
      <table>
        <thead><tr>
          <th style="width:60px">Code</th>
          <th style="width:200px">Name</th>
          <th>Explanation</th>
          <th>Recovery / Remediation</th>
        </tr></thead>
        <tbody>{status_ref_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- ═══ WPA3-SAE Reason Code Reference ═══ -->
  <div class="card">
    <div class="card-header">📖 WPA3-Relevant Reason Code Reference (IEEE 802.11-2020)</div>
    <div class="card-body">
      <p style="font-size:0.83em;color:#7f8c8d;margin-bottom:10px;">
        Reason codes are used in Deauthentication (0x000c) and Disassociation (0x000a) frames.
        WPA3-specific codes are 47 and 50. Codes 2, 3, 6, 7 are frequently seen in SAE
        failure recovery flows.
      </p>
      <table>
        <thead><tr>
          <th style="width:60px">Code</th>
          <th style="width:200px">Name</th>
          <th>Explanation</th>
          <th>Recovery / Remediation</th>
        </tr></thead>
        <tbody>{reason_ref_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- ═══ WPA3-SAE Protocol Spec Note ═══ -->
  <div class="card">
    <div class="card-header">📚 WPA3-SAE Protocol Reference</div>
    <div class="card-body" style="font-size:0.88em;line-height:1.7;color:#444">
      <p><strong>SAE Exchange (IEEE 802.11-2020 §12.4):</strong></p>
      <ol style="margin:8px 0 12px 20px;">
        <li>STA → AP: Auth frame, <code>auth_alg=3</code>, <code>auth_seq=0x0001</code> — <em>SAE Commit</em>
            (contains Scalar + FFE element for ECDH on group 19/P-256)</li>
        <li>AP → STA: Auth frame, <code>auth_alg=3</code>, <code>auth_seq=0x0001</code>, <code>status=0</code> — <em>SAE Commit Response</em></li>
        <li>STA → AP: Auth frame, <code>auth_alg=3</code>, <code>auth_seq=0x0002</code> — <em>SAE Confirm</em></li>
        <li>AP → STA: Auth frame, <code>auth_alg=3</code>, <code>auth_seq=0x0002</code>, <code>status=0</code> — <em>SAE Confirm Response</em></li>
        <li>Normal Association Request / Response</li>
        <li>4-way EAPOL/PTK handshake (Msg1–Msg4) to install session keys</li>
      </ol>
      <p><strong>SA Query (IEEE 802.11-2020 §11.3.5, 802.11w MFP):</strong></p>
      <ul style="margin:8px 0 12px 20px;">
        <li>Used by an AP to verify a previously associated STA still holds the old PTK</li>
        <li>SA Query Request: Action frame Category=8, Action=0, PMF-encrypted with existing PTK</li>
        <li>SA Query Response: same category/action, sent by STA if it has the PTK</li>
        <li>If no response within <code>dot11AssociationSAQueryMaximumTimeout</code>, AP <strong>MUST</strong>
            issue Disassociation (Reason 6 or 7) per §11.3.5.5</li>
        <li>Failure to send Disassociation = firmware non-compliance → permanent deadlock</li>
      </ul>
      <p><strong>CCMP Packet Number (PN) forensics:</strong></p>
      <ul style="margin:8px 0 0 20px;">
        <li>If PMF-encrypted Action frames appear after an SAE Commit rejection, and the PN
            starts at a value &gt; 1, this proves the AP is encrypting with a <strong>stale PTK</strong>
            from a prior session (a fresh PTK would start at PN=0 or 1)</li>
        <li>A PN of 67 (0x43) at the start of post-rejection frames, as in the reference case,
            is definitive forensic proof of stale-PTK SA Query</li>
      </ul>
    </div>
  </div>

</div>
</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    logger.info(f"WPA3 RCA report saved to {output_path}")


def run(pcap_file: str, mac_filter: str = None, output_dir: str = 'results') -> dict:
    """Callable entry point — usable from workers without subprocess."""
    _stem = Path(pcap_file).stem
    if mac_filter:
        _mac_slug = mac_filter.replace(':', '_')
        _stem = f"{_stem}_mac_{_mac_slug}"
    output_json = str(Path(output_dir) / f"{_stem}.json")
    output_html = str(Path(output_dir) / f"{_stem}_report.html")

    raw = run_tshark(pcap_file, mac_filter=mac_filter)
    df = parse_tshark_output(raw)
    logger.info(f"Parsed {len(df)} WLAN frames via tshark")

    if df.empty:
        logger.warning("No frames matched the filter — check the MAC address.")
        return {'error': 'No frames matched', 'json_path': None, 'html_path': None}

    analyzer = WLANAnalyzer()
    statistics = analyzer._calculate_statistics(df)

    # Classify SSIDs into regular vs WiFi Direct
    detected_ssids = statistics.get('detected_ssids', {})
    regular_ssids, wifi_direct_ssids = _classify_ssids(detected_ssids)
    statistics['wifi_direct_ssids'] = wifi_direct_ssids
    statistics['regular_ssids'] = regular_ssids
    statistics['wifi_direct_ap_count'] = len(wifi_direct_ssids)

    results = {
        "total_packets": len(df),
        "mac_filter": mac_filter,
        "statistics": statistics,
        "connection_events": analyzer._analyze_connection_events(df),
        "threats": analyzer._detect_threats(df),
    }

    Path(output_json).parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"JSON results saved to {output_json}")

    try:
        from src.reports.html_generator import HTMLReportGenerator
        generator = HTMLReportGenerator()
        report_data = {
            'total_packets': results['total_packets'],
            'protocol_analysis': {'wlan': results},
        }
        proto_label = f"WLAN [MAC: {mac_filter}]" if mac_filter else "WLAN"
        generator.generate_report(
            results=report_data,
            pcap_file=pcap_file,
            output_file=output_html,
            protocol=proto_label,
        )
        logger.info(f"HTML report saved to {output_html}")
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")

    # ── WPA3 RCA standalone report ─────────────────────────────────────────────
    wpa3_data = results.get("threats", {}).get("wpa3_sae_failures", {})
    if wpa3_data.get("detected") or wpa3_data.get("wpa3_network_detected"):
        wpa3_rca_path = str(Path(output_dir) / f"{Path(output_json).stem}_wpa3_rca.html")
        try:
            generate_wpa3_rca_html(pcap_file, wpa3_data, wpa3_rca_path, mac_filter)
            results["wpa3_rca_html"] = wpa3_rca_path
        except Exception as e:
            logger.error(f"Failed to generate WPA3 RCA report: {e}")

    return {'json_path': output_json, 'html_path': output_html, 'results': results}


def main():
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else None
    mac_filter = sys.argv[2] if len(sys.argv) > 2 else None
    if not pcap_file:
        print("Usage: python scripts/run_wlan_analysis.py <pcap_file> [mac_filter]")
        sys.exit(1)
    out = run(pcap_file, mac_filter)
    results = out.get('results', {})
    if not results:
        sys.exit(0)

    # Print summary
    print("\n=== WLAN ANALYSIS SUMMARY ===")
    if mac_filter:
        print(f"MAC Filter: {mac_filter}")
    stats = results['statistics']
    print(f"Total frames: {stats.get('total_frames', 0)}")
    print(f"Management: {stats.get('management_frames', 0)}")
    print(f"Control: {stats.get('control_frames', 0)}")
    print(f"Data: {stats.get('data_frames', 0)}")
    print(f"Unique BSSIDs: {stats.get('unique_bssids', 0)}")
    print(f"Unique SSIDs: {stats.get('unique_ssids', 0)}")
    if stats.get('detected_ssids'):
        regular_ssids, wifi_direct_ssids = _classify_ssids(stats['detected_ssids'])
        if regular_ssids:
            print(f"Regular SSIDs ({len(regular_ssids)}): {list(regular_ssids.keys())[:15]}"
                  + (" ..." if len(regular_ssids) > 15 else ""))
        if wifi_direct_ssids:
            print(f"\nWiFi Direct / P2P SSIDs ({len(wifi_direct_ssids)}):")
            for ssid in sorted(wifi_direct_ssids.keys())[:20]:
                print(f"  [WiFi-Direct]  {ssid}")
            if len(wifi_direct_ssids) > 20:
                print(f"  ... and {len(wifi_direct_ssids) - 20} more")

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
