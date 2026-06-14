"""
WPA/WPA2/WPA3 Wireless Capture Decryption Module
==================================================
Decrypts encrypted 802.11 captures using tshark's built-in WPA decryption engine.

Supported key types:
  wpa-pwd  — WPA/WPA2/WPA3-SAE passphrase + SSID  (most common home/office use)
  wpa-psk  — WPA2 Pre-Shared Key (64-char hex PMK, no SSID needed)

Decryption prerequisites:
  - tshark (Wireshark CLI) must be installed and in PATH
  - The capture must include a full 4-way EAPOL handshake (msg 1-4) for WPA/WPA2
  - For WPA3-SAE the capture must contain the SAE commit + confirm exchange
    followed by the EAPOL 4-way handshake

Post-decryption analysis extracts:
  - DNS queries / top domains
  - Unencrypted HTTP requests
  - IP endpoint traffic matrix (top talkers)
  - Protocol hierarchy / distribution
  - TCP/UDP port summary with service names
  - Security observations (plaintext protocols, high entropy endpoints, etc.)
"""

import subprocess
import json
import tempfile
import html as html_module
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Any

from loguru import logger


# ── Key-type registry ──────────────────────────────────────────────────────────
KEY_TYPES: Dict[str, str] = {
    "wpa-pwd": "WPA/WPA2/WPA3-SAE Passphrase",
    "wpa-psk": "WPA2 PMK (64-char hex Pre-Shared Key)",
}

# Well-known port → service name mapping used in reports
PORT_NAMES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP-srv", 68: "DHCP-cli", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP/TLS", 853: "DNS-TLS", 993: "IMAPS", 995: "POP3S",
    1900: "SSDP/UPnP", 3389: "RDP", 5353: "mDNS",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
}


# ──────────────────────────────────────────────────────────────────────────────
# Helper: build the tshark uat:80211_keys option string
# ──────────────────────────────────────────────────────────────────────────────
def _build_tshark_key_arg(key_type: str, password: str, ssid: str = "") -> str:
    """Return the tshark ``-o`` argument for 802.11 decryption.

    wpa-pwd format:  ``uat:80211_keys:"wpa-pwd","<password>:<ssid>"``
    wpa-psk format:  ``uat:80211_keys:"wpa-psk","<64-hex-pmk>"``
    """
    if key_type == "wpa-pwd":
        key_value = f"{password}:{ssid}" if ssid else password
    elif key_type == "wpa-psk":
        key_value = password
    else:
        raise ValueError(f"Unsupported key_type: {key_type!r}")

    return f'uat:80211_keys:"{key_type}","{key_value}"'


# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Handshake detection
# ──────────────────────────────────────────────────────────────────────────────
def check_handshake_present(pcap_file: str) -> Dict[str, Any]:
    """Examine the capture for 4-way EAPOL and SAE (WPA3) handshake frames.

    Returns a dict with:
      eapol_frames          — total EAPOL frames
      eapol_messages_found  — set of EAPOL key message numbers (1-4)
      has_full_4way_handshake
      sae_frames            — SAE authentication frames
      has_sae
    """
    # ── EAPOL 4-way handshake ────────────────────────────────────────────────
    cmd_eapol = [
        "tshark", "-r", pcap_file,
        "-Y", "eapol",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "wlan_rsna_eapol.keydes.msgnr",
        "-E", "separator=|",
        "-E", "header=n",
    ]
    proc = subprocess.run(cmd_eapol, capture_output=True, text=True, timeout=60)

    eapol_frames = []
    for line in proc.stdout.strip().splitlines():
        if line.strip():
            parts = line.split("|")
            eapol_frames.append({
                "frame": parts[0].strip(),
                "msg_nr": parts[1].strip() if len(parts) > 1 else "",
            })

    msg_nrs = {f["msg_nr"] for f in eapol_frames if f["msg_nr"]}
    has_full = {"1", "2", "3", "4"}.issubset(msg_nrs)

    # ── SAE (WPA3) frames ────────────────────────────────────────────────────
    cmd_sae = [
        "tshark", "-r", pcap_file,
        "-Y", "wlan.fixed.auth.alg == 3",   # algorithm 3 = SAE
        "-T", "fields",
        "-e", "frame.number",
        "-E", "header=n",
    ]
    proc_sae = subprocess.run(cmd_sae, capture_output=True, text=True, timeout=60)
    sae_frames = [l.strip() for l in proc_sae.stdout.strip().splitlines() if l.strip()]

    return {
        "eapol_frames": len(eapol_frames),
        "eapol_messages_found": sorted(msg_nrs),
        "has_full_4way_handshake": has_full,
        "has_partial_handshake": bool(msg_nrs),
        "sae_frames": len(sae_frames),
        "has_sae": bool(sae_frames),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Step 2: tshark decryption
# ──────────────────────────────────────────────────────────────────────────────
def decrypt_capture(
    pcap_file: str,
    key_type: str,
    password: str,
    ssid: str = "",
    output_pcap: Optional[str] = None,
) -> Dict[str, Any]:
    """Run tshark to produce a decrypted pcap from an encrypted 802.11 capture.

    Args:
        pcap_file:   Input encrypted PCAP path.
        key_type:    ``"wpa-pwd"`` or ``"wpa-psk"``.
        password:    Passphrase (wpa-pwd) or 64-char hex PMK (wpa-psk).
        ssid:        Network SSID — required for wpa-pwd, ignored for wpa-psk.
        output_pcap: Destination path.  Auto-generates a temp file when None.

    Returns:
        dict with decrypted_pcap path and decryption statistics.
    """
    pcap_path = Path(pcap_file)
    if not pcap_path.exists():
        return {"error": f"PCAP file not found: {pcap_file}"}

    # Auto-generate output path inside a temp directory
    if not output_pcap:
        tmp_dir = tempfile.mkdtemp(prefix="ai_wireshark_dec_")
        output_pcap = str(Path(tmp_dir) / f"decrypted_{pcap_path.name}")

    key_arg = _build_tshark_key_arg(key_type, password, ssid)

    cmd = [
        "tshark",
        "-r", str(pcap_file),
        "-o", "wlan.enable_decryption:TRUE",
        "-o", key_arg,
        "-w", output_pcap,
    ]

    logger.info(
        f"Decrypting {pcap_file!r} | key_type={key_type}"
        + (f" | SSID={ssid!r}" if ssid else "")
    )
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    out_path = Path(output_pcap)
    if not out_path.exists() or out_path.stat().st_size == 0:
        return {
            "error": (
                f"Decryption produced no output. "
                f"tshark stderr: {proc.stderr.strip()}"
            ),
            "decrypted_pcap": None,
        }

    # Compare protected frame counts before/after
    orig_total = _count_frames(pcap_file)
    dec_total = _count_frames(output_pcap)
    orig_unprotected = _count_frames(pcap_file, "wlan && !wlan.fc.protected")
    dec_unprotected = _count_frames(output_pcap, "wlan && !wlan.fc.protected")
    newly_decrypted = max(0, dec_unprotected - orig_unprotected)

    result: Dict[str, Any] = {
        "decrypted_pcap": output_pcap,
        "key_type": key_type,
        "ssid": ssid,
        "original_frames": orig_total,
        "decrypted_output_frames": dec_total,
        "newly_decrypted_frames": newly_decrypted,
        "decryption_success": newly_decrypted > 0,
        "stderr": proc.stderr.strip() if proc.returncode != 0 else "",
    }

    if not result["decryption_success"]:
        result["warning"] = (
            "No additional frames were decrypted. "
            "Verify the SSID/password is correct and that the capture contains "
            "a complete 4-way EAPOL handshake (messages 1-4)."
        )

    return result


# ──────────────────────────────────────────────────────────────────────────────
# Step 3: Inner-protocol analysis on the decrypted pcap
# ──────────────────────────────────────────────────────────────────────────────
def analyze_decrypted_traffic(
    decrypted_pcap: str,
    mac_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """Extract application-layer insights from the decrypted capture."""
    return {
        "dns":                    _extract_dns(decrypted_pcap),
        "http":                   _extract_http(decrypted_pcap),
        "ip_endpoints":           _extract_ip_endpoints(decrypted_pcap),
        "protocol_distribution":  _extract_protocol_distribution(decrypted_pcap),
        "port_summary":           _extract_port_summary(decrypted_pcap),
        "security_observations":  None,  # filled below
    }


def _finalize_security_observations(analysis: Dict[str, Any]) -> List[str]:
    """Derive human-readable security findings from inner-protocol analysis."""
    obs: List[str] = []
    dns = analysis.get("dns", {})
    http = analysis.get("http", {})
    ports = analysis.get("port_summary", {})
    ep = analysis.get("ip_endpoints", {})

    if dns.get("total_dns_packets", 0) > 0:
        obs.append(
            f"DNS activity: {dns['unique_domains']} unique domains queried "
            f"across {dns['total_dns_packets']} DNS packets"
        )

    if http.get("total_http_requests", 0) > 0:
        obs.append(
            f"⚠ Unencrypted HTTP: {http['total_http_requests']} plaintext HTTP "
            "request(s) detected — consider enforcing HTTPS"
        )

    # Insecure plaintext TCP services
    risky_ports = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP"}
    for entry in ports.get("top_tcp_ports", []):
        if entry["port"] in risky_ports:
            obs.append(
                f"⚠ Insecure protocol on TCP/{entry['port']} "
                f"({risky_ports[entry['port']]}) — plaintext credentials risk"
            )

    if ep.get("unique_ips", 0) > 50:
        obs.append(
            f"High endpoint diversity: {ep['unique_ips']} unique IP addresses "
            "seen in decrypted traffic"
        )

    if not obs:
        obs.append("No significant security findings in decrypted traffic")

    return obs


# ── tshark helpers ────────────────────────────────────────────────────────────
def _count_frames(pcap_file: str, display_filter: Optional[str] = None) -> int:
    cmd = ["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.number"]
    if display_filter:
        cmd += ["-Y", display_filter]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return len([l for l in proc.stdout.strip().splitlines() if l.strip()])


def _extract_dns(pcap_file: str) -> Dict[str, Any]:
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "dns",
        "-T", "fields",
        "-e", "dns.qry.name",
        "-e", "dns.a",
        "-E", "separator=|",
        "-E", "header=n",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    queries: List[Dict] = []
    for line in proc.stdout.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        qname = parts[0].strip() if parts else ""
        a_rec = parts[1].strip() if len(parts) > 1 else ""
        if qname:
            queries.append({"query": qname, "a_record": a_rec})

    ctr = Counter(q["query"] for q in queries if q["query"])
    return {
        "total_dns_packets": len(queries),
        "unique_domains": len(ctr),
        "top_queries": [{"domain": d, "count": c} for d, c in ctr.most_common(25)],
    }


def _extract_http(pcap_file: str) -> Dict[str, Any]:
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "http.request",
        "-T", "fields",
        "-e", "http.host",
        "-e", "http.request.method",
        "-e", "http.request.uri",
        "-e", "ip.src",
        "-E", "separator=|",
        "-E", "header=n",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    requests: List[Dict] = []
    for line in proc.stdout.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        requests.append({
            "host":   parts[0] if len(parts) > 0 else "",
            "method": parts[1] if len(parts) > 1 else "",
            "uri":    parts[2] if len(parts) > 2 else "",
            "src_ip": parts[3] if len(parts) > 3 else "",
        })
    return {
        "total_http_requests": len(requests),
        "requests": requests[:50],
    }


def _extract_ip_endpoints(pcap_file: str) -> Dict[str, Any]:
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "ip",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len",
        "-E", "separator=|",
        "-E", "header=n",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    ip_stats: Dict[str, Dict] = defaultdict(lambda: {"sent_bytes": 0, "recv_bytes": 0, "packets": 0})

    for line in proc.stdout.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        src, dst, length = parts[0].strip(), parts[1].strip(), parts[2].strip()
        try:
            byte_len = int(length)
        except ValueError:
            byte_len = 0
        if src:
            ip_stats[src]["sent_bytes"] += byte_len
            ip_stats[src]["packets"] += 1
        if dst:
            ip_stats[dst]["recv_bytes"] += byte_len

    top_talkers = sorted(
        [{"ip": ip, **stats} for ip, stats in ip_stats.items()],
        key=lambda x: x["sent_bytes"] + x["recv_bytes"],
        reverse=True,
    )[:20]

    return {"unique_ips": len(ip_stats), "top_talkers": top_talkers}


def _extract_protocol_distribution(pcap_file: str) -> Dict[str, int]:
    """Use ``tshark -z io,phs`` to obtain the protocol hierarchy."""
    cmd = ["tshark", "-r", pcap_file, "-q", "-z", "io,phs"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    protocols: Dict[str, int] = {}
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if (not stripped
                or stripped.startswith("=")
                or stripped.lower().startswith("protocol")
                or "frames" in stripped.lower()):
            continue
        parts = stripped.split()
        if len(parts) >= 3:
            proto = parts[0]
            try:
                frames = int(parts[-2])
                protocols[proto] = frames
            except (ValueError, IndexError):
                pass

    return dict(sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:15])


def _extract_port_summary(pcap_file: str) -> Dict[str, Any]:
    def _port_counts(display_filter: str, field: str) -> Counter:
        cmd = [
            "tshark", "-r", pcap_file,
            "-Y", display_filter,
            "-T", "fields",
            "-e", field,
            "-E", "header=n",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        ctr: Counter = Counter()
        for line in proc.stdout.strip().splitlines():
            port = line.strip()
            if port:
                try:
                    ctr[int(port)] += 1
                except ValueError:
                    pass
        return ctr

    tcp_ctr = _port_counts("tcp", "tcp.dstport")
    udp_ctr = _port_counts("udp", "udp.dstport")

    top_tcp = [
        {"port": p, "name": PORT_NAMES.get(p, ""), "count": c}
        for p, c in tcp_ctr.most_common(15)
    ]
    top_udp = [
        {"port": p, "name": PORT_NAMES.get(p, ""), "count": c}
        for p, c in udp_ctr.most_common(15)
    ]

    return {
        "top_tcp_ports": top_tcp,
        "top_udp_ports": top_udp,
        "total_tcp_frames": sum(tcp_ctr.values()),
        "total_udp_frames": sum(udp_ctr.values()),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────
def run(
    pcap_file: str,
    key_type: str,
    password: str,
    ssid: str = "",
    mac_filter: Optional[str] = None,
    output_dir: str = "results",
    save_decrypted_pcap: bool = False,
) -> Dict[str, Any]:
    """Full decryption + analysis pipeline.

    1. Checks for EAPOL/SAE handshake presence
    2. Decrypts using tshark (-o wlan.enable_decryption:TRUE)
    3. Runs inner-protocol analysis on the decrypted pcap
    4. Re-runs WLAN-level analysis on the decrypted capture
    5. Generates JSON + HTML reports

    Args:
        pcap_file:          Input (encrypted) PCAP path.
        key_type:           ``"wpa-pwd"`` or ``"wpa-psk"``.
        password:           WiFi passphrase or 64-char hex PMK.
        ssid:               Network SSID (required for wpa-pwd).
        mac_filter:         Optional client MAC address filter.
        output_dir:         Directory for JSON/HTML/PCAP output files.
        save_decrypted_pcap: When True, the decrypted pcap is copied to output_dir.

    Returns:
        dict with ``json_path``, ``html_path``, ``results``, ``decrypted_pcap``.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    pcap_stem = Path(pcap_file).stem
    if mac_filter:
        mac_slug = mac_filter.replace(":", "_")
        pcap_stem = f"{pcap_stem}_mac_{mac_slug}"
    output_json = str(Path(output_dir) / f"{pcap_stem}_decrypted.json")
    output_html = str(Path(output_dir) / f"{pcap_stem}_decrypted_report.html")

    # ── 1. Handshake check ────────────────────────────────────────────────────
    logger.info("Checking capture for 4-way EAPOL / SAE handshake ...")
    handshake_info = check_handshake_present(pcap_file)
    logger.info(
        f"EAPOL messages found: {handshake_info['eapol_messages_found']} | "
        f"Full handshake: {handshake_info['has_full_4way_handshake']} | "
        f"SAE: {handshake_info['has_sae']}"
    )

    # ── 2. Decryption ─────────────────────────────────────────────────────────
    decrypted_pcap_dest: Optional[str] = None
    if save_decrypted_pcap:
        decrypted_pcap_dest = str(Path(output_dir) / f"{pcap_stem}_decrypted.pcap")

    decrypt_result = decrypt_capture(
        pcap_file=pcap_file,
        key_type=key_type,
        password=password,
        ssid=ssid,
        output_pcap=decrypted_pcap_dest,
    )

    if decrypt_result.get("error"):
        return {"error": decrypt_result["error"]}

    decrypted_pcap = decrypt_result["decrypted_pcap"]

    # ── 3. Inner protocol analysis ────────────────────────────────────────────
    logger.info("Analysing decrypted traffic for inner protocols ...")
    inner = analyze_decrypted_traffic(decrypted_pcap, mac_filter=mac_filter)
    inner["security_observations"] = _finalize_security_observations(inner)

    # ── 4. WLAN-level re-analysis on decrypted pcap ───────────────────────────
    wlan_summary: Dict[str, Any] = {}
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from scripts.run_wlan_analysis import run_tshark as wlan_tshark, parse_tshark_output
        from src.protocols.wlan_analyzer import WLANAnalyzer

        raw = wlan_tshark(decrypted_pcap, mac_filter=mac_filter)
        df = parse_tshark_output(raw)
        if not df.empty:
            analyzer = WLANAnalyzer()
            wlan_summary = {
                "statistics":        analyzer._calculate_statistics(df),
                "connection_events": analyzer._analyze_connection_events(df),
                "threats":           analyzer._detect_threats(df),
            }
    except Exception as exc:
        logger.warning(f"Post-decryption WLAN analysis failed: {exc}")
        wlan_summary = {"error": str(exc)}

    # ── 5. Assemble results ───────────────────────────────────────────────────
    results: Dict[str, Any] = {
        "pcap_file":   pcap_file,
        "key_type":    KEY_TYPES.get(key_type, key_type),
        "ssid":        ssid,
        "mac_filter":  mac_filter,
        "handshake_info": handshake_info,
        "decryption": {
            "success":              decrypt_result["decryption_success"],
            "warning":              decrypt_result.get("warning", ""),
            "original_frames":      decrypt_result["original_frames"],
            "decrypted_frames":     decrypt_result["decrypted_output_frames"],
            "newly_decrypted_frames": decrypt_result["newly_decrypted_frames"],
            "decrypted_pcap": (
                decrypted_pcap if save_decrypted_pcap else "(temporary, not saved)"
            ),
        },
        "inner_protocol_analysis": inner,
        "wlan_post_decryption":    wlan_summary,
    }

    # ── JSON output ───────────────────────────────────────────────────────────
    with open(output_json, "w") as fh:
        json.dump(results, fh, indent=2, default=str)
    logger.info(f"JSON results → {output_json}")

    # ── HTML report ───────────────────────────────────────────────────────────
    try:
        _generate_html_report(results, pcap_file, output_html)
        logger.info(f"HTML report → {output_html}")
    except Exception as exc:
        logger.error(f"HTML report generation failed: {exc}")

    return {
        "json_path":      output_json,
        "html_path":      output_html,
        "results":        results,
        "decrypted_pcap": decrypted_pcap if save_decrypted_pcap else None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# HTML report generation
# ──────────────────────────────────────────────────────────────────────────────
def _generate_html_report(results: Dict, pcap_file: str, output_html: str) -> None:
    """Try the shared HTMLReportGenerator, fall back to a self-contained template."""
    try:
        from src.reports.html_generator import HTMLReportGenerator

        generator = HTMLReportGenerator()
        report_data = {
            "total_packets": results["decryption"]["original_frames"],
            "protocol_analysis": {"wpa_decrypt": results},
        }
        generator.generate_report(
            results=report_data,
            pcap_file=pcap_file,
            output_file=output_html,
            protocol="WPA Decrypt",
        )
    except Exception:
        _write_standalone_html(results, pcap_file, output_html)


def _write_standalone_html(results: Dict, pcap_file: str, output_html: str) -> None:
    """Render a fully self-contained dark-theme HTML report."""
    dec   = results.get("decryption", {})
    hs    = results.get("handshake_info", {})
    inner = results.get("inner_protocol_analysis", {})
    dns   = inner.get("dns", {})
    http  = inner.get("http", {})
    ports = inner.get("port_summary", {})
    ep    = inner.get("ip_endpoints", {})
    sec   = inner.get("security_observations", [])
    proto = inner.get("protocol_distribution", {})

    esc = html_module.escape

    def _tbl(items: list, keys: list, max_rows: int = 50) -> str:
        rows = ""
        for item in items[:max_rows]:
            cells = ""
            for k in keys:
                val = item.get(k, "")
                val_str = str(val)[:120] if isinstance(val, str) else str(val)
                cells += f"<td>{esc(val_str)}</td>"
            rows += f"<tr>{cells}</tr>"
        return rows

    status_colour = "#a6e3a1" if dec.get("success") else "#f38ba8"
    status_text   = "SUCCESS" if dec.get("success") else "FAILED / No new frames decrypted"
    hs_colour     = "#a6e3a1" if hs.get("has_full_4way_handshake") else "#f38ba8"
    hs_text       = "✓ Complete (messages 1-4 present)" if hs.get("has_full_4way_handshake") else "✗ Incomplete or missing"

    # Protocol distribution table
    proto_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{v}</td></tr>"
        for k, v in proto.items()
    )

    # DNS top queries
    dns_section = ""
    if dns.get("top_queries"):
        dns_section = (
            "<table><tr><th>Domain</th><th>Queries</th></tr>"
            + _tbl(dns["top_queries"], ["domain", "count"])
            + "</table>"
        )
    else:
        dns_section = "<p>No DNS traffic found</p>"

    # HTTP requests
    http_banner = (
        f'<p class="warn">⚠ {esc(str(http.get("total_http_requests", 0)))} '
        "unencrypted HTTP request(s) detected</p>"
        if http.get("total_http_requests", 0) > 0
        else '<p class="ok">✓ No plaintext HTTP detected</p>'
    )
    http_tbl = (
        "<table><tr><th>Host</th><th>Method</th><th>URI</th><th>Src IP</th></tr>"
        + _tbl(http.get("requests", [])[:20], ["host", "method", "uri", "src_ip"])
        + "</table>"
        if http.get("requests")
        else ""
    )

    # IP endpoints
    ep_tbl = (
        "<table><tr><th>IP</th><th>Sent B</th><th>Recv B</th><th>Pkts</th></tr>"
        + _tbl(ep.get("top_talkers", []), ["ip", "sent_bytes", "recv_bytes", "packets"])
        + "</table>"
        if ep.get("top_talkers")
        else "<p>No IP endpoints found</p>"
    )

    # TCP/UDP ports
    tcp_tbl = (
        "<table><tr><th>Port</th><th>Service</th><th>Frames</th></tr>"
        + _tbl(ports.get("top_tcp_ports", []), ["port", "name", "count"])
        + "</table>"
        if ports.get("top_tcp_ports")
        else "<p>No TCP traffic</p>"
    )
    udp_tbl = (
        "<table><tr><th>Port</th><th>Service</th><th>Frames</th></tr>"
        + _tbl(ports.get("top_udp_ports", []), ["port", "name", "count"])
        + "</table>"
        if ports.get("top_udp_ports")
        else "<p>No UDP traffic</p>"
    )

    sec_items = "".join(f"<li>{esc(o)}</li>" for o in sec)

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WPA Decryption Report — {esc(Path(pcap_file).name)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #1e1e2e; color: #cdd6f4;
         padding: 28px; line-height: 1.5; }}
  h1   {{ color: #89b4fa; font-size: 24px; border-bottom: 2px solid #313244;
          padding-bottom: 12px; margin-bottom: 20px; }}
  h2   {{ color: #cba6f7; font-size: 17px; margin: 26px 0 10px; }}
  h3   {{ color: #89dceb; font-size: 14px; margin: 18px 0 8px; }}
  .card {{ background: #181825; border: 1px solid #313244; border-radius: 10px;
           padding: 18px 20px; margin-bottom: 16px; }}
  .badge {{ display: inline-block; padding: 3px 12px; border-radius: 5px;
            font-weight: 700; font-size: 12px; color: #1e1e2e; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }}
  th    {{ background: #313244; color: #cba6f7; text-align: left;
           padding: 7px 12px; font-weight: 600; }}
  td    {{ padding: 5px 12px; border-bottom: 1px solid #252535; }}
  tr:hover td {{ background: #252535; }}
  .warn {{ color: #fab387; }}
  .ok   {{ color: #a6e3a1; }}
  ul    {{ padding-left: 20px; }}
  li    {{ margin: 5px 0; }}
  .meta td:first-child {{ color: #a6adc8; width: 180px; font-size: 13px; }}
</style>
</head>
<body>
<h1>🔓 WPA Decryption &amp; Analysis Report</h1>

<div class="card">
  <table class="meta">
    <tr><td>PCAP File</td><td>{esc(pcap_file)}</td></tr>
    <tr><td>Key Type</td><td>{esc(results.get("key_type", ""))}</td></tr>
    <tr><td>SSID</td><td>{esc(results.get("ssid", "—"))}</td></tr>
    <tr><td>MAC Filter</td><td>{esc(str(results.get("mac_filter", "—")))}</td></tr>
  </table>
</div>

<h2>🤝 Handshake Detection</h2>
<div class="card">
  <table class="meta">
    <tr><td>EAPOL Frames</td><td>{hs.get("eapol_frames", 0)}</td></tr>
    <tr><td>EAPOL Messages</td><td>{", ".join(hs.get("eapol_messages_found", [])) or "—"}</td></tr>
    <tr><td>4-Way Handshake</td>
        <td><span class="badge" style="background:{hs_colour}">{esc(hs_text)}</span></td></tr>
    <tr><td>SAE Frames (WPA3)</td>
        <td>{hs.get("sae_frames", 0)}{"  (SAE/WPA3 exchange detected)" if hs.get("has_sae") else ""}</td></tr>
  </table>
</div>

<h2>🔓 Decryption Result</h2>
<div class="card">
  <p style="margin-bottom:10px">
    <span class="badge" style="background:{status_colour}">{esc(status_text)}</span>
  </p>
  {"<p class='warn' style='margin-bottom:8px'>⚠ " + esc(dec.get("warning", "")) + "</p>" if dec.get("warning") else ""}
  <table class="meta">
    <tr><td>Original Frames</td><td>{dec.get("original_frames", 0)}</td></tr>
    <tr><td>Output Frames</td><td>{dec.get("decrypted_frames", 0)}</td></tr>
    <tr><td>Newly Decrypted</td><td>{dec.get("newly_decrypted_frames", 0)}</td></tr>
    <tr><td>Decrypted PCAP</td><td>{esc(str(dec.get("decrypted_pcap", "—")))}</td></tr>
  </table>
</div>

<h2>🔍 Inner Protocol Analysis (Decrypted Traffic)</h2>

<h3>Protocol Distribution</h3>
<div class="card">
  {"<table><tr><th>Protocol</th><th>Frames</th></tr>" + proto_rows + "</table>" if proto_rows else "<p>No protocol data</p>"}
</div>

<h3>DNS</h3>
<div class="card">
  <p>DNS packets: <b>{dns.get("total_dns_packets", 0)}</b> &nbsp;|&nbsp;
     Unique domains: <b>{dns.get("unique_domains", 0)}</b></p>
  {dns_section}
</div>

<h3>HTTP (Unencrypted)</h3>
<div class="card">
  {http_banner}
  {http_tbl}
</div>

<h3>Top IP Endpoints</h3>
<div class="card">
  <p>Unique IPs: <b>{ep.get("unique_ips", 0)}</b></p>
  {ep_tbl}
</div>

<h3>TCP Port Summary</h3>
<div class="card">
  <p>Total TCP frames: <b>{ports.get("total_tcp_frames", 0)}</b></p>
  {tcp_tbl}
</div>

<h3>UDP Port Summary</h3>
<div class="card">
  <p>Total UDP frames: <b>{ports.get("total_udp_frames", 0)}</b></p>
  {udp_tbl}
</div>

<h2>🛡️ Security Observations</h2>
<div class="card">
  <ul>{sec_items}</ul>
</div>

</body>
</html>"""

    Path(output_html).parent.mkdir(parents=True, exist_ok=True)
    with open(output_html, "w", encoding="utf-8") as fh:
        fh.write(html_out)
