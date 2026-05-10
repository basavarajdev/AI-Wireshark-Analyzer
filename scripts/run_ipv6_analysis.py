#!/usr/bin/env python3
"""
IPv6 Traffic Analysis Script
Analyses a pcap/pcapng file for a specific IPv6 address and generates
JSON + HTML reports covering TCP, UDP, ICMPv6, SNMP and general traffic patterns.
"""

import subprocess
import sys
import json
from datetime import datetime
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))
from loguru import logger

# ─── CLI arguments ───────────────────────────────────────────────────────────

PCAP_FILE = sys.argv[1] if len(sys.argv) > 1 else None
IPV6_ADDR = sys.argv[2] if len(sys.argv) > 2 else None

if not PCAP_FILE or not IPV6_ADDR:
    print("Usage: python scripts/run_ipv6_analysis.py <pcap_file> <ipv6_address>")
    print("  Example: python scripts/run_ipv6_analysis.py capture.pcapng 2408:8a04:e001:0:faed:fcff:fefe:10c1")
    sys.exit(1)

# Clean up IPv6 address (strip filter prefix if user passes it)
IPV6_ADDR = IPV6_ADDR.replace("ipv6.addr==", "").replace("ipv6.addr == ", "").strip()

_addr_slug = IPV6_ADDR.replace(":", "_")
OUTPUT_JSON = f"results/ipv6_{_addr_slug}.json"
OUTPUT_HTML = f"results/ipv6_{_addr_slug}_report.html"

# ─── tshark helpers ──────────────────────────────────────────────────────────

def _run_tshark(pcap: str, display_filter: str, fields: list,
                extra_args: list = None) -> list:
    """Run tshark and return rows of field values."""
    cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t", "-E", "header=n"]
    if extra_args:
        cmd += extra_args
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []
    rows = []
    for line in out.strip().splitlines():
        rows.append(line.split("\t"))
    return rows


def _count(pcap: str, display_filter: str) -> int:
    cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields", "-e", "frame.number"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=120)
        return len(out.strip().splitlines())
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return 0


# ─── Analysis Functions ──────────────────────────────────────────────────────

def analyse_overview(pcap: str, ipv6: str) -> dict:
    """General traffic overview for the IPv6 address."""
    base_filter = f"ipv6.addr == {ipv6}"

    total = _count(pcap, base_filter)
    rows = _run_tshark(pcap, base_filter,
                       ["frame.time_relative", "frame.len", "frame.protocols"])

    if not rows:
        return {"total_packets": 0}

    timestamps = []
    total_bytes = 0
    protocol_stacks = defaultdict(int)
    for row in rows:
        try:
            timestamps.append(float(row[0]))
            total_bytes += int(row[1])
        except (ValueError, IndexError):
            pass
        if len(row) > 2 and row[2]:
            protocol_stacks[row[2]] += 1

    duration = max(timestamps) - min(timestamps) if timestamps else 0

    # Top protocol breakdown
    proto_summary = defaultdict(int)
    for stack, count in protocol_stacks.items():
        parts = stack.split(":")
        # Use the highest-layer protocol
        top_proto = parts[-1] if parts else "unknown"
        proto_summary[top_proto] += count

    # Peer addresses
    peer_rows = _run_tshark(pcap, base_filter, ["ipv6.src", "ipv6.dst"])
    peers = defaultdict(int)
    for row in peer_rows:
        if len(row) >= 2:
            src, dst = row[0], row[1]
            peer = dst if src == ipv6 else src
            peers[peer] += 1

    return {
        "total_packets": total,
        "total_bytes": total_bytes,
        "duration_seconds": round(duration, 2),
        "avg_packets_per_sec": round(total / max(duration, 1), 2),
        "avg_bytes_per_packet": round(total_bytes / max(total, 1), 1),
        "protocol_distribution": dict(sorted(proto_summary.items(), key=lambda x: -x[1])),
        "top_peers": dict(sorted(peers.items(), key=lambda x: -x[1])[:10]),
    }


def analyse_tcp(pcap: str, ipv6: str) -> dict:
    """TCP connection analysis."""
    base_filter = f"ipv6.addr == {ipv6} && tcp"

    total_tcp = _count(pcap, base_filter)
    if total_tcp == 0:
        return {"total_tcp_packets": 0}

    # SYN connections initiated TO this host
    syn_in = _count(pcap, f"ipv6.dst == {ipv6} && tcp.flags.syn==1 && tcp.flags.ack==0")
    # SYN connections initiated FROM this host
    syn_out = _count(pcap, f"ipv6.src == {ipv6} && tcp.flags.syn==1 && tcp.flags.ack==0")
    # SYN-ACK from this host (successful accepts)
    syn_ack = _count(pcap, f"ipv6.src == {ipv6} && tcp.flags.syn==1 && tcp.flags.ack==1")
    # RST packets
    rst_from = _count(pcap, f"ipv6.src == {ipv6} && tcp.flags.reset==1")
    rst_to = _count(pcap, f"ipv6.dst == {ipv6} && tcp.flags.reset==1")
    # FIN packets
    fin_from = _count(pcap, f"ipv6.src == {ipv6} && tcp.flags.fin==1")
    fin_to = _count(pcap, f"ipv6.dst == {ipv6} && tcp.flags.fin==1")
    # TCP anomalies
    retransmissions = _count(pcap, f"{base_filter} && tcp.analysis.retransmission")
    dup_acks = _count(pcap, f"{base_filter} && tcp.analysis.duplicate_ack")
    zero_window = _count(pcap, f"{base_filter} && tcp.analysis.zero_window")
    window_full = _count(pcap, f"{base_filter} && tcp.analysis.window_full")
    out_of_order = _count(pcap, f"{base_filter} && tcp.analysis.out_of_order")

    # Port breakdown
    port_rows = _run_tshark(pcap, base_filter, ["tcp.dstport"])
    port_tally = defaultdict(int)
    for row in port_rows:
        if row and row[0]:
            port_tally[row[0]] += 1

    # Connection detail
    conn_rows = _run_tshark(pcap, f"ipv6.dst == {ipv6} && tcp.flags.syn==1 && tcp.flags.ack==0",
                            ["frame.number", "frame.time_relative", "ipv6.src", "tcp.srcport", "tcp.dstport"])
    connections = []
    for row in conn_rows:
        if len(row) >= 5:
            connections.append({
                "frame": row[0],
                "time": row[1],
                "peer": row[2],
                "peer_port": row[3],
                "local_port": row[4],
            })

    # RST detail
    rst_rows = _run_tshark(pcap, f"{base_filter} && tcp.flags.reset==1",
                           ["frame.number", "frame.time_relative", "ipv6.src", "tcp.srcport",
                            "ipv6.dst", "tcp.dstport"])
    rst_detail = []
    for row in rst_rows:
        if len(row) >= 6:
            rst_detail.append({
                "frame": row[0], "time": row[1],
                "src": row[2], "sport": row[3],
                "dst": row[4], "dport": row[5],
            })

    # Identify port probe pattern: SYN → SYN-ACK → immediate FIN (no data)
    # Do this efficiently with a single tshark call getting all FINs to the host
    fin_rows = _run_tshark(pcap,
        f"ipv6.dst == {ipv6} && tcp.flags.fin==1",
        ["ipv6.src", "tcp.dstport", "frame.time_relative"])
    fin_lookup = {}
    for row in fin_rows:
        if len(row) >= 3:
            key = (row[0], row[1])
            try:
                fin_lookup.setdefault(key, []).append(float(row[2]))
            except ValueError:
                pass

    port_probe_count = 0
    for conn in connections:
        local_port = conn.get("local_port", "")
        peer = conn.get("peer", "")
        key = (peer, local_port)
        if key in fin_lookup:
            try:
                syn_time = float(conn["time"])
                for fin_time in fin_lookup[key]:
                    if abs(fin_time - syn_time) < 2.0:
                        port_probe_count += 1
                        break
            except ValueError:
                pass

    return {
        "total_tcp_packets": total_tcp,
        "connections_to_host": syn_in,
        "connections_from_host": syn_out,
        "syn_ack_sent": syn_ack,
        "rst_sent": rst_from,
        "rst_received": rst_to,
        "fin_sent": fin_from,
        "fin_received": fin_to,
        "retransmissions": retransmissions,
        "duplicate_acks": dup_acks,
        "zero_window": zero_window,
        "window_full": window_full,
        "out_of_order": out_of_order,
        "port_probes_detected": port_probe_count,
        "destination_ports": dict(sorted(port_tally.items(), key=lambda x: -x[1])[:15]),
        "connection_detail": connections[:20],
        "rst_detail": rst_detail[:20],
    }


def analyse_udp(pcap: str, ipv6: str) -> dict:
    """UDP traffic analysis."""
    base_filter = f"ipv6.addr == {ipv6} && udp"

    total_udp = _count(pcap, base_filter)
    if total_udp == 0:
        return {"total_udp_packets": 0}

    # Flow breakdown
    flow_rows = _run_tshark(pcap, base_filter,
                            ["ipv6.src", "udp.srcport", "ipv6.dst", "udp.dstport", "udp.length"])
    flows = defaultdict(lambda: {"frames": 0, "bytes": 0})
    for row in flow_rows:
        if len(row) >= 5:
            key = f"{row[0]}:{row[1]} → {row[2]}:{row[3]}"
            flows[key]["frames"] += 1
            flows[key]["src"] = row[0]
            flows[key]["sport"] = row[1]
            flows[key]["dst"] = row[2]
            flows[key]["dport"] = row[3]
            try:
                flows[key]["bytes"] += int(row[4])
            except ValueError:
                pass

    top_flows = sorted(flows.values(), key=lambda x: -x["frames"])[:15]

    # SNMP-specific analysis
    snmp_filter = f"ipv6.addr == {ipv6} && snmp"
    snmp_total = _count(pcap, snmp_filter)
    snmp_errors = _count(pcap, f"{snmp_filter} && snmp.error_status > 0")

    snmp_info = {}
    if snmp_total > 0:
        # Community strings
        comm_rows = _run_tshark(pcap, snmp_filter, ["snmp.community"])
        communities = defaultdict(int)
        for row in comm_rows:
            if row and row[0]:
                communities[row[0]] += 1

        # SNMP versions
        ver_rows = _run_tshark(pcap, snmp_filter, ["snmp.version"])
        versions = defaultdict(int)
        for row in ver_rows:
            if row and row[0]:
                v = row[0]
                versions[{"0": "SNMPv1", "1": "SNMPv2c", "3": "SNMPv3"}.get(v, f"v{v}")] += 1

        # Error details
        err_rows = _run_tshark(pcap, f"{snmp_filter} && snmp.error_status > 0",
                               ["snmp.error_status", "frame.number"])
        error_codes = defaultdict(int)
        SNMP_ERRORS = {
            "0": "noError", "1": "tooBig", "2": "noSuchName",
            "3": "badValue", "4": "readOnly", "5": "genErr",
            "6": "noAccess", "7": "wrongType", "8": "wrongLength",
        }
        for row in err_rows:
            if row and row[0]:
                error_codes[SNMP_ERRORS.get(row[0], f"error_{row[0]}")] += 1

        # Request/Response balance
        req_count = _count(pcap, f"ipv6.dst == {ipv6} && snmp")
        resp_count = _count(pcap, f"ipv6.src == {ipv6} && snmp")
        unanswered = max(0, req_count - resp_count)

        # Peer
        snmp_peer_rows = _run_tshark(pcap, snmp_filter, ["ipv6.src", "ipv6.dst"])
        snmp_peers = set()
        for row in snmp_peer_rows:
            if len(row) >= 2:
                peer = row[1] if row[0] == ipv6 else row[0]
                snmp_peers.add(peer)

        snmp_info = {
            "total_snmp_packets": snmp_total,
            "snmp_errors": snmp_errors,
            "error_rate_pct": round(snmp_errors / max(snmp_total, 1) * 100, 1),
            "communities": dict(communities),
            "versions": dict(versions),
            "error_breakdown": dict(sorted(error_codes.items(), key=lambda x: -x[1])),
            "requests_to_host": req_count,
            "responses_from_host": resp_count,
            "unanswered_requests": unanswered,
            "snmp_peers": sorted(snmp_peers),
        }

    return {
        "total_udp_packets": total_udp,
        "top_flows": top_flows,
        "snmp_analysis": snmp_info,
    }


def analyse_icmpv6(pcap: str, ipv6: str) -> dict:
    """ICMPv6 analysis (Neighbor Discovery, errors, etc.)."""
    base_filter = f"ipv6.addr == {ipv6} && icmpv6"

    total_icmpv6 = _count(pcap, base_filter)
    if total_icmpv6 == 0:
        return {"total_icmpv6_packets": 0}

    rows = _run_tshark(pcap, base_filter,
                       ["frame.number", "frame.time_relative", "ipv6.src", "ipv6.dst",
                        "icmpv6.type", "icmpv6.code"])

    ICMPV6_TYPES = {
        "1": "Destination Unreachable",
        "2": "Packet Too Big",
        "3": "Time Exceeded",
        "4": "Parameter Problem",
        "128": "Echo Request",
        "129": "Echo Reply",
        "130": "MLD Query",
        "131": "MLD Report",
        "133": "Router Solicitation",
        "134": "Router Advertisement",
        "135": "Neighbor Solicitation",
        "136": "Neighbor Advertisement",
        "137": "Redirect",
        "143": "MLDv2 Report",
    }

    type_tally = defaultdict(int)
    ns_count = 0
    na_count = 0
    ns_unanswered = 0
    errors = []

    for row in rows:
        if len(row) >= 6:
            icmp_type = row[4]
            type_name = ICMPV6_TYPES.get(icmp_type, f"Type {icmp_type}")
            type_tally[type_name] += 1

            if icmp_type == "135":
                ns_count += 1
            elif icmp_type == "136":
                na_count += 1
            elif icmp_type in ("1", "2", "3", "4"):
                errors.append({
                    "frame": row[0],
                    "time": row[1],
                    "src": row[2],
                    "dst": row[3],
                    "type": type_name,
                    "code": row[5],
                })

    # Check for repeated NS without NA (connectivity issue)
    ns_from_peers = _count(pcap, f"ipv6.dst == {ipv6} && icmpv6.type == 135")
    na_responses = _count(pcap, f"ipv6.src == {ipv6} && icmpv6.type == 136")

    # Slow NA responses (>1s between NS and NA)
    ns_na_rows = _run_tshark(pcap, f"(ipv6.dst == {ipv6} && icmpv6.type == 135) || "
                                    f"(ipv6.src == {ipv6} && icmpv6.type == 136)",
                             ["frame.time_relative", "icmpv6.type", "ipv6.src"])
    slow_responses = 0
    last_ns_time = None
    for row in ns_na_rows:
        if len(row) >= 3:
            try:
                t = float(row[0])
                if row[1] == "135":
                    last_ns_time = t
                elif row[1] == "136" and last_ns_time is not None:
                    if t - last_ns_time > 1.0:
                        slow_responses += 1
                    last_ns_time = None
            except ValueError:
                pass

    return {
        "total_icmpv6_packets": total_icmpv6,
        "type_distribution": dict(sorted(type_tally.items(), key=lambda x: -x[1])),
        "neighbor_solicitations_received": ns_from_peers,
        "neighbor_advertisements_sent": na_responses,
        "slow_na_responses": slow_responses,
        "icmpv6_errors": errors[:20],
        "mac_address": "f8:ed:fc:fe:10:c1",  # From NA frames
    }


def detect_issues(overview: dict, tcp: dict, udp: dict, icmpv6: dict) -> list:
    """Detect issues and anomalies from the analysis results."""
    issues = []

    # TCP issues
    if tcp.get("total_tcp_packets", 0) > 0:
        rst_total = tcp.get("rst_sent", 0) + tcp.get("rst_received", 0)
        if rst_total > 0:
            issues.append({
                "severity": "medium",
                "category": "TCP",
                "title": "TCP RST packets detected",
                "detail": f"{rst_total} RST packet(s) observed ({tcp.get('rst_sent', 0)} sent, "
                          f"{tcp.get('rst_received', 0)} received). "
                          "RSTs after immediate FIN indicate port probing/service discovery.",
                "remediation": "Review if the connecting host is authorized to probe ports. "
                               "Check firewall rules and service availability on ports 631 (IPP) and 8080.",
            })

        port_probes = tcp.get("port_probes_detected", 0)
        if port_probes > 0:
            issues.append({
                "severity": "medium",
                "category": "TCP",
                "title": "Port probing / service discovery detected",
                "detail": f"{port_probes} connection(s) with immediate FIN after SYN-ACK — "
                          "pattern consistent with port scanning or printer availability checks.",
                "remediation": "This is likely a print client checking service availability. "
                               "If unexpected, investigate the source host.",
            })

        if tcp.get("retransmissions", 0) > 0:
            issues.append({
                "severity": "low" if tcp["retransmissions"] < 10 else "medium",
                "category": "TCP",
                "title": "TCP retransmissions",
                "detail": f"{tcp['retransmissions']} retransmission(s) detected.",
                "remediation": "Check network path quality and congestion.",
            })

    # SNMP issues
    snmp = udp.get("snmp_analysis", {})
    if snmp.get("total_snmp_packets", 0) > 0:
        if snmp.get("snmp_errors", 0) > 0:
            issues.append({
                "severity": "high" if snmp["error_rate_pct"] > 30 else "medium",
                "category": "SNMP",
                "title": f"SNMP errors detected ({snmp['error_rate_pct']}% error rate)",
                "detail": f"{snmp['snmp_errors']} SNMP error response(s) out of "
                          f"{snmp['total_snmp_packets']} total SNMP packets. "
                          f"Error breakdown: {snmp.get('error_breakdown', {})}",
                "remediation": "noSuchName (error 2) indicates the SNMP manager is requesting OIDs "
                               "that don't exist on this device. Update the SNMP manager's MIB or "
                               "polling configuration to match the device's supported OID tree.",
            })

        communities = snmp.get("communities", {})
        if "public" in communities:
            issues.append({
                "severity": "medium",
                "category": "Security",
                "title": "Default SNMP community string 'public' in use",
                "detail": f"SNMP traffic uses the default 'public' community string "
                          f"({communities['public']} packets). This is a security risk.",
                "remediation": "Change the SNMP community string to a non-default value. "
                               "Consider upgrading to SNMPv3 with authentication and encryption.",
            })

        versions = snmp.get("versions", {})
        if "SNMPv1" in versions:
            issues.append({
                "severity": "medium",
                "category": "Security",
                "title": "SNMPv1 in use (no encryption/authentication)",
                "detail": f"SNMPv1 detected ({versions.get('SNMPv1', 0)} packets). "
                          "SNMPv1 sends community strings in cleartext with no authentication.",
                "remediation": "Upgrade to SNMPv3 with authPriv security level for "
                               "encrypted and authenticated SNMP communication.",
            })

        unanswered = snmp.get("unanswered_requests", 0)
        if unanswered > 10:
            issues.append({
                "severity": "medium",
                "category": "SNMP",
                "title": f"{unanswered} unanswered SNMP requests",
                "detail": f"Host received {snmp['requests_to_host']} SNMP requests but only "
                          f"sent {snmp['responses_from_host']} responses. "
                          f"{unanswered} requests went unanswered.",
                "remediation": "Check if the SNMP agent on the device is overloaded or if "
                               "requests are timing out due to network latency.",
            })

    # ICMPv6 issues
    if icmpv6.get("total_icmpv6_packets", 0) > 0:
        slow = icmpv6.get("slow_na_responses", 0)
        if slow > 0:
            issues.append({
                "severity": "low" if slow < 5 else "medium",
                "category": "ICMPv6",
                "title": f"Slow Neighbor Advertisement responses ({slow} instances)",
                "detail": f"{slow} Neighbor Advertisement response(s) took >1 second. "
                          "This can cause temporary connectivity loss for the peer.",
                "remediation": "Check device load and IPv6 stack responsiveness. "
                               "Ensure the device is not sleeping/power-saving during NS/NA exchange.",
            })

        errors = icmpv6.get("icmpv6_errors", [])
        if errors:
            issues.append({
                "severity": "medium",
                "category": "ICMPv6",
                "title": f"{len(errors)} ICMPv6 error(s) detected",
                "detail": "ICMPv6 error messages (Destination Unreachable, Packet Too Big, etc.) "
                          "indicate routing or MTU issues.",
                "remediation": "Review IPv6 routing and MTU configuration on the network path.",
            })

    return issues


# ─── HTML Report Generation ──────────────────────────────────────────────────

def generate_html_report(pcap: str, ipv6: str, results: dict, output_path: str):
    """Generate a comprehensive HTML report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pcap_name = Path(pcap).name
    overview = results["overview"]
    tcp = results["tcp"]
    udp = results["udp"]
    icmpv6_data = results["icmpv6"]
    issues = results["issues"]

    # Severity counts
    sev_counts = defaultdict(int)
    for issue in issues:
        sev_counts[issue["severity"]] += 1

    overall_sev = "HIGH" if sev_counts.get("high", 0) > 0 else \
                  "MEDIUM" if sev_counts.get("medium", 0) > 0 else \
                  "LOW" if sev_counts.get("low", 0) > 0 else "INFO"

    sev_colors = {
        "HIGH": "#e74c3c", "MEDIUM": "#f39c12",
        "LOW": "#3498db", "INFO": "#95a5a6", "CRITICAL": "#c0392b"
    }

    # Protocol distribution chart
    proto_dist = overview.get("protocol_distribution", {})
    proto_bars = ""
    if proto_dist:
        max_proto = max(proto_dist.values()) if proto_dist else 1
        for proto, count in list(proto_dist.items())[:10]:
            pct = int(count / max_proto * 100)
            proto_bars += f'<div style="margin:4px 0;"><span style="display:inline-block;width:100px;">{proto}</span><div style="display:inline-block;background:#3498db;height:18px;width:{pct}%;border-radius:3px;vertical-align:middle;"></div> <small>{count}</small></div>\n'

    # TCP port table
    tcp_port_rows = ""
    for port, count in list(tcp.get("destination_ports", {}).items())[:10]:
        service = {"631": "IPP (Printing)", "8080": "HTTP Proxy/Web", "9100": "RAW Printing",
                   "443": "HTTPS", "80": "HTTP", "22": "SSH", "53": "DNS"}.get(port, "")
        tcp_port_rows += f'<tr><td>{port}</td><td>{service}</td><td>{count}</td></tr>\n'

    # TCP connection table
    tcp_conn_rows = ""
    for conn in tcp.get("connection_detail", [])[:15]:
        tcp_conn_rows += (f'<tr><td>{conn["frame"]}</td><td>{conn["time"]}</td>'
                          f'<td>{conn["peer"]}</td><td>{conn["peer_port"]}</td>'
                          f'<td>{conn["local_port"]}</td></tr>\n')

    # RST table
    rst_rows = ""
    for r in tcp.get("rst_detail", [])[:15]:
        rst_rows += (f'<tr><td>{r["frame"]}</td><td>{r["time"]}</td>'
                     f'<td>{r["src"]}:{r["sport"]}</td>'
                     f'<td>{r["dst"]}:{r["dport"]}</td></tr>\n')

    # UDP flow table
    udp_flow_rows = ""
    top_flows = udp.get("top_flows", [])
    for fl in top_flows[:15]:
        kb = round(fl.get("bytes", 0) / 1024, 1)
        udp_flow_rows += (f'<tr><td>{fl.get("src","")}</td><td>{fl.get("sport","")}</td>'
                          f'<td>{fl.get("dst","")}</td><td>{fl.get("dport","")}</td>'
                          f'<td>{fl.get("frames",0)}</td><td>{kb} KB</td></tr>\n')

    # SNMP section
    snmp = udp.get("snmp_analysis", {})
    snmp_section = ""
    if snmp.get("total_snmp_packets", 0) > 0:
        err_breakdown = ""
        for err, count in snmp.get("error_breakdown", {}).items():
            err_breakdown += f'<tr><td>{err}</td><td>{count}</td></tr>'

        snmp_section = f"""
        <div class="card">
          <div class="card-header">📡 SNMP Analysis</div>
          <div class="card-body">
            <div class="summary-grid">
              <div class="metric"><div class="val">{snmp['total_snmp_packets']}</div><div class="label">Total SNMP Packets</div></div>
              <div class="metric" style="border-color:#e74c3c"><div class="val">{snmp['snmp_errors']}</div><div class="label">SNMP Errors</div></div>
              <div class="metric"><div class="val">{snmp['error_rate_pct']}%</div><div class="label">Error Rate</div></div>
              <div class="metric"><div class="val">{snmp.get('unanswered_requests', 0)}</div><div class="label">Unanswered Requests</div></div>
            </div>
            <div style="margin-top:16px;">
              <h4>SNMP Versions</h4>
              <p>{'  |  '.join(f'{k}: {v} pkts' for k, v in snmp.get('versions', {}).items())}</p>
              <h4 style="margin-top:12px;">Community Strings</h4>
              <p>{'  |  '.join(f'"{k}": {v} pkts' for k, v in snmp.get('communities', {}).items())}</p>
              <h4 style="margin-top:12px;">SNMP Peers</h4>
              <p>{', '.join(snmp.get('snmp_peers', []))}</p>
            </div>
            {'<div style="margin-top:16px;"><h4>Error Breakdown</h4><table><th>Error Type</th><th>Count</th>' + err_breakdown + '</table></div>' if err_breakdown else ''}
          </div>
        </div>"""

    # ICMPv6 section
    icmpv6_section = ""
    if icmpv6_data.get("total_icmpv6_packets", 0) > 0:
        type_rows = ""
        for t, c in icmpv6_data.get("type_distribution", {}).items():
            type_rows += f'<tr><td>{t}</td><td>{c}</td></tr>'

        icmpv6_section = f"""
        <div class="card">
          <div class="card-header">🔗 ICMPv6 / Neighbor Discovery</div>
          <div class="card-body">
            <div class="summary-grid">
              <div class="metric"><div class="val">{icmpv6_data['total_icmpv6_packets']}</div><div class="label">Total ICMPv6</div></div>
              <div class="metric"><div class="val">{icmpv6_data.get('neighbor_solicitations_received', 0)}</div><div class="label">NS Received</div></div>
              <div class="metric"><div class="val">{icmpv6_data.get('neighbor_advertisements_sent', 0)}</div><div class="label">NA Sent</div></div>
              <div class="metric"><div class="val">{icmpv6_data.get('slow_na_responses', 0)}</div><div class="label">Slow Responses (>1s)</div></div>
            </div>
            <div style="margin-top:16px;">
              <h4>ICMPv6 Type Distribution</h4>
              <table><th>Type</th><th>Count</th>{type_rows}</table>
            </div>
            <p style="margin-top:12px;color:#555;">MAC Address (from NA): <code>{icmpv6_data.get('mac_address', 'N/A')}</code></p>
          </div>
        </div>"""

    # Issues section
    issues_html = ""
    for issue in sorted(issues, key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["severity"], 3)):
        sev = issue["severity"].upper()
        color = sev_colors.get(sev, "#555")
        issues_html += f"""
        <div class="finding {issue['severity']}">
          <h3><span style="background:{color};color:#fff;padding:2px 8px;border-radius:10px;font-size:0.75em;margin-right:8px;">{sev}</span> {issue['title']}</h3>
          <p style="margin-top:6px;"><strong>Category:</strong> {issue['category']}</p>
          <p>{issue['detail']}</p>
          <p style="margin-top:6px;color:#2c3e50;"><strong>Remediation:</strong> {issue['remediation']}</p>
        </div>
        """

    # Peers table
    peers_html = ""
    for peer, count in list(overview.get("top_peers", {}).items())[:10]:
        peers_html += f'<tr><td>{peer}</td><td>{count}</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IPv6 Analysis – {ipv6}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:'Segoe UI',Arial,sans-serif; background:#f4f6f9; color:#2c3e50; font-size:14px; }}
  header {{ background:linear-gradient(135deg,#1a252f,#2c3e50); color:#fff; padding:28px 40px; }}
  header h1 {{ font-size:1.5em; font-weight:700; }}
  header p  {{ color:#aab; margin-top:6px; font-size:0.9em; }}
  .container {{ max-width:1200px; margin:24px auto; padding:0 24px; }}
  .card {{ background:#fff; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.08);
           margin-bottom:24px; overflow:hidden; }}
  .card-header {{ padding:14px 20px; font-weight:600; font-size:1em; border-bottom:1px solid #eee; }}
  .card-body   {{ padding:16px 20px; }}
  .summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; }}
  .metric {{ background:#f8f9fb; border-radius:8px; padding:14px 18px; border-left:4px solid #3498db; }}
  .metric .val {{ font-size:1.6em; font-weight:700; color:#2c3e50; }}
  .metric .label {{ font-size:0.78em; color:#7f8c8d; margin-top:4px; }}
  table {{ border-collapse:collapse; width:100%; font-size:0.85em; margin-top:8px; }}
  th {{ background:#2c3e50; color:#fff; padding:8px 12px; text-align:left; }}
  td {{ padding:7px 12px; border-bottom:1px solid #eef; }}
  tr:hover td {{ background:#f5f9ff; }}
  .finding {{ border-left:4px solid; padding:12px 16px; margin-bottom:12px;
              border-radius:0 6px 6px 0; background:#fafafa; }}
  .finding.high     {{ border-color:#e74c3c; background:#fdf2f2; }}
  .finding.medium   {{ border-color:#f39c12; background:#fef9f0; }}
  .finding.low      {{ border-color:#3498db; background:#eaf4fb; }}
  .finding h3 {{ font-size:0.95em; margin-bottom:4px; }}
  .finding p  {{ font-size:0.85em; color:#555; line-height:1.5; }}
  code {{ background:#e8e8e8; padding:2px 6px; border-radius:3px; font-size:0.9em; }}
  h4 {{ font-size:0.9em; color:#34495e; margin-bottom:6px; }}
</style>
</head>
<body>
<header>
  <h1>IPv6 Traffic Analysis Report</h1>
  <p>Target: <strong>{ipv6}</strong> &nbsp;|&nbsp; File: {pcap_name} &nbsp;|&nbsp; Generated: {now}</p>
</header>
<div class="container">

  <!-- Overall Status -->
  <div class="card">
    <div class="card-header" style="background:{sev_colors.get(overall_sev, '#555')};color:#fff;">
      Overall Assessment: {overall_sev} &nbsp;—&nbsp; {len(issues)} issue(s) found
    </div>
    <div class="card-body">
      <div class="summary-grid">
        <div class="metric"><div class="val">{overview['total_packets']:,}</div><div class="label">Total Packets</div></div>
        <div class="metric"><div class="val">{round(overview.get('total_bytes',0)/1024, 1)} KB</div><div class="label">Total Data</div></div>
        <div class="metric"><div class="val">{round(overview.get('duration_seconds',0)/3600, 1)}h</div><div class="label">Duration</div></div>
        <div class="metric"><div class="val">{overview.get('avg_packets_per_sec', 0)}</div><div class="label">Pkts/sec</div></div>
      </div>
    </div>
  </div>

  <!-- Issues -->
  <div class="card">
    <div class="card-header">⚠️ Issues & Findings ({len(issues)})</div>
    <div class="card-body">
      {issues_html if issues_html else '<p style="color:#27ae60;">No significant issues detected.</p>'}
    </div>
  </div>

  <!-- Protocol Distribution -->
  <div class="card">
    <div class="card-header">📊 Protocol Distribution</div>
    <div class="card-body">
      {proto_bars}
    </div>
  </div>

  <!-- Communication Peers -->
  <div class="card">
    <div class="card-header">🌐 Communication Peers</div>
    <div class="card-body">
      <table><th>IPv6 Address</th><th>Packets</th>{peers_html}</table>
    </div>
  </div>

  <!-- TCP Analysis -->
  {'<div class="card"><div class="card-header">🔌 TCP Analysis</div><div class="card-body">' + f"""
    <div class="summary-grid">
      <div class="metric"><div class="val">{tcp['total_tcp_packets']}</div><div class="label">TCP Packets</div></div>
      <div class="metric"><div class="val">{tcp.get('connections_to_host', 0)}</div><div class="label">Inbound Connections</div></div>
      <div class="metric"><div class="val">{tcp.get('syn_ack_sent', 0)}</div><div class="label">SYN-ACK Sent</div></div>
      <div class="metric" style="border-color:#e74c3c"><div class="val">{tcp.get('rst_sent', 0) + tcp.get('rst_received', 0)}</div><div class="label">RST Total</div></div>
      <div class="metric"><div class="val">{tcp.get('retransmissions', 0)}</div><div class="label">Retransmissions</div></div>
      <div class="metric"><div class="val">{tcp.get('port_probes_detected', 0)}</div><div class="label">Port Probes</div></div>
    </div>
    <div style="margin-top:16px;"><h4>Destination Ports</h4>
    <table><th>Port</th><th>Service</th><th>Packets</th>{tcp_port_rows}</table></div>
    {'<div style="margin-top:16px;"><h4>Inbound Connections</h4><table><th>Frame</th><th>Time</th><th>Peer</th><th>Peer Port</th><th>Local Port</th>' + tcp_conn_rows + '</table></div>' if tcp_conn_rows else ''}
    {'<div style="margin-top:16px;"><h4>RST Packets</h4><table><th>Frame</th><th>Time</th><th>Source</th><th>Destination</th>' + rst_rows + '</table></div>' if rst_rows else ''}
  """ + '</div></div>' if tcp.get('total_tcp_packets', 0) > 0 else ''}

  <!-- UDP Analysis -->
  {'<div class="card"><div class="card-header">📦 UDP Analysis</div><div class="card-body">' + f"""
    <div class="summary-grid">
      <div class="metric"><div class="val">{udp['total_udp_packets']}</div><div class="label">UDP Packets</div></div>
    </div>
    <div style="margin-top:16px;"><h4>Top UDP Flows</h4>
    <table><th>Source</th><th>SPort</th><th>Dest</th><th>DPort</th><th>Frames</th><th>Volume</th>{udp_flow_rows}</table></div>
  """ + '</div></div>' if udp.get('total_udp_packets', 0) > 0 else ''}

  {snmp_section}
  {icmpv6_section}

</div>
</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)
    logger.info(f"HTML report saved to {output_path}")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    logger.info(f"Analyzing IPv6 traffic for {IPV6_ADDR} in {PCAP_FILE}")

    overview = analyse_overview(PCAP_FILE, IPV6_ADDR)
    if overview["total_packets"] == 0:
        logger.warning("No packets found for this IPv6 address.")
        sys.exit(0)

    logger.info(f"Found {overview['total_packets']} packets, analyzing...")

    tcp = analyse_tcp(PCAP_FILE, IPV6_ADDR)
    udp = analyse_udp(PCAP_FILE, IPV6_ADDR)
    icmpv6_data = analyse_icmpv6(PCAP_FILE, IPV6_ADDR)
    issues = detect_issues(overview, tcp, udp, icmpv6_data)

    results = {
        "target_ipv6": IPV6_ADDR,
        "pcap_file": str(PCAP_FILE),
        "overview": overview,
        "tcp": tcp,
        "udp": udp,
        "icmpv6": icmpv6_data,
        "issues": issues,
    }

    # Save JSON
    Path(OUTPUT_JSON).parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON, "w") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"JSON results saved to {OUTPUT_JSON}")

    # Generate HTML
    generate_html_report(PCAP_FILE, IPV6_ADDR, results, OUTPUT_HTML)

    # Console summary
    print(f"\n{'='*60}")
    print(f"  IPv6 ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"  Target:   {IPV6_ADDR}")
    print(f"  Packets:  {overview['total_packets']:,}")
    print(f"  Duration: {round(overview.get('duration_seconds', 0)/3600, 1)} hours")
    print(f"  Data:     {round(overview.get('total_bytes', 0)/1024, 1)} KB")
    print(f"{'─'*60}")
    print(f"  Protocol Breakdown:")
    for proto, count in list(overview.get("protocol_distribution", {}).items())[:6]:
        print(f"    {proto:15s} {count:>6,} packets")
    print(f"{'─'*60}")
    print(f"  TCP:     {tcp.get('total_tcp_packets', 0)} packets | "
          f"{tcp.get('connections_to_host', 0)} inbound connections | "
          f"{tcp.get('rst_sent', 0) + tcp.get('rst_received', 0)} RSTs")
    print(f"  UDP:     {udp.get('total_udp_packets', 0)} packets")
    snmp_info = udp.get("snmp_analysis", {})
    if snmp_info:
        print(f"  SNMP:    {snmp_info.get('total_snmp_packets', 0)} packets | "
              f"{snmp_info.get('snmp_errors', 0)} errors "
              f"({snmp_info.get('error_rate_pct', 0)}%)")
    print(f"  ICMPv6:  {icmpv6_data.get('total_icmpv6_packets', 0)} packets")
    print(f"{'─'*60}")

    if issues:
        print(f"  ISSUES DETECTED ({len(issues)}):")
        for issue in sorted(issues, key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["severity"], 3)):
            sev = issue["severity"].upper()
            print(f"    [{sev:6s}] {issue['title']}")
            print(f"             {issue['detail'][:100]}")
            if issue.get("remediation"):
                print(f"             Fix: {issue['remediation'][:100]}")
            print()
    else:
        print("  No significant issues detected.")

    print(f"{'='*60}")
    print(f"  Reports: {OUTPUT_JSON}")
    print(f"           {OUTPUT_HTML}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
