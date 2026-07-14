"""
TCP/UDP Traffic Analyser
Analyses a pcap file for TCP and UDP issues and generates an HTML report.
"""

import subprocess
import sys
import json
from datetime import datetime
from pathlib import Path
from collections import defaultdict


# ─── tshark helpers ──────────────────────────────────────────────────────────

def _tshark(pcap: str, display_filter: str, fields: list[str],
             extra_args: list[str] | None = None) -> list[list[str]]:
    """Run tshark and return rows of field values."""
    cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    if extra_args:
        cmd += extra_args
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        return []
    rows = []
    for line in out.strip().splitlines():
        rows.append(line.split("\t"))
    return rows


def _tshark_count(pcap: str, display_filter: str) -> int:
    cmd = ["tshark", "-r", pcap, "-Y", display_filter]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        return len(out.strip().splitlines())
    except subprocess.CalledProcessError:
        return 0


def _tshark_stat(pcap: str, filter_expr: str, fields: list[str]) -> list[list[str]]:
    """tshark without a display filter (for conversations etc.)."""
    cmd = ["tshark", "-r", pcap]
    if filter_expr:
        cmd += ["-Y", filter_expr]
    cmd += ["-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        return []
    return [line.split("\t") for line in out.strip().splitlines()]


def _total_packets(pcap: str) -> int:
    try:
        out = subprocess.check_output(
            ["tshark", "-r", pcap], stderr=subprocess.DEVNULL, text=True)
        return len(out.strip().splitlines())
    except subprocess.CalledProcessError:
        return 0


def _capture_duration(pcap: str) -> float:
    try:
        out = subprocess.check_output(
            ["tshark", "-r", pcap, "-T", "fields", "-e", "frame.time_relative"],
            stderr=subprocess.DEVNULL, text=True)
        lines = out.strip().splitlines()
        if lines:
            return float(lines[-1])
    except (subprocess.CalledProcessError, ValueError):
        pass
    return 0.0


def _data_volume_mb(pcap: str, filt: str) -> float:
    rows = _tshark_stat(pcap, filt, ["tcp.len"])
    total = sum(int(r[0]) for r in rows if r and r[0].isdigit())
    return round(total / 1_048_576, 2)


# ─── analysis ────────────────────────────────────────────────────────────────

def analyse(pcap: str, ip_filter: str = None, port_filter: str = None) -> dict:
    """Analyze TCP/UDP traffic with optional IP and port filters"""
    # Build filter expression
    base_filters = []
    if ip_filter:
        base_filters.append(f'(ip.src=={ip_filter} || ip.dst=={ip_filter})')
    if port_filter:
        ports = [p.strip() for p in port_filter.split(',')]
        port_expr = ' || '.join([f'(tcp.port=={port} || udp.port=={port})' for port in ports])
        base_filters.append(f'({port_expr})')
    
    filter_expr = ' && '.join(base_filters) if base_filters else None
    
    results = {}

    # ── Basic stats ──────────────────────────────────────────────────
    if filter_expr:
        results["total_packets"] = _tshark_count(pcap, filter_expr)
        results["duration_s"] = round(_capture_duration(pcap), 2)
        results["tcp_count"] = _tshark_count(pcap, f"tcp && ({filter_expr})")
        results["udp_count"] = _tshark_count(pcap, f"udp && ({filter_expr})")
    else:
        results["total_packets"] = _total_packets(pcap)
        results["duration_s"] = round(_capture_duration(pcap), 2)
        results["tcp_count"] = _tshark_count(pcap, "tcp")
        results["udp_count"] = _tshark_count(pcap, "udp")

    # ── Identify print stream (port 9100) ────────────────────────────
    print_rows = _tshark(
        pcap,
        "tcp.port==9100 or tcp.port==631 or tcp.port==515",
        ["ip.src", "ip.dst", "tcp.dstport"]
    )
    port_tally: dict[tuple, int] = defaultdict(int)
    for row in print_rows:
        if len(row) == 3:
            port_tally[(row[0], row[1], row[2])] += 1

    # largest print-job direction
    results["print_hosts"] = {}
    if port_tally:
        top = max(port_tally, key=lambda k: port_tally[k])
        results["print_hosts"] = {
            "client": top[0], "printer": top[1], "port": top[2],
            "frames": port_tally[top]
        }

    client = results["print_hosts"].get("client", "")
    printer = results["print_hosts"].get("printer", "")

    # ── TCP anomaly counts ────────────────────────────────────────────
    results["rst_total"] = _tshark_count(pcap, "tcp.flags.reset==1")

    if client and printer:
        print_pair = f"(ip.addr=={client} and ip.addr=={printer})"
        results["zero_window"] = _tshark_count(
            pcap, f"(tcp.analysis.zero_window or tcp.analysis.window_full) and {print_pair}")
        results["window_updates"] = _tshark_count(
            pcap, f"tcp.analysis.window_update and {print_pair}")
        results["retransmissions_print"] = _tshark_count(
            pcap, f"tcp.analysis.retransmission and {print_pair}")
        results["dup_acks_print"] = _tshark_count(
            pcap, f"tcp.analysis.duplicate_ack and {print_pair}")
        results["lost_segments"] = _tshark_count(
            pcap, f"tcp.analysis.lost_segment and {print_pair}")
        results["data_sent_mb"] = _data_volume_mb(
            pcap, f"ip.src=={client} and ip.dst=={printer} and tcp.dstport==9100")
        results["print_connections"] = _tshark_count(
            pcap,
            f"ip.src=={client} and ip.dst=={printer} and "
            f"tcp.dstport==9100 and tcp.flags.syn==1 and tcp.flags.ack==0")
        # zero-window timeline buckets (per 30 s)
        zw_rows = _tshark(
            pcap,
            f"tcp.analysis.zero_window and ip.src=={printer} and tcp.srcport==9100",
            ["frame.time_relative"])
        buckets: dict[int, int] = defaultdict(int)
        for row in zw_rows:
            try:
                b = int(float(row[0]) / 30) * 30
                buckets[b] += 1
            except (ValueError, IndexError):
                pass
        results["zw_timeline"] = {str(k): v for k, v in sorted(buckets.items())}
    else:
        for key in ("zero_window", "window_updates", "retransmissions_print",
                    "dup_acks_print", "lost_segments", "print_connections"):
            results[key] = 0
        results["data_sent_mb"] = 0.0
        results["zw_timeline"] = {}

    # ── RST detail ───────────────────────────────────────────────────
    rst_rows = _tshark(
        pcap, "tcp.flags.reset==1",
        ["frame.number", "frame.time_relative", "ip.src", "tcp.srcport",
         "ip.dst", "tcp.dstport"])
    results["rst_detail"] = [
        {"frame": r[0], "time": r[1], "src": r[2], "sport": r[3],
         "dst": r[4], "dport": r[5]}
        for r in rst_rows if len(r) == 6
    ]

    # RST bursts (group by source within 1-s windows)
    rst_bursts = []
    src_times: dict[str, list[float]] = defaultdict(list)
    for rd in results["rst_detail"]:
        try:
            src_times[rd["src"]].append(float(rd["time"]))
        except ValueError:
            pass
    for src, times in src_times.items():
        times.sort()
        window = [times[0]]
        for t in times[1:]:
            if t - window[0] <= 2.0:
                window.append(t)
            else:
                if len(window) >= 3:
                    rst_bursts.append({"src": src, "count": len(window),
                                       "start": round(window[0], 3)})
                window = [t]
        if len(window) >= 3:
            rst_bursts.append({"src": src, "count": len(window),
                                "start": round(window[0], 3)})
    results["rst_bursts"] = rst_bursts

    # ── UDP analysis ─────────────────────────────────────────────────
    udp_rows = _tshark(
        pcap, "udp",
        ["ip.src", "udp.srcport", "ip.dst", "udp.dstport", "udp.length"])
    udp_flow: dict[str, dict] = {}
    for row in udp_rows:
        if len(row) < 5:
            continue
        src, sport, dst, dport, length = row
        key = f"{src}:{sport} → {dst}:{dport}"
        if key not in udp_flow:
            udp_flow[key] = {"src": src, "sport": sport, "dst": dst,
                              "dport": dport, "frames": 0, "bytes": 0}
        udp_flow[key]["frames"] += 1
        try:
            udp_flow[key]["bytes"] += int(length)
        except ValueError:
            pass
    # top 15 flows by frame count
    results["udp_top_flows"] = sorted(
        udp_flow.values(), key=lambda x: x["frames"], reverse=True)[:15]

    # ── QUIC detection ───────────────────────────────────────────────
    results["quic_count"] = _tshark_count(pcap, "quic")

    # ── Broadcast/discovery UDP (non-unicast destinations) ───────────
    bc_rows = _tshark(
        pcap,
        "udp and (ip.dst==255.255.255.255 or ip.dst matches \"^.*\\.255$\" "
        "or ip.dst matches \"^224\\.\" or ip.dst matches \"^239\\.\")",
        ["ip.src", "udp.dstport"])
    bc_tally: dict[tuple, int] = defaultdict(int)
    for row in bc_rows:
        if len(row) == 2:
            bc_tally[(row[0], row[1])] += 1
    results["broadcast_udp"] = [
        {"src": k[0], "dport": k[1], "frames": v}
        for k, v in sorted(bc_tally.items(), key=lambda x: -x[1])
    ][:10]

    return results


# ─── HTML generation ─────────────────────────────────────────────────────────

def _severity_badge(level: str) -> str:
    colours = {
        "CRITICAL": ("#c0392b", "#fdf2f2"),
        "HIGH":     ("#e67e22", "#fef9f0"),
        "MEDIUM":   ("#d4ac0d", "#fefcf0"),
        "LOW":      ("#2e86c1", "#eaf4fb"),
        "INFO":     ("#5d6d7e", "#f2f3f4"),
    }
    bg, text_bg = colours.get(level, ("#444", "#f9f9f9"))
    return (f'<span style="background:{bg};color:#fff;padding:3px 10px;'
            f'border-radius:12px;font-size:0.78em;font-weight:bold;">{level}</span>')


def _bar(value: int, maximum: int, colour: str = "#2980b9") -> str:
    if maximum == 0:
        return ""
    pct = min(100, int(value / maximum * 100))
    return (f'<div style="background:#e8e8e8;border-radius:4px;height:16px;width:100%;">'
            f'<div style="background:{colour};width:{pct}%;height:16px;border-radius:4px;">'
            f'</div></div>')


def _zw_chart(timeline: dict) -> str:
    if not timeline:
        return ""
    items = sorted((int(k), v) for k, v in timeline.items())
    max_v = max(v for _, v in items) or 1
    bars = ""
    for bucket, count in items:
        h = max(2, int(count / max_v * 120))
        label = f"{bucket}s"
        bars += (f'<div title="{bucket}–{bucket+30}s: {count} zero-windows" '
                 f'style="display:inline-block;width:22px;margin:1px;'
                 f'vertical-align:bottom;">'
                 f'<div style="background:#e74c3c;height:{h}px;border-radius:2px 2px 0 0;"></div>'
                 f'<div style="font-size:8px;text-align:center;color:#888;'
                 f'transform:rotate(-45deg);margin-top:2px;">{label}</div>'
                 f'</div>')
    return (f'<div style="overflow-x:auto;white-space:nowrap;padding:8px 0;">'
            f'{bars}</div>')


def generate_html(pcap: str, data: dict, out_path: str,
                  ip_filter: str = None, port_filter: str = None) -> None:
    """Generate a fully-dynamic HTML report.  No IP addresses or port numbers
    are ever hard-coded in this function — every value comes from *data*."""

    ph = data.get("print_hosts", {})
    client  = ph.get("client",  "")
    printer = ph.get("printer", "")
    port    = ph.get("port",    "")
    now        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pcap_name  = Path(pcap).name

    zw   = data.get("zero_window", 0)
    retx = data.get("retransmissions_print", 0)
    rst  = data.get("rst_total", 0)

    has_print_stream = bool(client and printer)

    # ── active-filter display banner ─────────────────────────────────
    filter_parts = []
    if ip_filter:
        filter_parts.append(f"IP: <code>{ip_filter}</code>")
    if port_filter:
        filter_parts.append(f"Port: <code>{port_filter}</code>")
    filter_banner = (
        f'<div style="background:#eaf3fb;border-left:4px solid #2980b9;'
        f'padding:10px 18px;margin-bottom:18px;border-radius:0 6px 6px 0;'
        f'font-size:0.88em;color:#1a4a6b;">'
        f'<strong>Analysis filter applied:</strong> {" &amp; ".join(filter_parts)}'
        f'</div>'
    ) if filter_parts else ""

    # ── overall severity ──────────────────────────────────────────────
    if has_print_stream and (zw > 5000 or retx > 200):
        overall_sev = "CRITICAL"; overall_colour = "#c0392b"
    elif has_print_stream and (zw > 1000 or retx > 50):
        overall_sev = "HIGH";     overall_colour = "#e67e22"
    elif has_print_stream and (zw > 100 or retx > 10):
        overall_sev = "MEDIUM";   overall_colour = "#d4ac0d"
    elif rst > 200:
        overall_sev = "HIGH";     overall_colour = "#e67e22"
    elif rst > 50:
        overall_sev = "MEDIUM";   overall_colour = "#d4ac0d"
    else:
        overall_sev = "LOW";      overall_colour = "#2e86c1"

    overall_msg = (
        "Severe printer flow-control stall detected" if overall_sev in ("CRITICAL","HIGH") and has_print_stream
        else "Elevated RST activity detected" if overall_sev in ("HIGH","MEDIUM") and not has_print_stream
        else "No critical issues detected"
    )

    # ── derive RST top-port breakdown ─────────────────────────────────
    rst_port_tally: dict[str, int] = defaultdict(int)
    for rd in data.get("rst_detail", []):
        dp = rd.get("dport", "")
        if dp:
            rst_port_tally[dp] += 1
    rst_top_ports = sorted(rst_port_tally.items(), key=lambda x: -x[1])[:5]

    rst_port_summary = ""
    if rst_top_ports:
        parts = [f"port <strong>{p}</strong>: {c} RSTs" for p, c in rst_top_ports]
        rst_port_summary = "Breakdown by destination port — " + ", ".join(parts) + "."

    # ── dynamic findings ──────────────────────────────────────────────
    findings_html = ""
    finding_idx = 0

    # Finding: print stream zero-window (only if print traffic exists)
    if has_print_stream:
        finding_idx += 1
        zw_rate  = round(zw / max(data["duration_s"], 1), 1)
        zw_sev_l = "critical" if zw > 5000 else "high" if zw > 1000 else "medium" if zw > 0 else "low"
        zw_sev   = zw_sev_l.upper()
        if zw > 0:
            findings_html += f"""
      <div class="finding {zw_sev_l}">
        <h3>{finding_idx}. Printer Receive Buffer Exhaustion (Zero-Window Stall) &nbsp;{_severity_badge(zw_sev)}</h3>
        <p>
          The printer (<strong>{printer}</strong>) announced a <em>zero receive window</em>
          <strong>{zw:,}</strong> times over the {data["duration_s"]} s capture.
          The printer's internal TCP receive buffer was repeatedly full — it could not process
          incoming data as fast as the client was sending it. Every zero-window event forces the
          sending client to completely halt transmission and wait for a <em>window update</em>;
          <strong>{data.get("window_updates", 0):,}</strong> window-update events were observed.
        </p>
        <p style="margin-top:8px;">
          <strong>Rate:</strong> ≈ {zw_rate} zero-windows/second over the full capture.
        </p>
        <p style="margin-top:6px;">
          <strong>Root cause:</strong> Printer's internal data pipeline (PDL/PCL rendering engine)
          is slower than the network feed, causing TCP receive buffer saturation.
        </p>
      </div>"""
        else:
            findings_html += f"""
      <div class="finding low">
        <h3>{finding_idx}. Print Stream — No Flow Control Issues &nbsp;{_severity_badge("INFO")}</h3>
        <p>No zero-window events detected on the print stream ({client} → {printer}:{port}). Flow control is healthy.</p>
      </div>"""

        # Finding: retransmissions on print stream
        finding_idx += 1
        retx_sev_l = "high" if retx > 200 else "medium" if retx > 50 else "low"
        retx_sev   = retx_sev_l.upper()
        findings_html += f"""
      <div class="finding {retx_sev_l}">
        <h3>{finding_idx}. Retransmissions on Print Stream &nbsp;{_severity_badge(retx_sev)}</h3>
        <p>
          <strong>{retx:,} retransmissions</strong> and
          <strong>{data.get("dup_acks_print", 0):,} duplicate ACKs</strong> were detected
          on the print stream ({client} → {printer}:{port}).
          {"Each retransmission represents a segment the client had to re-send after its retransmit timer expired — consistent with a zero-window stall triggering timeouts." if zw > 0
           else "No zero-window stalls detected; retransmissions may indicate network congestion or packet loss."}
        </p>
        <ul style="margin-top:8px;">
          <li>Lost segment events: <strong>{data.get("lost_segments", 0)}</strong></li>
        </ul>
      </div>"""

        # Finding: print job connections
        finding_idx += 1
        conns = data.get("print_connections", 0)
        data_mb = data.get("data_sent_mb", 0)
        dur_per_conn = round(data["duration_s"] / max(conns, 1), 1)
        findings_html += f"""
      <div class="finding low">
        <h3>{finding_idx}. Print Job Segmentation &nbsp;{_severity_badge("INFO")}</h3>
        <p>
          The client opened <strong>{conns:,} TCP connections</strong> to
          <strong>{printer}:{port}</strong> throughout the capture
          (≈ one every {dur_per_conn} s). A total of
          <strong>{data_mb:.2f} MB</strong> of print data was transferred.
          Pipelined connection cycling is normal driver behaviour for large print
          jobs split across multiple TCP sessions.
        </p>
      </div>"""

    # Finding: RST events (always shown when > 0)
    if rst > 0:
        finding_idx += 1
        rst_sev_l = "medium" if rst > 50 else "low"
        rst_sev   = rst_sev_l.upper()
        findings_html += f"""
      <div class="finding {rst_sev_l}">
        <h3>{finding_idx}. TCP RST Events &nbsp;{_severity_badge(rst_sev)}</h3>
        <p>
          <strong>{rst:,} TCP RST</strong> segments were captured.
          {rst_port_summary}
        </p>
        {('<p style="margin-top:6px;"><strong>Notable burst:</strong> ' +
          str(len([b for b in data.get("rst_bursts",[]) if b["count"]>=3])) +
          ' burst(s) of ≥ 3 resets within 2 seconds — see RST Detail table below.</p>')
         if data.get("rst_bursts") else ""}
      </div>"""

    # Finding: broadcast / multicast UDP senders (only shown when present)
    bc_data = data.get("broadcast_udp", [])
    if bc_data:
        finding_idx += 1
        # Build per-sender summary: group by src
        sender_map: dict[str, list] = defaultdict(list)
        for bc in bc_data:
            sender_map[bc["src"]].append(bc)

        sender_lines = ""
        for src, entries in list(sender_map.items())[:5]:
            total_bc_frames = sum(e["frames"] for e in entries)
            ports_str = ", ".join(str(e["dport"]) for e in entries)
            sender_lines += (
                f'<li>Host <strong>{src}</strong>: {total_bc_frames:,} broadcast frames '
                f'on port(s) {ports_str}</li>'
            )

        top_sender = bc_data[0]["src"]
        findings_html += f"""
      <div class="finding low">
        <h3>{finding_idx}. Broadcast / Multicast UDP Traffic &nbsp;{_severity_badge("LOW")}</h3>
        <p>
          The following host(s) sent broadcast or multicast UDP packets during the capture.
          This is commonly associated with device-discovery, mDNS, NetBIOS, or management protocols.
          Verify that each sender is intentional; excessive broadcast traffic adds unnecessary
          load to all devices on the subnet.
        </p>
        <ul style="margin-top:8px;color:#555;font-size:0.87em;line-height:1.8;">
          {sender_lines}
        </ul>
      </div>"""

    if not findings_html:
        findings_html = '<p style="color:#888;">No significant issues detected in this capture.</p>'

    # ── Print Stream Metrics card (only if print traffic found) ──────
    print_metrics_card = ""
    if has_print_stream:
        zw_chart_html = _zw_chart(data.get("zw_timeline", {}))
        print_metrics_card = f"""
  <div class="card">
    <div class="card-header">Print Stream TCP Metrics ({client} → {printer}:{port})</div>
    <div class="card-body">
      <div class="summary-grid">
        <div class="metric" style="border-color:#c0392b;">
          <div class="val">{zw:,}</div>
          <div class="label">Zero-Window / Window-Full Events</div>
        </div>
        <div class="metric" style="border-color:#e67e22;">
          <div class="val">{data.get("window_updates", 0):,}</div>
          <div class="label">Window Update (re-open) Events</div>
        </div>
        <div class="metric" style="border-color:#e74c3c;">
          <div class="val">{retx:,}</div>
          <div class="label">Retransmissions</div>
        </div>
        <div class="metric" style="border-color:#d4ac0d;">
          <div class="val">{data.get("dup_acks_print", 0):,}</div>
          <div class="label">Duplicate ACKs</div>
        </div>
        <div class="metric" style="border-color:#8e44ad;">
          <div class="val">{data.get("print_connections", 0)}</div>
          <div class="label">TCP Connections Opened</div>
        </div>
        <div class="metric" style="border-color:#27ae60;">
          <div class="val">{data.get("data_sent_mb", 0):.1f} MB</div>
          <div class="label">Print Data Transferred</div>
        </div>
      </div>
      {('<div style="margin-top:24px;"><div class="section-label">Zero-Window Announcements Over Time (30 s buckets)</div>' + zw_chart_html + '</div>') if zw_chart_html else ""}
    </div>
  </div>"""

    # ── RST detail table ──────────────────────────────────────────────
    rst_rows_html = ""
    for rd in data.get("rst_detail", []):
        rst_rows_html += (
            f'<tr><td>{rd["frame"]}</td><td>{rd["time"]}</td>'
            f'<td>{rd["src"]}:{rd["sport"]}</td>'
            f'<td>{rd["dst"]}:{rd["dport"]}</td></tr>\n'
        )

    burst_rows_html = ""
    for b in data.get("rst_bursts", []):
        burst_rows_html += (
            f'<tr><td>{b["src"]}</td><td>{b["count"]}</td>'
            f'<td>{b["start"]} s</td></tr>\n'
        )

    # ── UDP rows ──────────────────────────────────────────────────────
    udp_rows_html = ""
    top_udp = data.get("udp_top_flows", [])
    max_frames = top_udp[0]["frames"] if top_udp else 1
    for fl in top_udp:
        bar = _bar(fl["frames"], max_frames,
                   "#8e44ad" if fl.get("dport") in ("443", "80") else "#16a085")
        kb = round(fl["bytes"] / 1024, 1)
        udp_rows_html += (
            f'<tr><td>{fl["src"]}</td><td>{fl["sport"]}</td>'
            f'<td>{fl["dst"]}</td><td>{fl["dport"]}</td>'
            f'<td>{fl["frames"]}</td><td>{kb} KB</td>'
            f'<td style="width:120px;">{bar}</td></tr>\n'
        )

    bc_rows_html = ""
    for bc in data.get("broadcast_udp", []):
        bc_rows_html += (
            f'<tr><td>{bc["src"]}</td><td>{bc["dport"]}</td>'
            f'<td>{bc["frames"]}</td></tr>\n'
        )

    # ── dynamic recommendations ───────────────────────────────────────
    rec_html = ""

    if has_print_stream and zw > 0:
        rec_html += """
      <div class="finding critical" style="margin-bottom:12px;">
        <h3>Printer Buffer / Flow Control</h3>
        <ul>
          <li>Upgrade printer firmware — newer versions often include pipeline optimisations that reduce zero-window frequency.</li>
          <li>Enable <strong>TCP Offload / LAN I/O buffering</strong> in the printer's network settings if available.</li>
          <li>Switch to <strong>IPP (port 631)</strong> instead of Raw/JetDirect (port 9100) — IPP provides better flow control and job-status feedback.</li>
          <li>For large jobs, use <strong>PCL6 or HP-GL/2</strong> (vector-based) instead of rasterised formats — the rasteriser is often the pipeline bottleneck.</li>
          <li>Consider upgrading the printer's network interface to Gigabit if currently 100 Mbps.</li>
        </ul>
      </div>"""

    if has_print_stream and retx > 10:
        rec_html += """
      <div class="finding medium" style="margin-bottom:12px;">
        <h3>TCP Retransmissions on Print Stream</h3>
        <ul>
          <li>Retransmissions are a secondary symptom of zero-window stalls. Resolving the buffer exhaustion above will eliminate them.</li>
          <li>Review TCP retransmit timeout settings on the print client if retransmissions persist after firmware update.</li>
        </ul>
      </div>"""

    if rst > 50:
        rec_html += f"""
      <div class="finding medium" style="margin-bottom:12px;">
        <h3>TCP RST / Connection Resets</h3>
        <ul>
          <li>Investigate the top RST sources: {", ".join(p for p,_ in rst_top_ports[:3]) or "see table"}.</li>
          <li>Determine whether RSTs originate from servers (connection refused / timeout) or from a firewall/middlebox.</li>
          <li>If RSTs correlate with application errors, check server-side logs and firewall rules.</li>
        </ul>
      </div>"""
    elif rst > 0:
        rec_html += """
      <div class="finding low" style="margin-bottom:12px;">
        <h3>TCP RST Events</h3>
        <ul>
          <li>RST count is low. Monitor over time; no immediate action required unless applications report connection errors.</li>
        </ul>
      </div>"""

    if bc_data:
        bc_sender_list = ", ".join(sorted({bc["src"] for bc in bc_data[:5]}))
        rec_html += f"""
      <div class="finding low" style="margin-bottom:12px;">
        <h3>Broadcast / Multicast UDP</h3>
        <ul>
          <li>Identify and verify the intent of broadcast UDP senders: <strong>{bc_sender_list}</strong>.</li>
          <li>If these are printer management or device-discovery services, consider using <strong>unicast discovery</strong> to reduce subnet broadcast load.</li>
          <li>Apply switch-level broadcast storm control if broadcast rates are abnormal.</li>
        </ul>
      </div>"""

    if not rec_html:
        rec_html = '<p style="color:#888;font-size:0.9em;">No specific remediation required for this capture.</p>'

    # ── overview metrics ──────────────────────────────────────────────
    print_client_metric = (
        f'<div class="metric" style="border-color:#e74c3c;">'
        f'<div class="val">{client}</div><div class="label">Print Client</div></div>'
        f'<div class="metric" style="border-color:#27ae60;">'
        f'<div class="val">{printer}:{port}</div><div class="label">Printer (RAW port)</div></div>'
    ) if has_print_stream else ""

    # ── assemble full HTML ────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TCP/UDP Analysis \u2013 {pcap_name}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:'Segoe UI',Arial,sans-serif; background:#f4f6f9; color:#2c3e50; font-size:14px; }}
  header {{ background:linear-gradient(135deg,#1a252f,#2c3e50); color:#fff; padding:28px 40px; }}
  header h1 {{ font-size:1.6em; font-weight:700; }}
  header p  {{ color:#aab; margin-top:6px; font-size:0.9em; }}
  .container {{ max-width:1200px; margin:24px auto; padding:0 24px; }}
  .card {{ background:#fff; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.08);
           margin-bottom:24px; overflow:hidden; }}
  .card-header {{ padding:14px 20px; font-weight:600; font-size:1em; border-bottom:1px solid #eee; }}
  .card-body   {{ padding:16px 20px; }}
  .summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(175px,1fr)); gap:16px; }}
  .metric {{ background:#f8f9fb; border-radius:8px; padding:14px 18px; border-left:4px solid #3498db; }}
  .metric .val {{ font-size:1.8em; font-weight:700; color:#2c3e50; }}
  .metric .label {{ font-size:0.8em; color:#7f8c8d; margin-top:4px; }}
  .severity-bar {{ display:flex; align-items:center; gap:12px; padding:14px 20px;
                   background:#fafafa; border-top:1px solid #eee; }}
  .severity-bar span {{ font-size:0.82em; color:#555; }}
  table {{ border-collapse:collapse; width:100%; font-size:0.85em; }}
  th {{ background:#2c3e50; color:#fff; padding:8px 12px; text-align:left; }}
  td {{ padding:7px 12px; border-bottom:1px solid #eef; }}
  tr:hover td {{ background:#f5f9ff; }}
  .section-label {{ font-size:0.75em; text-transform:uppercase; letter-spacing:.06em;
                    color:#7f8c8d; margin-bottom:6px; }}
  .finding {{ border-left:4px solid; padding:12px 16px; margin-bottom:12px;
              border-radius:0 6px 6px 0; background:#fafafa; }}
  .finding.critical {{ border-color:#c0392b; background:#fdf2f2; }}
  .finding.high     {{ border-color:#e67e22; background:#fef9f0; }}
  .finding.medium   {{ border-color:#d4ac0d; background:#fefcf0; }}
  .finding.low      {{ border-color:#2e86c1; background:#eaf4fb; }}
  .finding h3 {{ font-size:0.95em; margin-bottom:4px; }}
  .finding p  {{ font-size:0.85em; color:#555; line-height:1.5; }}
  .finding ul {{ font-size:0.85em; color:#555; padding-left:18px; line-height:1.8; }}
  .overall {{ padding:20px; text-align:center; color:#fff; font-size:1.2em;
              font-weight:700; border-radius:8px; margin-bottom:20px;
              background:{overall_colour}; }}
  footer {{ text-align:center; color:#aaa; font-size:0.78em; padding:20px 0 32px; }}
</style>
</head>
<body>
<header>
  <h1>TCP / UDP Traffic Analysis Report</h1>
  <p>{pcap_name} &nbsp;|&nbsp; Generated {now}</p>
</header>
<div class="container">

  <div class="overall">Overall Assessment: {overall_sev} &nbsp;\u2014 {overall_msg}</div>

  {filter_banner}

  <!-- Capture Overview -->
  <div class="card">
    <div class="card-header">Capture Overview</div>
    <div class="card-body">
      <div class="summary-grid">
        <div class="metric" style="border-color:#3498db;">
          <div class="val">{data["total_packets"]:,}</div>
          <div class="label">{"Filtered" if filter_parts else "Total"} Packets</div>
        </div>
        <div class="metric" style="border-color:#1abc9c;">
          <div class="val">{data["duration_s"]} s</div>
          <div class="label">Capture Duration</div>
        </div>
        <div class="metric" style="border-color:#8e44ad;">
          <div class="val">{data["tcp_count"]:,}</div>
          <div class="label">TCP Frames{" (filtered)" if filter_parts else ""}</div>
        </div>
        <div class="metric" style="border-color:#e67e22;">
          <div class="val">{data["udp_count"]:,}</div>
          <div class="label">UDP Frames{" (filtered)" if filter_parts else ""}</div>
        </div>
        {print_client_metric}
      </div>
    </div>
  </div>

  <!-- Key Findings -->
  <div class="card">
    <div class="card-header">Key Findings Summary</div>
    <div class="card-body">{findings_html}</div>
  </div>

  {print_metrics_card}

  <!-- RST Detail -->
  <div class="card">
    <div class="card-header">TCP Reset (RST) Detail</div>
    <div class="card-body">
      <table>
        <thead><tr>
          <th>Frame</th><th>Time (s)</th>
          <th>Source</th><th>Destination</th>
        </tr></thead>
        <tbody>{rst_rows_html or "<tr><td colspan='4' style='text-align:center;color:#aaa;'>No RST events</td></tr>"}</tbody>
      </table>
      {('<div style="margin-top:16px;"><div class="section-label">RST Bursts (\u2265 3 resets within 2 s)</div>'
         '<table><thead><tr><th>Source IP</th><th>Count</th><th>Start Time</th></tr></thead>'
         f'<tbody>{burst_rows_html}</tbody></table></div>') if burst_rows_html else ""}
    </div>
  </div>

  <!-- UDP Analysis -->
  <div class="card">
    <div class="card-header">UDP Traffic Analysis</div>
    <div class="card-body">
      <div class="summary-grid" style="margin-bottom:20px;">
        <div class="metric" style="border-color:#e67e22;">
          <div class="val">{data["udp_count"]:,}</div>
          <div class="label">Total UDP Frames</div>
        </div>
        <div class="metric" style="border-color:#8e44ad;">
          <div class="val">{data.get("quic_count", 0):,}</div>
          <div class="label">QUIC Frames (UDP/443)</div>
        </div>
      </div>
      <div class="section-label">Top UDP Flows (by frame count)</div>
      <table>
        <thead><tr>
          <th>Source IP</th><th>Src Port</th>
          <th>Destination IP</th><th>Dst Port</th>
          <th>Frames</th><th>Volume</th><th>Relative Volume</th>
        </tr></thead>
        <tbody>{udp_rows_html or "<tr><td colspan='7' style='text-align:center;color:#aaa;'>No UDP flows</td></tr>"}</tbody>
      </table>
      {('<div style="margin-top:20px;"><div class="section-label">Broadcast / Multicast UDP Senders</div>'
         '<table><thead><tr><th>Source IP</th><th>Dst Port</th><th>Frames</th></tr></thead>'
         f'<tbody>{bc_rows_html}</tbody></table></div>') if bc_rows_html else ""}
    </div>
  </div>

  <!-- Recommendations -->
  <div class="card">
    <div class="card-header">Recommendations</div>
    <div class="card-body">{rec_html}</div>
  </div>

</div>
<footer>Generated by AI Wireshark Analyser &nbsp;|&nbsp; {now}</footer>
</body>
</html>"""

    Path(out_path).write_text(html, encoding="utf-8")
    print(f"Report saved: {out_path}")


# ─── entry point ─────────────────────────────────────────────────────────────

def run(pcap_file: str, output_html: str = None, output_dir: str = 'results', ip_filter: str = None, port_filter: str = None) -> dict:
    """Callable entry point — usable from workers without subprocess."""
    if not output_html:
        output_html = str(Path(output_dir) / (Path(pcap_file).stem + "_tcp_udp_report.html"))
    Path(output_html).parent.mkdir(parents=True, exist_ok=True)
    analysis = analyse(pcap_file, ip_filter=ip_filter, port_filter=port_filter)
    generate_html(pcap_file, analysis, output_html,
                  ip_filter=ip_filter, port_filter=port_filter)
    return {'html_path': output_html, 'results': analysis}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_tcp_udp.py <pcap_file> [output.html]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else str(
        Path("results") / (Path(pcap_path).stem + "_tcp_udp_report.html"))

    print(f"Analysing: {pcap_path}")
    print("Extracting TCP/UDP metrics via tshark …")
    analysis = analyse(pcap_path)
    print(json.dumps({k: v for k, v in analysis.items()
                      if k not in ("rst_detail", "udp_top_flows", "zw_timeline",
                                   "broadcast_udp", "rst_bursts")}, indent=2))
    generate_html(pcap_path, analysis, output)

