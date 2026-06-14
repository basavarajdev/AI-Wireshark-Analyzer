#!/usr/bin/env python3
"""Build combined comprehensive network monitor HTML report."""
import json
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict


def _extract_rf_from_channel_jsons(channel_jsons_dir: str) -> dict:
    """Extract RF metrics from per-channel monitor JSON outputs.

    Looks for files matching ch_monitor_*_ch<N>.json or similar patterns.
    Returns dict mapping channel number -> RF metrics dict.
    """
    rf = {}
    dir_path = Path(channel_jsons_dir)
    if not dir_path.exists():
        return rf

    for json_file in sorted(dir_path.glob("*.json")):
        try:
            data = json.loads(json_file.read_text())
        except (json.JSONDecodeError, OSError):
            continue

        overall = data.get("overall", {})
        if not overall:
            continue

        # Determine channel from the data
        channels_seen = overall.get("channels_seen", [])
        if not channels_seen:
            continue
        ch = channels_seen[0] if len(channels_seen) == 1 else channels_seen[0]

        # Extract metrics
        frame_types = overall.get("frame_types", {})
        total_frames = sum(frame_types.values()) if frame_types else 1
        ctrl_pct = (frame_types.get("ctrl", 0) / total_frames * 100) if total_frames else 0

        bssid_stats = overall.get("bssid_stats", {})
        client_stats = overall.get("client_stats", {})

        util = overall.get("utilisation_pct", 0) or 0
        retry = (overall.get("retry_rate", 0) or 0) * 100
        rts = (overall.get("rts_per_data_frame", 0) or 0) * 100

        # Determine status
        issues = []
        status_cls = "ok"
        if retry >= 20:
            issues.append("High retry")
            status_cls = "bad"
        if ctrl_pct >= 20:
            issues.append("Control overhead")
            status_cls = "bad"
        if rts >= 15:
            issues.append("Hidden node")
            if status_cls != "bad":
                status_cls = "warn" if rts < 30 else "bad"
        if util >= 35:
            issues.append("High utilization")
            if status_cls == "ok":
                status_cls = "warn"

        status = " + ".join(issues) if issues else "OK"

        rf[ch] = {
            "util": round(util, 1),
            "retry": round(retry, 1),
            "ctrl": round(ctrl_pct, 1),
            "rts": round(rts, 1),
            "nav": 0,  # NAV not always available in JSON
            "bssids_rf": len(bssid_stats),
            "clients_rf": len(client_stats),
            "status": status,
            "status_cls": status_cls,
        }

    return rf


def run(client_map_json: str, channel_jsons_dir: str = None, output_dir: str = 'results') -> dict:
    """Build combined comprehensive network report.

    Args:
        client_map_json: Path to client_network_map.json with per-channel client data.
        channel_jsons_dir: Directory containing per-channel monitor JSON files for RF data.
                          If None, attempts to use same directory as client_map_json.
        output_dir: Directory to write the output HTML report.

    Returns:
        dict with 'html_path' key (or 'error' on failure).
    """
    client_map_path = Path(client_map_json)
    if not client_map_path.exists():
        return {'error': f'Client map JSON not found: {client_map_json}', 'html_path': None}

    try:
        data = json.loads(client_map_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return {'error': f'Failed to read client map JSON: {e}', 'html_path': None}

    # Extract RF data from channel monitor JSONs
    if channel_jsons_dir is None:
        channel_jsons_dir = str(client_map_path.parent)

    RF = _extract_rf_from_channel_jsons(channel_jsons_dir)
    if not RF:
        return {'error': 'No channel monitor JSON data found for RF metrics. '
                        'Provide a directory with per-channel monitor JSONs.',
                'html_path': None}

    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    html_path = str(output_dir_path / "comprehensive_network_report.html")

    _build_report(data, RF, html_path)
    return {'html_path': html_path, 'json_path': None}


def _build_report(data: dict, RF: dict, html_path: str):
    """Internal: generate the combined report HTML."""
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build client map summary from data
    CM = {}
    for ch_str, ch_data in data.items():
        ch = int(ch_str)
        CM[ch] = {
            "aps":       ch_data.get("n_aps", 0),
            "assoc":     sum(1 for c in ch_data["clients"].values() if c.get("primary_ssid")),
            "scan":      sum(1 for c in ch_data["clients"].values()
                            if not c.get("primary_ssid") and not c.get("primary_bssid")),
            "total":     len(ch_data["clients"]),
            "ssids":     len(set(ch_data["bssid_ssid"].values())),
            "bssid_ssid": ch_data["bssid_ssid"],
            "clients":   ch_data["clients"],
        }

    # Use only channels that have both RF and CM data
    available_channels = sorted(set(RF.keys()) & set(CM.keys()))
    if not available_channels:
        Path(html_path).write_text("<html><body><h1>No matching channel data</h1></body></html>")
        return

    # ── Helpers ────────────────────────────────────────────────────────────────────
    def esc(s):
        if s is None: return "—"
        return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    def cls_util(v):
        return "bad" if v >= 35 else "warn" if v >= 20 else "ok"

    def cls_retry(v):
        return "bad" if v >= 20 else "warn" if v >= 5 else "ok"

    def cls_rts(v):
        return "bad" if v >= 30 else "warn" if v >= 10 else "ok"

    def cls_ctrl(v):
        return "bad" if v >= 25 else "warn" if v >= 10 else "ok"

    def nav_badge(nav):
        if nav >= 32000: return '<span class="badge badge-bad">Max NAV</span>'
        if nav >= 20000: return '<span class="badge badge-warn">High NAV</span>'
        return ""

    def score(ch):
        """Compute a 0-100 health score (higher = healthier)."""
        r = RF[ch]
        s = 100
        s -= min(r["util"], 40) * 0.5        # utilization penalty
        s -= min(r["retry"], 80) * 0.4       # retry penalty
        s -= min(r["rts"], 60) * 0.3         # RTS penalty (hidden node)
        s -= min(r["ctrl"], 40) * 0.2        # control overhead penalty
        if r["nav"] >= 32000: s -= 5
        return max(0, round(s))

    def health_cls(s):
        return "bad" if s < 45 else "warn" if s < 70 else "ok"

    def sparkbar(pct, cls):
        return f'<div class="sparkbar"><div class="sparkfill fill-{cls}" style="width:{min(pct,100):.0f}%"></div></div>'

    # Per-channel issues badge list
    def issue_badges(ch):
        r = RF[ch]
        badges = []
        if r["retry"] >= 60:  badges.append('<span class="badge badge-bad">Extreme Retry</span>')
        elif r["retry"] >= 20: badges.append('<span class="badge badge-bad">High Retry</span>')
        elif r["retry"] >= 5: badges.append('<span class="badge badge-warn">Elevated Retry</span>')
        if r["rts"] >= 30:    badges.append('<span class="badge badge-bad">Hidden Node</span>')
        elif r["rts"] >= 10:  badges.append('<span class="badge badge-warn">RTS Overhead</span>')
        if r["ctrl"] >= 25:   badges.append('<span class="badge badge-bad">Ctrl Overhead</span>')
        if r["nav"] >= 32000: badges.append('<span class="badge badge-warn">Max NAV</span>')
        if r["util"] >= 35:   badges.append('<span class="badge badge-warn">High Util</span>')
        if not badges:        badges.append('<span class="badge badge-ok">Healthy</span>')
        return " ".join(badges)

    # ── AP table for a channel ─────────────────────────────────────────────────────
    def ap_table(ch):
        bssid_ssid = CM[ch]["bssid_ssid"]
        if not bssid_ssid:
            return "<p>No APs detected.</p>"
        rows = []
        for bssid, ssid in sorted(bssid_ssid.items(), key=lambda x: x[1] or ""):
            rows.append(f"<tr><td class='mono'>{esc(bssid)}</td><td>{esc(ssid) if ssid else '<em>Hidden</em>'}</td></tr>")
        return (
            f"<table><thead><tr><th>BSSID</th><th>SSID</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    # ── Client table for a channel ─────────────────────────────────────────────────
    def client_table(ch):
        clients = CM[ch]["clients"]
        if not clients:
            return "<p>No confirmed wireless clients detected on this channel during capture.</p>"
        rows = []
        for mac, info in sorted(clients.items(), key=lambda x: x[1].get("avg_signal_dbm") or -999, reverse=True):
            role = info.get("role","client")
            if role == "AP": continue
            ssid  = esc(info.get("primary_ssid"))
            bssid = esc(info.get("primary_bssid"))
            sig   = info.get("avg_signal_dbm")
            sig_s = f"{sig:.0f} dBm" if sig else "—"
            sig_c = "bad" if sig and sig < -80 else "warn" if sig and sig < -70 else "ok"
            frames = info.get("total_frames", 0)
            retry  = info.get("retry_rate", 0) * 100
            r_c    = "bad" if retry >= 20 else "warn" if retry >= 8 else "ok"
            rows.append(
                f"<tr><td class='mono'>{esc(mac)}</td>"
                f"<td>{ssid if info.get('primary_ssid') else '<em>Scanning</em>'}</td>"
                f"<td class='mono small'>{bssid if info.get('primary_bssid') else '—'}</td>"
                f"<td class='num {sig_c}'>{sig_s}</td>"
                f"<td class='num'>{frames}</td>"
                f"<td class='num {r_c}'>{retry:.0f}%</td></tr>"
            )
        if not rows:
            return "<p>No confirmed wireless clients detected on this channel during capture.</p>"
        return (
            "<table><thead><tr><th>Client MAC</th><th>SSID / Association</th>"
            "<th>BSSID</th><th>Avg Signal</th><th>Frames TX</th><th>Retry%</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    # ── Build per-channel detail sections ─────────────────────────────────────────
    def channel_sections():
        sections = []
        for ch in available_channels:
            r  = RF[ch]
            cm = CM.get(ch, {})
            sc = score(ch)
            hc = health_cls(sc)
            sections.append(f"""
    <div class="ch-section" id="ch{ch}">
      <div class="ch-header">
        <span class="ch-label">CH {ch}</span>
        <span class="health-badge {hc}">Health {sc}/100</span>
        <span class="ch-status">{issue_badges(ch)}</span>
      </div>
      <div class="ch-grid">
        <div class="metric-card">
          <div class="metric-label">Channel Utilization</div>
          <div class="metric-val {cls_util(r['util'])}">{r['util']:.1f}%</div>
          {sparkbar(r['util'], cls_util(r['util']))}
        </div>
        <div class="metric-card">
          <div class="metric-label">Retry Rate</div>
          <div class="metric-val {cls_retry(r['retry'])}">{r['retry']:.1f}%</div>
          {sparkbar(r['retry'], cls_retry(r['retry']))}
        </div>
        <div class="metric-card">
          <div class="metric-label">Control Frame %</div>
          <div class="metric-val {cls_ctrl(r['ctrl'])}">{r['ctrl']:.1f}%</div>
          {sparkbar(r['ctrl'], cls_ctrl(r['ctrl']))}
        </div>
        <div class="metric-card">
          <div class="metric-label">RTS/Data %</div>
          <div class="metric-val {cls_rts(r['rts'])}">{r['rts']:.1f}%</div>
          {sparkbar(r['rts'], cls_rts(r['rts']))}
        </div>
        <div class="metric-card">
          <div class="metric-label">Max NAV</div>
          <div class="metric-val">{r['nav']:,} µs {nav_badge(r['nav'])}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">APs Detected</div>
          <div class="metric-val">{cm.get('aps','—')}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Confirmed Clients</div>
          <div class="metric-val">{cm.get('total',0) - cm.get('aps',0)}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Unique SSIDs</div>
          <div class="metric-val">{cm.get('ssids','—')}</div>
        </div>
      </div>
      <div class="ch-tabs">
        <button class="tab-btn active" onclick="switchTab(this,'aps-{ch}')">APs ({cm.get('aps',0)})</button>
        <button class="tab-btn" onclick="switchTab(this,'cli-{ch}')">Clients ({cm.get('total',0) - cm.get('aps',0)})</button>
      </div>
      <div class="tab-pane active" id="aps-{ch}">{ap_table(ch)}</div>
      <div class="tab-pane" id="cli-{ch}">{client_table(ch)}</div>
    </div>""")
        return "\n".join(sections)

    # ── Summary table rows ────────────────────────────────────────────────────────
    def summary_rows():
        rows = []
        for ch in available_channels:
            r  = RF[ch]
            cm = CM.get(ch, {})
            sc = score(ch)
            hc = health_cls(sc)
            total_clients = cm.get('total', 0) - cm.get('aps', 0)
            rows.append(f"""
    <tr onclick="document.getElementById('ch{ch}').scrollIntoView({{behavior:'smooth'}})">
      <td><a href="#ch{ch}" class="ch-link">CH {ch}</a></td>
      <td><span class="health-dot {hc}"></span> {sc}</td>
      <td class="num {cls_util(r['util'])}">{r['util']:.1f}%</td>
      <td class="num {cls_retry(r['retry'])}">{r['retry']:.1f}%</td>
      <td class="num {cls_ctrl(r['ctrl'])}">{r['ctrl']:.1f}%</td>
      <td class="num {cls_rts(r['rts'])}">{r['rts']:.1f}%</td>
      <td class="num">{r['nav']:,}</td>
      <td class="num">{cm.get('aps','—')}</td>
      <td class="num">{total_clients}</td>
      <td class="num">{cm.get('assoc',0)}</td>
      <td class="num">{cm.get('scan',0)}</td>
      <td class="num">{cm.get('ssids','—')}</td>
      <td>{issue_badges(ch)}</td>
    </tr>""")
        return "\n".join(rows)

    # ── HTML ──────────────────────────────────────────────────────────────────────
    HTML = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>Comprehensive WLAN Network Monitor Report</title>
    <style>
    :root{{
      --bg:#0f1117;--bg2:#1a1d27;--bg3:#22263a;--border:#2e3350;
      --ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--blue:#60a5fa;
      --text:#e2e8f0;--sub:#94a3b8;--mono:#a5f3fc;
      --ok-bg:rgba(34,197,94,.15);--warn-bg:rgba(245,158,11,.15);--bad-bg:rgba(239,68,68,.15);
    }}
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.5}}
    a{{color:var(--blue);text-decoration:none}}
    /* Header */
    .hero{{background:linear-gradient(135deg,#1e2a4a 0%,#0f1117 100%);padding:36px 40px 28px;border-bottom:1px solid var(--border)}}
    .hero h1{{font-size:1.9rem;font-weight:700;color:#fff;letter-spacing:-0.5px}}
    .hero .meta{{color:var(--sub);font-size:0.85rem;margin-top:6px}}
    /* Summary cards */
    .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;padding:24px 40px}}
    .card{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px}}
    .card-label{{color:var(--sub);font-size:0.78rem;text-transform:uppercase;letter-spacing:.05em}}
    .card-val{{font-size:1.7rem;font-weight:700;margin-top:4px}}
    /* Summary table */
    .section{{padding:0 40px 32px}}
    .section-title{{font-size:1.05rem;font-weight:600;color:var(--blue);margin-bottom:14px;padding-bottom:6px;border-bottom:1px solid var(--border)}}
    table{{width:100%;border-collapse:collapse;font-size:13px}}
    thead th{{background:var(--bg3);color:var(--sub);padding:8px 10px;text-align:left;font-weight:600;font-size:0.78rem;text-transform:uppercase;letter-spacing:.04em;position:sticky;top:0;z-index:1}}
    tbody tr{{border-bottom:1px solid var(--border);transition:background .15s;cursor:pointer}}
    tbody tr:hover{{background:var(--bg3)}}
    td{{padding:7px 10px;vertical-align:middle}}
    .num{{text-align:right;font-variant-numeric:tabular-nums}}
    .mono{{font-family:monospace;font-size:12px;color:var(--mono)}}
    .small{{font-size:11px}}
    /* Health score */
    .health-dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px}}
    .health-dot.ok,.health-badge.ok{{background:var(--ok)}}
    .health-dot.warn,.health-badge.warn{{background:var(--warn)}}
    .health-dot.bad,.health-badge.bad{{background:var(--bad)}}
    .health-badge{{border-radius:6px;padding:2px 8px;font-size:0.78rem;font-weight:600;color:#000}}
    /* Value coloring */
    .ok{{color:var(--ok)}}
    .warn{{color:var(--warn)}}
    .bad{{color:var(--bad)}}
    /* Badges */
    .badge{{border-radius:4px;padding:2px 6px;font-size:0.72rem;font-weight:600;white-space:nowrap}}
    .badge-ok{{background:var(--ok-bg);color:var(--ok)}}
    .badge-warn{{background:var(--warn-bg);color:var(--warn)}}
    .badge-bad{{background:var(--bad-bg);color:var(--bad)}}
    /* Sparkbar */
    .sparkbar{{height:4px;background:var(--bg3);border-radius:2px;margin-top:6px}}
    .sparkfill{{height:100%;border-radius:2px;transition:width .3s}}
    .fill-ok{{background:var(--ok)}}
    .fill-warn{{background:var(--warn)}}
    .fill-bad{{background:var(--bad)}}
    /* Channel sections */
    .ch-section{{background:var(--bg2);border:1px solid var(--border);border-radius:12px;margin:0 40px 20px;padding:20px 24px}}
    .ch-header{{display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}}
    .ch-label{{font-size:1.3rem;font-weight:700;color:#fff;min-width:52px}}
    .ch-status{{flex:1}}
    .ch-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:16px}}
    .metric-card{{background:var(--bg3);border-radius:8px;padding:12px}}
    .metric-label{{color:var(--sub);font-size:0.73rem;text-transform:uppercase;letter-spacing:.04em}}
    .metric-val{{font-size:1.15rem;font-weight:600;margin-top:3px}}
    /* Tabs */
    .ch-tabs{{display:flex;gap:8px;margin-bottom:12px}}
    .tab-btn{{background:var(--bg3);border:1px solid var(--border);color:var(--sub);padding:5px 14px;border-radius:6px;cursor:pointer;font-size:13px;transition:all .15s}}
    .tab-btn.active,.tab-btn:hover{{background:var(--blue);border-color:var(--blue);color:#000;font-weight:600}}
    .tab-pane{{display:none}}
    .tab-pane.active{{display:block}}
    /* Table inside section */
    .ch-section table{{font-size:12px}}
    .ch-section thead th{{font-size:0.72rem}}
    .ch-link{{color:var(--blue);font-weight:700}}
    /* Legend */
    .legend{{display:flex;gap:20px;padding:8px 40px 0;font-size:12px;color:var(--sub);flex-wrap:wrap}}
    .legend-item{{display:flex;align-items:center;gap:6px}}
    .legend-dot{{width:10px;height:10px;border-radius:50%}}
    /* Scrollbar */
    ::-webkit-scrollbar{{width:6px;height:6px}}
    ::-webkit-scrollbar-track{{background:var(--bg)}}
    ::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
    /* sticky toc */
    .toc{{background:var(--bg2);border-bottom:1px solid var(--border);padding:8px 40px;display:flex;gap:6px;flex-wrap:wrap;position:sticky;top:0;z-index:10}}
    .toc a{{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:3px 9px;font-size:12px;color:var(--sub);transition:all .15s}}
    .toc a:hover{{color:#fff;border-color:var(--blue)}}
    em{{color:var(--sub);font-style:normal}}
    </style>
    </head>
    <body>

    <div class="hero">
      <h1>WLAN Comprehensive Network Monitor Report</h1>
      <div class="meta">2.4 GHz Band · {len(available_channels)} channels · Generated {gen_time}</div>
    </div>

    <div class="toc">
      {''.join(f'<a href="#ch{c}">CH {c}</a>' for c in available_channels)}
    </div>

    <!-- Summary cards -->
    <div class="cards">
      <div class="card"><div class="card-label">Channels Surveyed</div><div class="card-val" style="color:var(--blue)">{len(available_channels)}</div></div>
      <div class="card"><div class="card-label">Total APs</div><div class="card-val" style="color:var(--blue)">{sum(CM[c].get('aps',0) for c in available_channels)}</div></div>
      <div class="card"><div class="card-label">Confirmed Clients</div><div class="card-val" style="color:var(--ok)">{sum(CM[c].get('total',0)-CM[c].get('aps',0) for c in available_channels)}</div></div>
      <div class="card"><div class="card-label">Channels Healthy</div><div class="card-val" style="color:var(--ok)">{sum(1 for c in available_channels if health_cls(score(c))=='ok')}</div></div>
      <div class="card"><div class="card-label">Channels Degraded</div><div class="card-val" style="color:var(--warn)">{sum(1 for c in available_channels if health_cls(score(c))=='warn')}</div></div>
      <div class="card"><div class="card-label">Channels Critical</div><div class="card-val" style="color:var(--bad)">{sum(1 for c in available_channels if health_cls(score(c))=='bad')}</div></div>
      <div class="card"><div class="card-label">Peak Retry CH</div><div class="card-val" style="color:var(--bad)">CH {max(available_channels, key=lambda c: RF[c]['retry'])} <span style="font-size:1rem">{max(RF[c]['retry'] for c in available_channels):.1f}%</span></div></div>
      <div class="card"><div class="card-label">Busiest Channel</div><div class="card-val" style="color:var(--warn)">CH {max(available_channels, key=lambda c: RF[c]['util'])} <span style="font-size:1rem">{max(RF[c]['util'] for c in available_channels):.1f}%</span></div></div>
    </div>

    <!-- Legend -->
    <div class="legend">
      <div class="legend-item"><div class="legend-dot" style="background:var(--ok)"></div> Healthy / Good</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--warn)"></div> Warning / Degraded</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--bad)"></div> Critical / Action needed</div>
      <span style="margin-left:auto;font-size:11px">Health score = 100 − penalties for utilization, retry, RTS overhead, control frames, NAV</span>
    </div>

    <!-- Master summary table -->
    <div class="section" style="margin-top:24px">
      <div class="section-title">All-Channel Summary</div>
      <div style="overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th>CH</th><th>Health</th>
            <th>Util%</th><th>Retry%</th><th>Ctrl%</th><th>RTS/Data%</th><th>Max NAV (µs)</th>
            <th>APs</th><th>Clients</th><th>Assoc</th><th>Scan</th><th>SSIDs</th>
            <th>Issues</th>
          </tr>
        </thead>
        <tbody>
    {summary_rows()}
        </tbody>
      </table>
      </div>
    </div>

    <!-- Per-channel detail -->
    <div class="section"><div class="section-title">Per-Channel Detail</div></div>
    {channel_sections()}

    <div style="padding:16px 40px 40px;color:var(--sub);font-size:12px">
      Capture source: Channel survey · {len(available_channels)} channels analysed<br>
      Client counts use wlan.ta (uplink transmitter) + unicast wlan.ra (downlink destination) — multicast/broadcast excluded.<br>
      Retry%, Ctrl%, RTS/Data%, Utilization% from frame-level tshark analysis. NAV from wlan.duration field.
    </div>

    SCRIPT_PLACEHOLDER
    </body>
    </html>"""

    JS = """<script>
    function switchTab(btn, paneId) {
      var sec = btn.parentElement.parentElement;
      sec.querySelectorAll('.tab-btn').forEach(function(b){ b.classList.remove('active'); });
      sec.querySelectorAll('.tab-pane').forEach(function(p){ p.classList.remove('active'); });
      btn.classList.add('active');
      document.getElementById(paneId).classList.add('active');
    }
    </script>"""
    HTML = HTML.replace("SCRIPT_PLACEHOLDER", JS)

    out = Path(html_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(HTML)
    print(f"Report -> {out}  ({out.stat().st_size//1024} KB)")

    # Print health summary
    print("\nChannel Health Summary:")
    print(f"{'CH':>4} {'Score':>6} {'Util%':>6} {'Retry%':>7} {'RTS%':>6} {'APs':>4} {'Clients':>8}  Status")
    print("-"*70)
    for ch in available_channels:
        r = RF[ch]; cm = CM.get(ch, {}); sc = score(ch)
        clients = cm.get('total',0) - cm.get('aps',0)
        hc = {'ok':'OK','warn':'WARN','bad':'CRIT'}[health_cls(sc)]
        print(f"CH{ch:2d} {sc:>5}  {r['util']:>6.1f}  {r['retry']:>7.1f}  {r['rts']:>5.1f}  {cm.get('aps',0):>4}  {clients:>7}  [{hc}] {r['status']}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Build combined network report")
    parser.add_argument("client_map_json", help="Path to client_network_map.json")
    parser.add_argument("--channel-jsons-dir", help="Directory with per-channel monitor JSONs")
    parser.add_argument("--output-dir", default="results", help="Output directory")
    args = parser.parse_args()
    result = run(args.client_map_json, channel_jsons_dir=args.channel_jsons_dir,
                 output_dir=args.output_dir)
    if result.get('error'):
        print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)
