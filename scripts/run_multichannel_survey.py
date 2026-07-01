#!/usr/bin/env python3
"""
Multi-Channel WLAN Survey
=========================
Runs the channel monitor on multiple captures (one per channel) and produces
a comprehensive cross-channel comparison report.

The dominant channel is auto-detected from each capture's wlan_radio.channel
metadata, so you do not need to label files manually.

Usage (CLI):
  python scripts/run_multichannel_survey.py ch1.pcap ch6.pcap ch11.pcap
  python scripts/run_multichannel_survey.py --pcap-dir /path/to/captures/ --interval 120

API (from workers):
  from scripts.run_multichannel_survey import run
  result = run(pcap_files=[...], interval=60.0, output_dir='results')
  # result['html_path'] → comparison HTML report
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from loguru import logger


# ─────────────────────────────────────────────────────────────────────────────
# HTML helpers
# ─────────────────────────────────────────────────────────────────────────────

def _esc(s) -> str:
    if s is None:
        return '—'
    return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _util_cls(v: float) -> str:
    if v >= 80:
        return 'val-bad'
    if v >= 50:
        return 'val-warn'
    return 'val-ok'


def _retry_cls(v: float) -> str:
    if v >= 15:
        return 'val-bad'
    if v >= 8:
        return 'val-warn'
    return 'val-ok'


def _sig_cls(v) -> str:
    if v is None:
        return ''
    if v < -80:
        return 'val-bad'
    if v < -70:
        return 'val-warn'
    return 'val-ok'


# ─────────────────────────────────────────────────────────────────────────────
# Cross-channel analysis
# ─────────────────────────────────────────────────────────────────────────────

def _find_multiband_aps(channel_data: List[dict]) -> List[dict]:
    """Return APs (BSSIDs) that appear on more than one channel."""
    bssid_channels: Dict[str, Dict] = defaultdict(lambda: {'channels': set(), 'ssid': None})
    for entry in channel_data:
        ch = entry['channel']
        for bssid, stats in entry['overall'].get('bssid_stats', {}).items():
            bssid_channels[bssid]['channels'].add(ch)
            if stats.get('ssid') and bssid_channels[bssid]['ssid'] is None:
                bssid_channels[bssid]['ssid'] = stats['ssid']
    result = []
    for bssid, info in sorted(bssid_channels.items(), key=lambda x: -len(x[1]['channels'])):
        if len(info['channels']) > 1:
            result.append({
                'bssid': bssid,
                'ssid': info['ssid'],
                'channels': sorted(info['channels']),
            })
    return result


def _find_roaming_clients(channel_data: List[dict]) -> List[dict]:
    """Return client MACs that appear on more than one channel."""
    client_channels: Dict[str, set] = defaultdict(set)
    for entry in channel_data:
        ch = entry['channel']
        for addr in entry['overall'].get('client_stats', {}):
            client_channels[addr].add(ch)
    result = []
    for addr, channels in sorted(client_channels.items(), key=lambda x: -len(x[1])):
        if len(channels) > 1:
            result.append({'mac': addr, 'channels': sorted(channels)})
    return result


# ─────────────────────────────────────────────────────────────────────────────
# HTML report
# ─────────────────────────────────────────────────────────────────────────────

def _build_comparison_html(channel_data: List[dict], html_path: str) -> None:
    gen_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    n_channels = len(channel_data)

    multiband_aps = _find_multiband_aps(channel_data)
    roaming_clients = _find_roaming_clients(channel_data)

    # ── Summary cards ──────────────────────────────────────────────────────
    cards_html = ''
    for entry in channel_data:
        o = entry['overall']
        ch = entry['channel']
        util = o.get('utilisation_pct', 0) or 0
        retry = (o.get('retry_rate', 0) or 0) * 100
        tput = o.get('data_throughput_mbps', 0) or 0
        n_bssids = len(o.get('bssid_stats', {}))
        n_clients = len(o.get('client_stats', {}))
        sig = o.get('avg_signal_dbm')
        overload = '⚠ Overloaded' if o.get('is_overloaded') else 'OK'
        ovl_cls = 'val-bad' if o.get('is_overloaded') else 'val-ok'
        cards_html += f"""
  <div class="card">
    <div class="card-label">Channel {_esc(ch)}</div>
    <div class="card-value">{_esc(entry['pcap_name'])}</div>
    <div class="card-sub">
      Utilisation: <span class="{_util_cls(util)}">{util:.1f}%</span> &nbsp;
      Retry: <span class="{_retry_cls(retry)}">{retry:.1f}%</span><br/>
      Throughput: {tput:.3f} Mbps &nbsp;
      BSSIDs: {n_bssids} &nbsp; Clients: {n_clients}<br/>
      Signal: <span class="{_sig_cls(sig)}">{_esc(sig)} dBm</span> &nbsp;
      Status: <span class="{ovl_cls}">{overload}</span>
    </div>
  </div>"""

    # ── Comparison table ───────────────────────────────────────────────────
    def _row(label: str, key_fn, fmt_fn=None, cls_fn=None):
        cells = ''
        for entry in channel_data:
            o = entry['overall']
            val = key_fn(o)
            text = fmt_fn(val) if fmt_fn else _esc(val)
            css = cls_fn(val) if cls_fn else ''
            cells += f"<td class='{css}'>{text}</td>"
        return f"<tr><td class='row-label'>{label}</td>{cells}</tr>"

    ch_headers = ''.join(
        f"<th>Ch {e['channel']}</th>" for e in channel_data
    )

    comp_table = f"""
<table class="comp-table">
  <thead>
    <tr><th>Parameter</th>{ch_headers}</tr>
  </thead>
  <tbody>
    {_row('PCAP File', lambda o: None,
          fmt_fn=lambda _: '',
          cls_fn=lambda _: '')}
"""
    # Build rows using entry list directly for the PCAP names row
    pcap_cells = ''.join(
        f"<td style='font-size:0.75rem;color:var(--dim)'>{_esc(e['pcap_name'])}</td>"
        for e in channel_data
    )
    comp_table = f"""
<table class="comp-table">
  <thead>
    <tr><th>Parameter</th>{ch_headers}</tr>
  </thead>
  <tbody>
    <tr><td class="row-label">Capture File</td>{pcap_cells}</tr>
"""

    def _make_row(label, getter, fmt='{}', cls_fn=None):
        cells = ''
        for entry in channel_data:
            val = getter(entry['overall'])
            text = fmt.format(_esc(val)) if val is not None else '—'
            css = cls_fn(val) if cls_fn and val is not None else ''
            cells += f"<td class='{css}'>{text}</td>"
        return f"    <tr><td class='row-label'>{label}</td>{cells}</tr>\n"

    comp_table += _make_row(
        'Channel Utilisation (%)',
        lambda o: round(o.get('utilisation_pct', 0) or 0, 1),
        '{:.1f}%',
        lambda v: _util_cls(v),
    )
    comp_table += _make_row(
        'Retry Rate (%)',
        lambda o: round((o.get('retry_rate', 0) or 0) * 100, 1),
        '{:.1f}%',
        lambda v: _retry_cls(v),
    )
    comp_table += _make_row(
        'Data Throughput (Mbps)',
        lambda o: round(o.get('data_throughput_mbps', 0) or 0, 3),
        '{:.3f}',
    )
    comp_table += _make_row(
        'Total Throughput (Mbps)',
        lambda o: round(o.get('throughput_mbps', 0) or 0, 3),
        '{:.3f}',
    )
    comp_table += _make_row(
        'Frame Rate (fps)',
        lambda o: round(o.get('frame_rate_fps', 0) or 0, 1),
        '{:.1f}',
    )
    comp_table += _make_row(
        'Total Frames',
        lambda o: o.get('n_frames', 0),
        '{:,}',
    )
    comp_table += _make_row(
        'Total Bytes',
        lambda o: o.get('total_bytes', 0),
        '{:,}',
    )
    comp_table += _make_row(
        'Avg Signal (dBm)',
        lambda o: o.get('avg_signal_dbm'),
        '{}',
        lambda v: _sig_cls(v),
    )
    comp_table += _make_row(
        'Min Signal (dBm)',
        lambda o: o.get('min_signal_dbm'),
    )
    comp_table += _make_row(
        'Avg Noise (dBm)',
        lambda o: o.get('avg_noise_dbm'),
    )
    comp_table += _make_row(
        'BSSID Count',
        lambda o: len(o.get('bssid_stats', {})),
        '{:,}',
    )
    comp_table += _make_row(
        'Client Count',
        lambda o: len(o.get('client_stats', {})),
        '{:,}',
    )
    comp_table += _make_row(
        'Mgmt Frames',
        lambda o: o.get('frame_types', {}).get('mgmt', 0),
        '{:,}',
    )
    comp_table += _make_row(
        'Ctrl Frames',
        lambda o: o.get('frame_types', {}).get('ctrl', 0),
        '{:,}',
    )
    comp_table += _make_row(
        'Data Frames',
        lambda o: o.get('frame_types', {}).get('data', 0),
        '{:,}',
    )
    comp_table += _make_row(
        'RTS Count',
        lambda o: o.get('rts_count', 0),
        '{:,}',
    )
    comp_table += _make_row(
        'CTS Count',
        lambda o: o.get('cts_count', 0),
        '{:,}',
    )
    comp_table += _make_row(
        'RTS/Data Frame Ratio (%)',
        lambda o: round((o.get('rts_per_data_frame', 0) or 0) * 100, 1),
        '{:.1f}%',
    )
    comp_table += _make_row(
        'Beacon Count',
        lambda o: o.get('beacon_count', 0),
        '{:,}',
    )
    comp_table += _make_row(
        'Probe Req Count',
        lambda o: o.get('probe_req_count', 0),
        '{:,}',
    )
    comp_table += _make_row(
        'Probe Resp Rate (%)',
        lambda o: round((o.get('probe_resp_rate', 1) or 1) * 100, 0),
        '{:.0f}%',
    )
    comp_table += _make_row(
        'Max NAV (µs)',
        lambda o: o.get('max_nav_usec', 0),
        '{:,}',
    )
    comp_table += _make_row(
        'PS-Poll Count',
        lambda o: o.get('ps_poll_count', 0),
        '{:,}',
    )
    comp_table += _make_row(
        'Null Data Count',
        lambda o: o.get('null_data_count', 0),
        '{:,}',
    )
    comp_table += _make_row(
        'Overload Flags',
        lambda o: ', '.join(o.get('overload_flags', [])) or 'None',
    )
    comp_table += '  </tbody>\n</table>'

    # ── Chart.js data ──────────────────────────────────────────────────────
    ch_labels = json.dumps([f"Ch {e['channel']}" for e in channel_data])
    chart_util = json.dumps([
        round(e['overall'].get('utilisation_pct', 0) or 0, 1)
        for e in channel_data
    ])
    chart_retry = json.dumps([
        round((e['overall'].get('retry_rate', 0) or 0) * 100, 1)
        for e in channel_data
    ])
    chart_tput = json.dumps([
        round(e['overall'].get('data_throughput_mbps', 0) or 0, 3)
        for e in channel_data
    ])
    chart_clients = json.dumps([
        len(e['overall'].get('client_stats', {}))
        for e in channel_data
    ])
    chart_bssids = json.dumps([
        len(e['overall'].get('bssid_stats', {}))
        for e in channel_data
    ])
    chart_signal = json.dumps([
        e['overall'].get('avg_signal_dbm')
        for e in channel_data
    ])
    chart_fps = json.dumps([
        round(e['overall'].get('frame_rate_fps', 0) or 0, 1)
        for e in channel_data
    ])

    # ── Multi-band APs table ───────────────────────────────────────────────
    mb_rows = ''
    for ap in multiband_aps:
        mb_rows += (
            f"<tr><td>{_esc(ap['bssid'])}</td>"
            f"<td>{_esc(ap['ssid'])}</td>"
            f"<td>{', '.join(str(c) for c in ap['channels'])}</td>"
            f"<td>{len(ap['channels'])}</td></tr>\n"
        )
    if not mb_rows:
        mb_rows = '<tr><td colspan="4" style="color:var(--dim)">No multi-band APs detected</td></tr>'

    # ── Roaming clients table ──────────────────────────────────────────────
    roam_rows = ''
    for client in roaming_clients[:50]:
        roam_rows += (
            f"<tr><td>{_esc(client['mac'])}</td>"
            f"<td>{', '.join(str(c) for c in client['channels'])}</td>"
            f"<td>{len(client['channels'])}</td></tr>\n"
        )
    if not roam_rows:
        roam_rows = '<tr><td colspan="3" style="color:var(--dim)">No roaming/multi-band clients detected</td></tr>'

    # ── Per-channel links ──────────────────────────────────────────────────
    per_ch_html = ''
    for entry in channel_data:
        hp = entry.get('html_path')
        link = (f'<a href="{_esc(hp)}" target="_blank">{_esc(hp)}</a>'
                if hp else '—')
        overload_flags = entry['overall'].get('overload_flags', [])
        flags_html = ''
        if overload_flags:
            items = ''.join(
                f"<li class='flag-item'>{_esc(f)}</li>"
                for f in overload_flags
            )
            flags_html = f"<ul class='flag-list'>{items}</ul>"
        else:
            flags_html = "<span class='val-ok'>✓ No overload flags</span>"

        n_bssids = len(entry['overall'].get('bssid_stats', {}))
        n_clients = len(entry['overall'].get('client_stats', {}))
        util = entry['overall'].get('utilisation_pct', 0) or 0
        retry = (entry['overall'].get('retry_rate', 0) or 0) * 100
        tput = entry['overall'].get('data_throughput_mbps', 0) or 0

        per_ch_html += f"""
<div class="ch-section">
  <h3>Channel {_esc(entry['channel'])} — {_esc(entry['pcap_name'])}</h3>
  <div class="cards" style="margin-bottom:8px">
    <div class="card">
      <div class="card-label">Utilisation</div>
      <div class="card-value {_util_cls(util)}">{util:.1f}%</div>
    </div>
    <div class="card">
      <div class="card-label">Retry Rate</div>
      <div class="card-value {_retry_cls(retry)}">{retry:.1f}%</div>
    </div>
    <div class="card">
      <div class="card-label">Data Throughput</div>
      <div class="card-value">{tput:.3f}</div>
      <div class="card-sub">Mbps</div>
    </div>
    <div class="card">
      <div class="card-label">BSSIDs / Clients</div>
      <div class="card-value">{n_bssids} / {n_clients}</div>
    </div>
  </div>
  <p style="font-size:0.8rem;color:var(--dim)">Full report: {link}</p>
  {flags_html}
</div>"""

    # ── Complete HTML ──────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Multi-Channel WLAN Survey</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --dim: #8b949e;
    --green: #3fb950; --yellow: #d29922; --red: #f85149; --blue: #58a6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text);
          font-family: 'Segoe UI', system-ui, sans-serif;
          font-size: 14px; padding: 24px; }}
  h1 {{ font-size: 1.6rem; color: var(--blue); margin-bottom: 4px; }}
  h2 {{ font-size: 1.1rem; color: var(--dim); margin: 28px 0 12px;
        border-bottom: 1px solid var(--border); padding-bottom: 6px; }}
  h3 {{ font-size: 0.95rem; color: var(--dim); margin: 18px 0 8px; }}
  .meta {{ color: var(--dim); font-size: 0.85rem; margin-bottom: 24px; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 24px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border);
           border-radius: 8px; padding: 16px 20px; min-width: 200px; flex: 1; }}
  .card-label {{ font-size: 0.75rem; color: var(--dim); text-transform: uppercase;
                 letter-spacing: .05em; }}
  .card-value {{ font-size: 1.3rem; font-weight: 700; margin-top: 4px; }}
  .card-sub {{ font-size: 0.8rem; color: var(--dim); margin-top: 4px; }}
  .val-ok   {{ color: var(--green); }}
  .val-warn {{ color: var(--yellow); }}
  .val-bad  {{ color: var(--red); }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.82rem; }}
  th {{ background: var(--surface); color: var(--dim); text-align: left;
        padding: 8px 10px; border-bottom: 1px solid var(--border);
        font-weight: 600; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid var(--border); }}
  tr:hover td {{ background: var(--surface); }}
  .row-label {{ color: var(--dim); white-space: nowrap; font-weight: 500; }}
  .comp-table {{ table-layout: fixed; }}
  .comp-table th, .comp-table td {{ text-align: center; }}
  .comp-table .row-label {{ text-align: left; width: 240px; }}
  .chart-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .chart-wrap {{ background: var(--surface); border: 1px solid var(--border);
                 border-radius: 8px; padding: 16px; }}
  canvas {{ max-height: 240px; }}
  .ch-section {{ background: var(--surface); border: 1px solid var(--border);
                 border-radius: 8px; padding: 18px 20px; margin-bottom: 14px; }}
  .ch-section h3 {{ color: var(--blue); margin-top: 0; }}
  .flag-list {{ list-style: none; }}
  .flag-item {{ background: #3d1212; border-left: 3px solid var(--red);
    padding: 6px 12px; margin: 4px 0; border-radius: 0 4px 4px 0;
    color: var(--red); font-family: monospace; }}
  a {{ color: var(--blue); }}
</style>
</head>
<body>
<h1>Multi-Channel WLAN Survey</h1>
<div class="meta">
  Channels analysed: <strong>{n_channels}</strong> &nbsp;|&nbsp;
  Generated: {gen_time}
</div>

<h2>Channel Summary</h2>
<div class="cards">
  {cards_html}
</div>

<h2>Comparison Charts</h2>
<div class="chart-grid">
  <div class="chart-wrap"><h3>Channel Utilisation (%)</h3>
    <canvas id="chartUtil"></canvas></div>
  <div class="chart-wrap"><h3>Retry Rate (%)</h3>
    <canvas id="chartRetry"></canvas></div>
  <div class="chart-wrap"><h3>Data Throughput (Mbps)</h3>
    <canvas id="chartTput"></canvas></div>
  <div class="chart-wrap"><h3>Client Count</h3>
    <canvas id="chartClients"></canvas></div>
  <div class="chart-wrap"><h3>BSSID Count</h3>
    <canvas id="chartBssids"></canvas></div>
  <div class="chart-wrap"><h3>Avg Signal (dBm)</h3>
    <canvas id="chartSignal"></canvas></div>
  <div class="chart-wrap"><h3>Frame Rate (fps)</h3>
    <canvas id="chartFps"></canvas></div>
</div>

<h2>Full Traffic Parameter Comparison</h2>
{comp_table}

<h2>Multi-Band APs  ({len(multiband_aps)} found)</h2>
<p style="color:var(--dim);font-size:0.85rem;margin-bottom:8px">
  Access points broadcasting on more than one channel (multi-band / dual-band APs).
</p>
<table>
  <tr><th>BSSID</th><th>SSID</th><th>Channels</th><th>Band Count</th></tr>
  {mb_rows}
</table>

<h2>Roaming / Multi-Band Clients  ({len(roaming_clients)} found)</h2>
<p style="color:var(--dim);font-size:0.85rem;margin-bottom:8px">
  Client stations observed on more than one channel (roaming or multi-band adapters).
</p>
<table>
  <tr><th>MAC Address</th><th>Channels Seen</th><th>Channel Count</th></tr>
  {roam_rows}
</table>

<h2>Per-Channel Details</h2>
{per_ch_html}

<script>
const labels = {ch_labels};
const BAR_OPTS = (color, ymax) => ({{
  type: 'bar',
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }},
      y: {{ min: 0, max: ymax, ticks: {{ color: '#8b949e' }},
            grid: {{ color: '#21262d' }} }}
    }}
  }},
  data: {{
    labels,
    datasets: [{{
      data: [], backgroundColor: color + 'aa',
      borderColor: color, borderWidth: 2, borderRadius: 4
    }}]
  }}
}});

function makeBar(id, data, color, ymax) {{
  const cfg = BAR_OPTS(color, ymax);
  cfg.data.datasets[0].data = data;
  new Chart(document.getElementById(id), cfg);
}}

makeBar('chartUtil',    {chart_util},    '#58a6ff', 100);
makeBar('chartRetry',   {chart_retry},   '#f85149', null);
makeBar('chartTput',    {chart_tput},    '#3fb950', null);
makeBar('chartClients', {chart_clients}, '#d29922', null);
makeBar('chartBssids',  {chart_bssids},  '#39d353', null);
makeBar('chartSignal',  {chart_signal},  '#79c0ff', null);
makeBar('chartFps',     {chart_fps},     '#bc8cff', null);
</script>
</body>
</html>
"""
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)
    logger.info(f"Multi-channel survey report saved → {html_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def run(
    pcap_files: List[str],
    interval: float = 60.0,
    output_dir: str = 'results',
) -> dict:
    """Run the channel monitor on each capture and generate a comparison report.

    Args:
        pcap_files:  List of paths to pcap/pcapng capture files (one per channel).
        interval:    Rolling window size in seconds. Must be a positive multiple
                     of 60.  Default 60.
        output_dir:  Directory to write output files.

    Returns:
        dict with keys:
          'html_path'         — path to the comparison HTML report
          'channels_analyzed' — number of channels successfully processed
          'error'             — error message (only present on failure)
    """
    from scripts.run_channel_monitor import (
        run as ch_run,
        detect_channel_from_pcap,
    )

    # Enforce multiples of 60
    interval = max(60.0, round(interval / 60) * 60)

    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)

    channel_data: List[dict] = []
    seen_channels: dict = {}   # channel -> first entry (dedup warning)

    for pcap in pcap_files:
        pcap_path = Path(pcap)
        if not pcap_path.exists():
            logger.warning(f"PCAP not found, skipping: {pcap}")
            continue

        # Auto-detect channel from wlan_radio.channel metadata
        channel = detect_channel_from_pcap(pcap)
        ch_label = str(channel) if channel else 'unknown'
        logger.info(f"Processing {pcap_path.name}  (channel {ch_label})")

        # Per-channel output prefix
        out_prefix = str(
            output_dir_path / f"survey_ch{ch_label}_{pcap_path.stem}"
        )
        result = ch_run(
            pcap=str(pcap_path),
            channel=channel,
            interval=interval,
            out_prefix=out_prefix,
            output_dir=str(output_dir_path),
        )

        if result.get('error'):
            logger.warning(
                f"Channel monitor failed for {pcap_path.name}: {result['error']}"
            )
            continue

        json_path = result.get('json_path')
        if not json_path or not Path(json_path).exists():
            logger.warning(f"No JSON output for {pcap_path.name}, skipping")
            continue

        data = json.loads(Path(json_path).read_text())
        overall = data.get('overall', {})

        # Resolve effective channel (may have been detected inside ch_run)
        effective_channel: int = channel or 0
        if not effective_channel:
            seen = overall.get('channels_seen', [])
            effective_channel = seen[0] if seen else 0

        if effective_channel in seen_channels:
            logger.warning(
                f"Channel {effective_channel} already in survey (from "
                f"{seen_channels[effective_channel]}). "
                f"Skipping duplicate from {pcap_path.name}."
            )
            continue
        seen_channels[effective_channel] = pcap_path.name

        channel_data.append({
            'channel': effective_channel,
            'pcap_name': pcap_path.name,
            'overall': overall,
            'windows': data.get('windows', []),
            'json_path': json_path,
            'html_path': result.get('html_path'),
        })

    if not channel_data:
        return {
            'error': 'No channels could be analysed successfully.',
            'html_path': None,
            'channels_analyzed': 0,
        }

    # Sort channels numerically
    channel_data.sort(key=lambda x: x['channel'])

    html_path = str(output_dir_path / 'multichannel_survey_report.html')
    _build_comparison_html(channel_data, html_path)

    logger.info(
        f"Multi-channel survey complete: {len(channel_data)} channels "
        f"→ {html_path}"
    )
    return {
        'html_path': html_path,
        'channels_analyzed': len(channel_data),
        'channel_list': [e['channel'] for e in channel_data],
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Multi-Channel WLAN Survey — compare traffic across channel captures'
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        'pcaps', nargs='*', metavar='PCAP',
        help='One or more pcap files (one per channel)'
    )
    src.add_argument(
        '--pcap-dir', metavar='DIR',
        help='Directory containing pcap/pcapng files'
    )
    parser.add_argument(
        '--interval', type=float, default=60.0, metavar='SEC',
        help='Rolling window in seconds, multiple of 60 (default: 60)'
    )
    parser.add_argument(
        '--out-dir', default='results', metavar='DIR',
        help='Output directory (default: results/)'
    )
    args = parser.parse_args()

    if args.pcap_dir:
        from pathlib import Path as _Path
        pcap_files = sorted(
            str(p) for ext in ('*.pcap', '*.pcapng', '*.cap')
            for p in _Path(args.pcap_dir).glob(ext)
        )
    else:
        pcap_files = args.pcaps

    if not pcap_files:
        parser.error('No capture files specified.')

    result = run(pcap_files, interval=args.interval, output_dir=args.out_dir)
    if result.get('error'):
        print(f"ERROR: {result['error']}", file=sys.stderr)
        sys.exit(1)
    print(f"Survey complete: {result['channels_analyzed']} channels analysed")
    print(f"Report: {result['html_path']}")


if __name__ == '__main__':
    main()
