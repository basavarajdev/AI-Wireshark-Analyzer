#!/usr/bin/env python3
"""Build client/network map HTML report — v3"""
import json
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# WiFi Direct / P2P SSID identification patterns
# Matches HP printers (DIRECT-XX-HP ...), Android P2P (DIRECT-XX), HP setup SSIDs
WIFI_DIRECT_SSID_PATTERNS = ('DIRECT-', 'DIRECT_', 'HP-Print-', 'HP=Setup', 'HP-Setup>')


def _is_wifi_direct_ssid(ssid: str) -> bool:
    """Return True if the SSID belongs to a WiFi Direct / P2P network."""
    if not ssid:
        return False
    return any(p in ssid for p in WIFI_DIRECT_SSID_PATTERNS)


def run(input_json: str, output_dir: str = 'results') -> dict:
    """Build client/network map HTML report from consolidated per-channel JSON.

    Args:
        input_json: Path to the client_network_map.json file containing per-channel data.
        output_dir: Directory to write the output HTML report.

    Returns:
        dict with 'html_path' key (or 'error' on failure).
    """
    input_path = Path(input_json)
    if not input_path.exists():
        return {'error': f'Input JSON not found: {input_json}', 'html_path': None}

    try:
        data = json.loads(input_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return {'error': f'Failed to read input JSON: {e}', 'html_path': None}

    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    html_path = str(output_dir_path / "client_network_map.html")

    _build_report(data, html_path)
    return {'html_path': html_path, 'json_path': None}


def _build_report(data: dict, html_path: str):
    """Internal: generate the HTML report from data dict."""
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def esc(s):
        if s is None: return "\u2014"
        return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    def retry_cls(r):
        return "val-bad" if r >= 0.15 else "val-warn" if r >= 0.08 else "val-ok"

    def sig_cls(s):
        if s is None: return ""
        return "val-bad" if s < -80 else "val-warn" if s < -70 else "val-ok"

    def build_assoc_tooltip(d):
        return " | ".join(f"{b} ({v.get('ssid') or '?'}): {v['frames']} frames" for b,v in d.items())

    def mac_to_int(mac):
        try: return int(mac.replace(":",""), 16)
        except: return 0

    def oui(mac): return mac[:8].upper()

    # Global BSSID maps
    global_bssid_ssid = {}
    bssid_ch_seen = defaultdict(set)
    for ch_str, ch_data in data.items():
        for bssid, ssid in ch_data["bssid_ssid"].items():
            if bssid != "ff:ff:ff:ff:ff:ff":
                global_bssid_ssid[bssid] = ssid
                bssid_ch_seen[bssid].add(int(ch_str))

    # WiFi Direct global count
    total_wifi_direct_aps = sum(
        1 for ch_data in data.values()
        for bssid, ssid in ch_data["bssid_ssid"].items()
        if _is_wifi_direct_ssid(ssid)
    )

    # Device cluster detection (sequential MACs, same OUI, diff <= 8)
    all_bssids = sorted(global_bssid_ssid.keys())
    device_clusters = {}
    bssid_cluster_id = {}
    cluster_counter = [0]

    def new_cluster(*bssids):
        cid = cluster_counter[0]; cluster_counter[0] += 1
        device_clusters[cid] = {"bssids": set(bssids), "ssids": set(), "channels": set()}
        for b in bssids:
            bssid_cluster_id[b] = cid
            device_clusters[cid]["ssids"].add(global_bssid_ssid.get(b,""))
            device_clusters[cid]["channels"].update(bssid_ch_seen[b])
        return cid

    for i, b1 in enumerate(all_bssids):
        for b2 in all_bssids[i+1:]:
            if oui(b1) != oui(b2): continue
            if abs(mac_to_int(b1) - mac_to_int(b2)) > 8: continue
            id1 = bssid_cluster_id.get(b1)
            id2 = bssid_cluster_id.get(b2)
            if id1 is not None and id2 is not None:
                if id1 != id2:
                    for b in list(device_clusters[id2]["bssids"]):
                        bssid_cluster_id[b] = id1
                    device_clusters[id1]["bssids"].update(device_clusters[id2]["bssids"])
                    device_clusters[id1]["ssids"].update(device_clusters[id2]["ssids"])
                    device_clusters[id1]["channels"].update(device_clusters[id2]["channels"])
                    del device_clusters[id2]
            elif id1 is not None:
                bssid_cluster_id[b2] = id1
                device_clusters[id1]["bssids"].add(b2)
                device_clusters[id1]["ssids"].add(global_bssid_ssid.get(b2,""))
                device_clusters[id1]["channels"].update(bssid_ch_seen[b2])
            elif id2 is not None:
                bssid_cluster_id[b1] = id2
                device_clusters[id2]["bssids"].add(b1)
                device_clusters[id2]["ssids"].add(global_bssid_ssid.get(b1,""))
                device_clusters[id2]["channels"].update(bssid_ch_seen[b1])
            else:
                new_cluster(b1, b2)

    for cl in device_clusters.values():
        cl["ssids"].discard(""); cl["ssids"].discard("<MISSING>")

    # Multi-channel SSID map
    ssid_bssid_channels = defaultdict(lambda: defaultdict(set))
    for ch_str, ch_data in data.items():
        for bssid, ssid in ch_data["bssid_ssid"].items():
            if bssid != "ff:ff:ff:ff:ff:ff":
                ssid_bssid_channels[ssid][bssid].add(int(ch_str))

    multi_ch_ssids = {}
    for ssid, bm in ssid_bssid_channels.items():
        if ssid in ("<MISSING>",""): continue
        all_chs = sorted(set(c for chs in bm.values() for c in chs))
        if len(all_chs) > 1:
            multi_ch_ssids[ssid] = {"bssids": {b: sorted(chs) for b,chs in bm.items()}, "channels": all_chs}

    # Cross-channel client duplicates
    client_channel_count = defaultdict(set)
    for ch_str, ch_data in data.items():
        for mac, c in ch_data["clients"].items():
            if c["role"] != "AP":
                client_channel_count[mac].add(int(ch_str))
    multi_ch_clients = {m: sorted(chs) for m,chs in client_channel_count.items() if len(chs)>1}
    dup_inflation = sum(len(v)-1 for v in multi_ch_clients.values())

    # Summary counts
    total_macs = sum(v["n_clients"] for v in data.values())
    total_aps  = sum(v["n_aps"] for v in data.values())
    all_macs_set = set()
    for ch_data in data.values(): all_macs_set.update(ch_data["clients"].keys())
    unique_macs = len(all_macs_set)

    # Cluster HTML section
    sorted_clusters = sorted(device_clusters.items(), key=lambda x: (-len(x[1]["bssids"]), sorted(x[1]["bssids"])[0]))
    cluster_html = ""
    for cid, cl in sorted_clusters:
        bssids = sorted(cl["bssids"])
        named  = sorted(cl["ssids"])
        channels = sorted(cl["channels"])
        phys_oui = oui(bssids[0])
        cluster_html += (
            f"<div class='cluster-card'>"
            f"<div class='cluster-hdr'>"
            f"<span class='cluster-oui'>{esc(phys_oui)}</span>"
            f"<span class='cluster-title'>1 physical AP &mdash; {len(bssids)} virtual BSSIDs"
            f"{' &mdash; ' + ', '.join(esc(s) for s in named) if named else ''}</span>"
            f"<span class='cluster-chs'>CH {channels}</span>"
            f"</div>"
            f"<table><tr><th>BSSID (virtual)</th><th>SSID / Network</th><th>Channels seen</th></tr>\n"
        )
        for b in bssids:
            ssid_v   = global_bssid_ssid.get(b,"")
            is_hidden = ssid_v in ("<MISSING>","")
            chs_b    = sorted(bssid_ch_seen[b])
            tag      = '<span class="tag-hidden">hidden SSID</span>' if is_hidden else ""
            cluster_html += (
                f"<tr><td class='mono'>{esc(b)}</td>"
                f"<td class='{'dim' if is_hidden else 'ssid-cell'}'>"
                f"{'[hidden / not captured] ' + tag if is_hidden else esc(ssid_v)}</td>"
                f"<td>{chs_b}</td></tr>\n"
            )
        cluster_html += "</table></div>\n"

    # Multi-channel network HTML
    multich_html = ""
    for ssid, info in sorted(multi_ch_ssids.items(), key=lambda x: (-len(x[1]["channels"]),x[0])):
        bssids  = sorted(info["bssids"].items(), key=lambda x: x[1])
        channels = info["channels"]
        multich_html += (
            f"<div class='cluster-card'>"
            f"<div class='cluster-hdr'>"
            f"<span class='ssid-badge'>{esc(ssid)}</span>"
            f"<span class='cluster-title'>{len(bssids)} APs on {len(channels)} channels</span>"
            f"<span class='cluster-chs'>CH {channels}</span>"
            f"</div>"
            f"<table><tr><th>BSSID</th><th>Channels</th><th>Device cluster</th></tr>\n"
        )
        for b, chs in bssids:
            cid = bssid_cluster_id.get(b)
            if cid is not None:
                named = sorted(device_clusters[cid]["ssids"])
                cl_tag = f'<span class="tag-cluster">cluster-{cid} ({", ".join(esc(s) for s in named) or "hidden SSIDs"})</span>'
            else:
                cl_tag = '<span class="dim">standalone AP</span>'
            multich_html += f"<tr><td class='mono'>{esc(b)}</td><td>{chs}</td><td>{cl_tag}</td></tr>\n"
        multich_html += "</table></div>\n"

    # Per-channel content
    nav_tabs = ""; tab_panels = ""; ch_summary_rows = ""
    for ch_str in sorted(data.keys(), key=int):
        ch_data = data[ch_str]; ch = ch_data["channel"]
        clients = ch_data["clients"]; bssid_ssid = ch_data["bssid_ssid"]
        n_ap = ch_data["n_aps"]; n_sta = ch_data["n_clients"] - n_ap
        unique_ssid_count = len(set(bssid_ssid.values()))

        ssid_groups = {}; unassoc_clients = []
        for mac, c in clients.items():
            if c["role"] == "AP": continue
            psid, pbssid = c.get("primary_ssid"), c.get("primary_bssid")
            if psid:
                ssid_groups.setdefault(psid, {"bssid": pbssid, "gtype":"ssid","clients":[]})["clients"].append((mac,c))
            elif pbssid:
                key = f"[BSSID {pbssid}]"
                ssid_groups.setdefault(key, {"bssid":pbssid,"gtype":"bssid","clients":[]})["clients"].append((mac,c))
            else:
                unassoc_clients.append((mac,c))

        n_assoc_sta = sum(len(g["clients"]) for g in ssid_groups.values())
        n_unassoc   = len(unassoc_clients)
        aps = sorted([(mac,c) for mac,c in clients.items() if c["role"]=="AP"], key=lambda x:-x[1]["total_frames"])

        ap_rows = ""
        for mac, c in aps:
            ssid_raw = c.get("primary_ssid") or bssid_ssid.get(mac, "")
            ssid = esc(ssid_raw)
            sig  = f"{c['avg_signal_dbm']} dBm" if c.get("avg_signal_dbm") is not None else "\u2014"
            assoc_cnt = sum(len(v["clients"]) for v in ssid_groups.values() if v.get("bssid")==mac)
            cid = bssid_cluster_id.get(mac)
            cl_badge = ""
            if cid is not None:
                siblings = sorted(device_clusters[cid]["bssids"] - {mac})
                named    = sorted(device_clusters[cid]["ssids"])
                tip      = f"Same device as: {', '.join(siblings)}"
                cl_badge = f'<span class="tag-cluster" title="{esc(tip)}">cluster-{cid}</span> '
            ch_count = len(bssid_ch_seen.get(mac, set()))
            mc_badge = f'<span class="tag-multich">on {ch_count} CH</span>' if ch_count > 1 else ""
            wd_badge = '<span class="tag-wifi-direct">WiFi-Direct</span> ' if _is_wifi_direct_ssid(ssid_raw) else ""
            ap_rows += (
                f"<tr><td class='mono'>{esc(mac)}</td><td class='ssid-cell'>{ssid}</td>"
                f"<td>{c['total_frames']:,}</td><td class='{sig_cls(c.get('avg_signal_dbm'))}'>{sig}</td>"
                f"<td>{assoc_cnt}</td><td>{wd_badge}{cl_badge}{mc_badge}</td></tr>\n"
            )

        def make_client_rows(client_list):
            rows = ""
            for mac, c in sorted(client_list, key=lambda x: -x[1]["total_frames"]):
                rr, sig = c["retry_rate"], c.get("avg_signal_dbm")
                sig_str = f"{sig} dBm" if sig is not None else "\u2014"
                ps_tag  = '<span class="tag-ps">PS</span>' if c.get("ps_mode") else ""
                na = len(c.get("associations",{}))
                roam_tag = f'<span class="tag-roam">roaming ({na} APs)</span>' if na>1 else ""
                n_chs = len(multi_ch_clients.get(mac,[]))
                xch_tag = f'<span class="tag-multich">seen {n_chs} CH</span>' if n_chs>1 else ""
                tip = esc(build_assoc_tooltip(c.get("associations",{})))
                # Show mgmt/data frame breakdown if available
                data_frames = c.get("data_frames", 0)
                mgmt_frames = c.get("mgmt_frames", c["total_frames"] - data_frames if data_frames else 0)
                frames_detail = (
                    f"<span title='Mgmt: {mgmt_frames:,}  Data: {data_frames:,}' "
                    f"style='cursor:help'>{c['total_frames']:,}</span>"
                    if data_frames or mgmt_frames
                    else f"{c['total_frames']:,}"
                )
                rows += (
                    f"<tr><td class='mono'>{esc(mac)}</td>"
                    f"<td class='{retry_cls(rr)}'>{rr*100:.1f}%</td>"
                    f"<td class='{sig_cls(sig)}'>{sig_str}</td>"
                    f"<td>{frames_detail}</td>"
                    f"<td>{ps_tag}{roam_tag}{xch_tag}</td>"
                    f"<td><span class='detail-link' title='{tip}'>details</span></td></tr>\n"
                )
            return rows

        client_rows = ""
        for grp_key, grp in sorted(ssid_groups.items(), key=lambda x: -len(x[1]["clients"])):
            bl, gtype = grp.get("bssid") or "", grp.get("gtype","ssid")
            badge_cls = "ssid-badge" if gtype=="ssid" else "ssid-badge ssid-badge-unknown"
            sub_label = (f" BSSID: {esc(bl)}" if gtype=="ssid" and bl else " (SSID not seen in capture)")
            client_rows += (
                f"<tr class='ssid-group-hdr'><td colspan='6'>"
                f"<span class='{badge_cls}'>{esc(grp_key)}</span>"
                f"<span class='bssid-sub'>{sub_label}</span>"
                f"<span class='count-badge'>{len(grp['clients'])} clients</span>"
                f"</td></tr>\n"
            )
            client_rows += make_client_rows(grp["clients"])
        if unassoc_clients:
            client_rows += (
                f"<tr class='ssid-group-hdr ssid-group-unassoc'><td colspan='6'>"
                f"<span class='ssid-badge ssid-badge-unassoc'>Scanning / Unassociated</span>"
                f"<span class='bssid-sub'> No BSSID seen \u2014 probe-only or MAC-randomised devices</span>"
                f"<span class='count-badge'>{n_unassoc} devices</span></td></tr>\n"
            )
            client_rows += make_client_rows(unassoc_clients)

        sample_ssids = ", ".join(sorted(set(bssid_ssid.values()))[:5])
        if unique_ssid_count > 5: sample_ssids += "\u2026"
        n_wifi_direct_ch = sum(1 for ssid in bssid_ssid.values() if _is_wifi_direct_ssid(ssid))
        ch_summary_rows += (
            f"<tr><td><a href='#' onclick=\"showTab({ch});return false\" class='ch-link'>"
            f"<strong>CH {ch}</strong></a></td>"
            f"<td>{n_ap}</td><td>{n_assoc_sta}</td><td>{n_unassoc}</td>"
            f"<td>{ch_data['n_clients']}</td><td>{unique_ssid_count}</td>"
            f"<td>{n_wifi_direct_ch}</td>"
            f"<td>{esc(sample_ssids)}</td></tr>\n"
        )
        nav_tabs += (
            f'<button class="tab-btn" id="tab-btn-{ch}" onclick="showTab({ch})">'
            f'CH {ch} <span class="cnt">{ch_data["n_clients"]}</span></button>\n'
        )
        # WiFi Direct section for this channel
        wifi_direct_aps_on_ch = [
            (mac, c) for mac, c in aps
            if _is_wifi_direct_ssid(c.get("primary_ssid") or bssid_ssid.get(mac, ""))
        ]
        wd_section = ""
        if wifi_direct_aps_on_ch:
            wd_rows = ""
            for wd_mac, wd_c in sorted(wifi_direct_aps_on_ch, key=lambda x: -(x[1]["total_frames"])):
                wd_ssid_raw = wd_c.get("primary_ssid") or bssid_ssid.get(wd_mac, "")
                wd_sig = f"{wd_c['avg_signal_dbm']} dBm" if wd_c.get("avg_signal_dbm") is not None else "\u2014"
                wd_rows += (
                    f"<tr><td class='mono'>{esc(wd_mac)}</td>"
                    f"<td class='ssid-cell'>{esc(wd_ssid_raw)}</td>"
                    f"<td>{wd_c['total_frames']:,}</td>"
                    f"<td class='{sig_cls(wd_c.get('avg_signal_dbm'))}'>{wd_sig}</td></tr>\n"
                )
            wd_section = (
                f"  <h3>WiFi Direct Networks ({len(wifi_direct_aps_on_ch)})"
                f" &mdash; HP printers &amp; P2P devices</h3>\n"
                f"  <table><tr><th>BSSID</th><th>SSID</th><th>Frames</th><th>Signal</th></tr>\n"
                f"  {wd_rows}</table>\n"
            )
        tab_panels += (
            f'\n<div class="tab-panel" id="tab-{ch}" style="display:none">\n'
            f'  <h2>Channel {ch} &mdash; {ch_data["n_clients"]} unique MACs ({n_ap} APs&nbsp;+&nbsp;{n_sta} STAs)</h2>\n'
            f'  <div class="ch-meta-row">\n'
            f'    <span class="meta-pill meta-ssid">{unique_ssid_count} unique SSIDs'
            f'<span class="meta-sub"> ({len(bssid_ssid)} BSSIDs with identified SSID)</span></span>\n'
            f'    <span class="meta-pill meta-assoc">{n_assoc_sta} associated<span class="meta-sub"> (in {len(ssid_groups)} networks)</span></span>\n'
            f'    <span class="meta-pill meta-unassoc">{n_unassoc} scanning / unassociated</span>\n'
            f'    <span class="meta-pill" style="border-color:#7a4500;color:#ff9f45">{len(wifi_direct_aps_on_ch)} WiFi-Direct APs</span>\n'
            f'  </div>\n'
            f'  <h3>Access Points ({n_ap}) &mdash; <span class="tag-cluster" style="cursor:default">cluster-N</span> = virtual BSSID on same physical device &nbsp; <span class="tag-multich" style="cursor:default">on N CH</span> = AP visible on multiple channel captures &nbsp; <span class="tag-wifi-direct" style="cursor:default">WiFi-Direct</span> = P2P / printer AP</h3>\n'
            f'  <table><tr><th>BSSID</th><th>SSID / Network Name</th><th>TX Frames</th><th>Signal</th><th>Assoc. clients</th><th>Flags</th></tr>\n'
            f'  {ap_rows or "<tr><td colspan=6 class=dim>none</td></tr>"}</table>\n'
            f'{wd_section}'
            f'  <h3>Client STAs ({n_sta}) &mdash; {n_assoc_sta} associated + {n_unassoc} scanning/unassociated</h3>\n'
            f'  <table><tr><th>MAC Address</th><th>Retry Rate</th><th>Avg Signal</th><th>TX Frames</th><th>Tags</th><th>Tooltip</th></tr>\n'
            f'  {client_rows or "<tr><td colspan=6 class=dim>none</td></tr>"}</table>\n'
            f'</div>\n'
        )

    js_data = {}
    for k, v in data.items():
        js_data[k] = {
            "channel": v["channel"], "bssid_ssid": v["bssid_ssid"],
            "clients": {
                mac: {
                    "role": c["role"], "primary_ssid": c.get("primary_ssid"),
                    "primary_bssid": c.get("primary_bssid"), "total_frames": c["total_frames"],
                    "retry_rate": c["retry_rate"], "avg_signal_dbm": c.get("avg_signal_dbm"),
                    "n_assoc": len(c.get("associations",{})),
                } for mac, c in v["clients"].items()
            },
        }

    CSS = """:root{--bg:#0d1117;--sf:#161b22;--br:#30363d;--tx:#e6edf3;--dm:#8b949e;--gn:#3fb950;--yw:#d29922;--rd:#f85149;--bl:#58a6ff;--cy:#39d353;--pu:#bc8cff}
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--bg);color:var(--tx);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;padding:20px}
    h1{font-size:1.45rem;color:var(--bl);margin-bottom:4px}
    h2{font-size:1rem;color:var(--tx);margin:20px 0 6px;border-bottom:1px solid var(--br);padding-bottom:5px}
    h3{font-size:0.88rem;color:var(--dm);margin:14px 0 6px;font-weight:600}
    .meta{color:var(--dm);font-size:0.82rem;margin-bottom:16px}
    .cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:18px}
    .card{background:var(--sf);border:1px solid var(--br);border-radius:8px;padding:12px 16px;min-width:130px}
    .card-label{font-size:0.7rem;color:var(--dm);text-transform:uppercase;letter-spacing:.05em}
    .card-value{font-size:1.3rem;font-weight:700;margin-top:3px}
    .card-sub{font-size:0.72rem;color:var(--dm);margin-top:2px}
    .ch-meta-row{display:flex;flex-wrap:wrap;gap:8px;margin:6px 0 14px}
    .meta-pill{background:var(--sf);border:1px solid var(--br);border-radius:20px;padding:4px 12px;font-size:0.78rem;font-weight:600}
    .meta-ssid{border-color:#1a4a7a;color:var(--bl)}.meta-assoc{border-color:#2a5a2a;color:var(--gn)}.meta-unassoc{border-color:#4a3a1a;color:var(--yw)}.meta-sub{font-weight:400;color:var(--dm);margin-left:4px}
    .tab-bar{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:16px;border-bottom:1px solid var(--br);padding-bottom:8px}
    .tab-btn{background:var(--sf);border:1px solid var(--br);border-radius:5px;color:var(--dm);cursor:pointer;font-size:0.78rem;padding:5px 10px;transition:background .15s}
    .tab-btn:hover{background:#21262d;color:var(--tx)}.tab-btn.active{background:#1f3a5f;border-color:var(--bl);color:var(--bl);font-weight:700}
    .cnt{background:#21262d;border-radius:10px;padding:1px 5px;font-size:0.7rem;margin-left:3px}
    table{width:100%;border-collapse:collapse;margin-top:6px;font-size:0.78rem}
    th{background:var(--sf);color:var(--dm);text-align:left;padding:7px 8px;border-bottom:1px solid var(--br);font-weight:600;white-space:nowrap}
    td{padding:5px 8px;border-bottom:1px solid var(--br);vertical-align:middle}
    tr:hover td{background:#161b22}.dim{color:var(--dm)}.mono{font-family:monospace;font-size:0.77rem;color:var(--cy)}.ssid-cell{color:var(--tx);font-weight:500}
    .ssid-group-hdr td{background:#0d1f33;padding:7px 8px;border-bottom:1px solid var(--br)}.ssid-group-unassoc td{background:#1a1200}
    .ssid-badge{background:#132d4a;border:1px solid #1a4a7a;border-radius:4px;padding:2px 8px;color:var(--bl);font-weight:700;font-size:0.8rem;margin-right:6px}
    .ssid-badge-unknown{background:#2d1f0d;border-color:#5a3a0d;color:var(--yw)}.ssid-badge-unassoc{background:#1a1200;border:1px solid #4a3a00;color:#d4a017}
    .bssid-sub{color:var(--dm);font-size:0.75rem;font-family:monospace;margin-right:8px}.count-badge{background:#1a2d1a;border:1px solid #2a5a2a;border-radius:4px;padding:1px 6px;color:var(--gn);font-size:0.73rem}
    .tag-ps{background:#2d1f0d;border:1px solid #5a3a0d;border-radius:3px;padding:1px 4px;color:var(--yw);font-size:0.7rem;margin-right:3px}
    .tag-roam{background:#1a1a3d;border:1px solid #2a2a7a;border-radius:3px;padding:1px 4px;color:#a9b8ff;font-size:0.7rem;margin-right:3px}
    .tag-cluster{background:#2a1a3d;border:1px solid #5a2a7a;border-radius:3px;padding:1px 5px;color:var(--pu);font-size:0.7rem;cursor:help;margin-right:3px}
    .tag-multich{background:#1a2a1a;border:1px solid #2a5a2a;border-radius:3px;padding:1px 4px;color:#7ee87e;font-size:0.7rem;margin-right:3px}
    .tag-hidden{background:#2a2a2a;border:1px solid #444;border-radius:3px;padding:1px 4px;color:var(--dm);font-size:0.7rem}
    .detail-link{color:var(--dm);font-size:0.72rem;cursor:help;text-decoration:underline dotted}
    .val-ok{color:var(--gn)}.val-warn{color:var(--yw)}.val-bad{color:var(--rd)}.ch-link{color:var(--bl);text-decoration:none}
    .cluster-card{background:var(--sf);border:1px solid var(--br);border-radius:8px;margin-bottom:12px;overflow:hidden}
    .cluster-hdr{background:#1a1a2e;padding:10px 14px;display:flex;align-items:center;flex-wrap:wrap;gap:10px}
    .cluster-oui{font-family:monospace;font-size:0.85rem;color:var(--pu);font-weight:700;min-width:90px}
    .cluster-title{font-size:0.82rem;color:var(--tx);flex:1}.cluster-chs{font-size:0.75rem;color:var(--dm);font-family:monospace}
    .search-wrap{margin-bottom:14px}
    #mac-search{background:var(--sf);border:1px solid var(--br);border-radius:6px;color:var(--tx);font-size:0.85rem;padding:7px 12px;width:360px;outline:none}
    #mac-search:focus{border-color:var(--bl)}#search-results{margin-top:8px;font-size:0.82rem}"""

    JS_TMPL = """
    const ALL_DATA=__DATA__;
    function showTab(ch){document.querySelectorAll('.tab-panel').forEach(p=>p.style.display='none');document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));const p=document.getElementById('tab-'+ch);if(p)p.style.display='block';const b=document.getElementById('tab-btn-'+ch);if(b)b.classList.add('active');}
    showTab(1);
    function searchMac(q){q=q.trim().toLowerCase();const out=document.getElementById('search-results');if(q.length<3){out.innerHTML='';return;}const hits=[];for(const[ch,chd]of Object.entries(ALL_DATA)){for(const[mac,c]of Object.entries(chd.clients)){if(mac.includes(q)){const ssid=c.primary_ssid||(chd.bssid_ssid[c.primary_bssid]||(c.primary_bssid?'[BSSID '+c.primary_bssid+']':'Unassociated'));const rr=(c.retry_rate*100).toFixed(1);const sig=c.avg_signal_dbm!==null?c.avg_signal_dbm+' dBm':'\u2014';const rCls=c.retry_rate>=0.15?'val-bad':c.retry_rate>=0.08?'val-warn':'val-ok';hits.push(`<tr><td><strong>CH ${ch}</strong></td><td style="font-family:monospace;color:#39d353">${mac}</td><td>${c.role}</td><td style="color:#58a6ff">${ssid}</td><td style="font-family:monospace;color:#8b949e">${c.primary_bssid||'\u2014'}</td><td class="${rCls}">${rr}%</td><td>${sig}</td><td>${c.total_frames.toLocaleString()}</td><td><button onclick="showTab(${ch})" style="background:#1f3a5f;border:1px solid #58a6ff;border-radius:4px;color:#58a6ff;cursor:pointer;font-size:0.73rem;padding:2px 6px">Go</button></td></tr>`);}}};if(!hits.length){out.innerHTML='<span style="color:#8b949e">No matches</span>';}else{out.innerHTML=`<table style="margin-top:8px"><tr><th>CH</th><th>MAC</th><th>Role</th><th>Network</th><th>BSSID</th><th>Retry</th><th>Signal</th><th>Frames</th><th></th></tr>${hits.join('')}</table><div style="color:#8b949e;margin-top:6px;font-size:0.78rem">${hits.length} match(es)</div>`;}}
    """
    JS_BODY = JS_TMPL.replace("__DATA__", json.dumps(js_data))

    html = (
        "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
        "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>\n"
        "<title>WLAN Client/Network Map v3 \u2014 CH 1-13</title>\n"
        f"<style>{CSS}</style>\n</head>\n<body>\n"
        f"<h1>WLAN Client / Network Map \u2014 Channels 1\u201313</h1>\n"
        f"<div class='meta'>Generated: {gen_time} &nbsp;|&nbsp; Source: OneDrive_1_5-21-2026 captures</div>\n"
        f"<div class='cards'>\n"
        f"  <div class='card'><div class='card-label'>MAC observations</div><div class='card-value'>{total_macs:,}</div><div class='card-sub'>across 13 channels (incl. duplicates)</div></div>\n"
        f"  <div class='card'><div class='card-label'>Unique MACs (global)</div><div class='card-value'>{unique_macs:,}</div><div class='card-sub'>distinct devices across all channels</div></div>\n"
        f"  <div class='card'><div class='card-label'>Total APs</div><div class='card-value'>{total_aps:,}</div><div class='card-sub'>BSSIDs acting as AP (incl. virtual)</div></div>\n"
        f"  <div class='card'><div class='card-label'>Physical AP clusters</div><div class='card-value'>{len(device_clusters):,}</div><div class='card-sub'>devices with multiple virtual BSSIDs</div></div>\n"
        f"  <div class='card' style='border-color:#7a4500'><div class='card-label'>WiFi Direct APs</div><div class='card-value' style='color:#ff9f45'>{total_wifi_direct_aps:,}</div><div class='card-sub'>HP printers &amp; P2P devices</div></div>\n"
        f"  <div class='card'><div class='card-label'>Multi-channel SSIDs</div><div class='card-value'>{len(multi_ch_ssids):,}</div><div class='card-sub'>networks on &gt;1 channel</div></div>\n"
        f"  <div class='card'><div class='card-label'>Roaming / multi-CH clients</div><div class='card-value'>{len(multi_ch_clients):,}</div><div class='card-sub'>+{dup_inflation:,} inflated per-ch rows</div></div>\n"
        f"</div>\n"
        f"<h2>Device Clusters \u2014 Same Physical AP, Multiple Virtual BSSIDs ({len(device_clusters)})</h2>\n"
        f"<p style='color:var(--dm);font-size:0.8rem;margin-bottom:10px'>Detected by sequential MAC within same OUI (diff &le;8). Each cluster = one physical radio broadcasting multiple SSIDs. Hover <span class='tag-cluster'>cluster-N</span> badge in AP tables for sibling BSSIDs.</p>\n"
        f"{cluster_html or '<p class=\"dim\">None detected.</p>'}\n"
        f"<h2>Multi-Channel Networks ({len(multi_ch_ssids)}) \u2014 Same SSID Across Multiple Channels</h2>\n"
        f"<p style='color:var(--dm);font-size:0.8rem;margin-bottom:10px'>Enterprise or mesh deployments. A <span class='tag-cluster'>cluster-N</span> tag means both BSSIDs are virtual interfaces on the same physical device.</p>\n"
        f"{multich_html or '<p class=\"dim\">None detected.</p>'}\n"
        f"<h2>Channel Summary</h2>\n"
        f"<table>\n  <tr><th>Channel</th><th>APs</th><th>Associated STAs</th><th>Scanning / Unassoc.</th><th>Total MACs</th><th>Unique SSIDs</th><th>WiFi Direct APs</th><th>Sample Networks</th></tr>\n"
        f"  {ch_summary_rows}\n</table>\n"
        f"<h2>MAC Address Search</h2>\n"
        f"<div class='search-wrap'><input id='mac-search' type='text' placeholder='Search MAC address (e.g. 5c:5a:c7 or partial)...' oninput='searchMac(this.value)'><div id='search-results'></div></div>\n"
        f"<h2>Per-Channel Client Details</h2>\n"
        f"<div class='tab-bar'>{nav_tabs}</div>\n"
        f"<div id='tab-content'>{tab_panels}</div>\n"
        f"<script>{JS_BODY}</script>\n</body>\n</html>"
    )

    out = Path(html_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"HTML report -> {out}  ({out.stat().st_size // 1024} KB)")

    print(f"\nDevice clusters: {len(device_clusters)}")
    for cid, cl in sorted_clusters:
        bssids=sorted(cl['bssids']); named=sorted(cl['ssids'])
        print(f"  OUI {oui(bssids[0])}  {len(bssids)} BSSIDs  SSIDs={named}  CH{sorted(cl['channels'])}")

    print(f"\nMulti-channel SSIDs ({len(multi_ch_ssids)}):")
    for ssid, info in sorted(multi_ch_ssids.items(), key=lambda x:(-len(x[1]['channels']),x[0])):
        print(f"  '{ssid}'  {len(info['bssids'])} BSSIDs  CH{info['channels']}")

    print(f"\nClients on multiple channels: {len(multi_ch_clients)}  (+{dup_inflation} inflated rows)")
    print(f"\n{'CH':>3}  {'APs':>4}  {'Assoc':>6}  {'Scan':>5}  {'Total':>6}  {'UniqSSID':>8}")
    print("-"*42)
    for ch_str in sorted(data.keys(), key=int):
        d=data[ch_str]; ch=d["channel"]; bs=d["bssid_ssid"]; cl=d["clients"]
        nap=d["n_aps"]; nsta=d["n_clients"]-nap
        assoc=sum(1 for c in cl.values() if c["role"]!="AP" and c.get("primary_bssid"))
        print(f"CH{ch:>2}  {nap:>4}  {assoc:>6}  {nsta-assoc:>5}  {d['n_clients']:>6}  {len(set(bs.values())):>8}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Build client/network map HTML report")
    parser.add_argument("input_json", help="Path to client_network_map.json")
    parser.add_argument("--output-dir", default="results", help="Output directory")
    args = parser.parse_args()
    result = run(args.input_json, output_dir=args.output_dir)
    if result.get('error'):
        print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)
