#!/usr/bin/env python3
"""
IPv6 Traffic Analysis Script
Analyses a pcap/pcapng file for a specific IPv6 address and generates
JSON + HTML reports covering:
  - IPv6 address classification (GUA/LLA/ULA/multicast, EUI-64, prefix)
  - Neighbor Discovery Protocol (NDP): NS/NA pairing, DAD, RA details, redirects
  - DNS AAAA / PTR resolution analysis
  - Extension headers (hop-by-hop, routing type 0, fragments, flow labels)
  - Traffic timeline (per-hour buckets)
  - TCP, UDP, ICMPv6, SNMP deep analysis
  - Security issue detection with remediations
"""

import subprocess
import sys
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))
from loguru import logger

# ─── CLI arguments ───────────────────────────────────────────────────────────

# Module-level argv parsing only when run directly (guarded in main())

# ─── tshark helpers ──────────────────────────────────────────────────────────

def _run_tshark(pcap: str, display_filter: str, fields: list,
                extra_args: list = None) -> list:
    """Run tshark and return rows of field values.
    
    Note: Ignores non-zero exit codes since tshark may still produce valid output
    for truncated/malformed files. Only returns empty list on timeout.
    """
    cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t", "-E", "header=n"]
    if extra_args:
        cmd += extra_args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        out = result.stdout
    except subprocess.TimeoutExpired:
        return []
    rows = []
    for line in out.strip().splitlines():
        rows.append(line.split("\t"))
    return rows


def _count(pcap: str, display_filter: str) -> int:
    """Count packets matching a display filter.
    
    Note: Ignores non-zero exit codes since tshark may still produce valid output
    for truncated/malformed files. Only returns 0 on timeout.
    """
    cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields", "-e", "frame.number"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        out = result.stdout
        return len(out.strip().splitlines()) if out.strip() else 0
    except subprocess.TimeoutExpired:
        return 0


# ─── IPv6 Address Classification ─────────────────────────────────────────────

def _classify_ipv6_address(addr: str) -> dict:
    """
    Classify an IPv6 address and extract addressing metadata.
    Returns scope, type, prefix, EUI-64 info, and multicast details.
    """
    info = {
        "address": addr,
        "scope": "unknown",
        "type": "unknown",
        "prefix": "",
        "prefix_length": "",
        "is_eui64": False,
        "embedded_mac": None,
        "multicast_scope": None,
        "multicast_group": None,
        "solicited_node": None,
        "notes": [],
    }

    try:
        parts = addr.split(":")
        # Expand :: if present
        if "::" in addr:
            missing = 8 - (len(parts) - 1)
            idx = parts.index("")
            parts = parts[:idx] + ["0000"] * missing + parts[idx + 1:]
            parts = [p if p else "0000" for p in parts]

        groups = [int(p or "0", 16) for p in parts[:8]]
        first16 = groups[0]
        first32 = (groups[0] << 16) | groups[1]

        # Loopback ::1
        if groups == [0, 0, 0, 0, 0, 0, 0, 1]:
            info.update({"scope": "host", "type": "loopback", "prefix": "::1/128",
                         "notes": ["Loopback address — not routable"]})
            return info

        # Unspecified ::
        if all(g == 0 for g in groups):
            info.update({"scope": "host", "type": "unspecified", "prefix": "::/128",
                         "notes": ["Unspecified address — used in DAD NS source"]})
            return info

        # Link-Local fe80::/10
        if (first16 & 0xFFC0) == 0xFE80:
            info["scope"] = "link"
            info["type"] = "link-local (LLA)"
            info["prefix"] = "fe80::/10"
            info["notes"].append("Not routable beyond local link")

        # Unique Local fc00::/7 (ULA)
        elif (first16 & 0xFE00) == 0xFC00:
            info["scope"] = "global"
            info["type"] = "unique-local (ULA)"
            info["prefix"] = f"fc00::/7 (L-bit={'1' if first16 & 0x0100 else '0'})"
            info["notes"].append("ULA — routable within organisation, not on public internet")
            if not (first16 & 0x0100):
                info["notes"].append("L-bit=0: globally assigned ULA prefix (unusual)")

        # Multicast ff00::/8
        elif (first16 & 0xFF00) == 0xFF00:
            mcast_scope_map = {
                0x1: "interface-local", 0x2: "link-local", 0x4: "admin-local",
                0x5: "site-local", 0x8: "organisation-local", 0xE: "global",
            }
            mscope = first16 & 0x000F
            info["scope"] = mcast_scope_map.get(mscope, f"scope-{mscope:#x}")
            info["type"] = "multicast"
            info["prefix"] = "ff00::/8"
            info["multicast_scope"] = info["scope"]
            info["multicast_group"] = addr

            # Solicited-node multicast ff02::1:ffXX:XXXX
            if (first16 == 0xFF02 and groups[1] == 0 and groups[2] == 0 and
                    groups[3] == 0 and groups[4] == 0 and groups[5] == 1 and
                    (groups[6] & 0xFF00) == 0xFF00):
                last3 = f"{groups[6] & 0xFF:02x}:{groups[7]:04x}"
                info["type"] = "solicited-node multicast"
                info["solicited_node"] = f"corresponds to host suffix ...{last3}"
                info["notes"].append(f"Solicited-node for host with last 3 bytes {last3}")

        # Global Unicast 2000::/3
        elif (first16 & 0xE000) == 0x2000:
            info["scope"] = "global"
            info["type"] = "global unicast (GUA)"
            info["prefix"] = f"{groups[0]:04x}:{groups[1]:04x}:{groups[2]:04x}:{groups[3]:04x}::/64"
            info["prefix_length"] = "64"
            info["notes"].append("Publicly routable IPv6 address")

            # ISP prefix range detection (common /32 allocations)
            first32_hex = f"{groups[0]:04x}:{groups[1]:04x}"
            info["isp_prefix_hint"] = f"{first32_hex}::/32 (likely ISP /32 allocation)"

        # Check for EUI-64 interface ID (RFC 4291) — bits 6&7 of group[4] == 0b11
        # EUI-64 pattern: xxxx:xxFF:FExx:xxxx where groups[5]=0x00FF
        if len(groups) >= 8:
            if groups[5] == 0x00FF and (groups[4] & 0xFF) == 0xFF:
                # Actually check standard: groups[4] hi-byte, groups[5]=00ff, groups[6] lo parts
                pass
            # Proper EUI-64: interface ID where 3rd group = 0x__FF and 4th group starts 0xFE__
            g4_hi = (groups[4] >> 8) & 0xFF
            g4_lo = groups[4] & 0xFF
            g5_hi = (groups[5] >> 8) & 0xFF
            g5_lo = groups[5] & 0xFF

            if g5_hi == 0xFF and g5_lo == 0xFE:
                # Reconstruct MAC: flip universal/local bit (bit 6 of first byte)
                b0 = g4_hi ^ 0x02  # flip U/L bit
                b1 = g4_lo
                b2 = (groups[5] >> 8) & 0xFF  # 0xFF
                b3 = groups[5] & 0xFF          # 0xFE — skip these in MAC
                b4 = (groups[6] >> 8) & 0xFF
                b5 = groups[6] & 0xFF
                b6 = (groups[7] >> 8) & 0xFF
                b7 = groups[7] & 0xFF
                mac = f"{b0:02x}:{b1:02x}:{(groups[5]>>8)&0xFF:02x}:{groups[5]&0xFF:02x}:{b4:02x}:{b5:02x}"
                # Correct reconstruction: EUI-64 interface ID = b0 b1 b2 FF FE b3 b4 b5
                mac_bytes = [
                    g4_hi ^ 0x02,  # flip U/L bit back to OUI canonical form
                    g4_lo,
                    0xFF,
                    0xFE,
                    (groups[6] >> 8) & 0xFF,
                    groups[6] & 0xFF,
                ]
                mac_str = ":".join(f"{b:02x}" for b in mac_bytes[:2] + mac_bytes[4:])
                actual_mac = f"{mac_bytes[0]:02x}:{mac_bytes[1]:02x}:{0xFF:02x}:{0xFE:02x}:{mac_bytes[4]:02x}:{mac_bytes[5]:02x}"
                # Proper 6-byte MAC without FF:FE middle bytes
                real_mac = f"{mac_bytes[0]:02x}:{mac_bytes[1]:02x}:{mac_bytes[4]:02x}:{mac_bytes[5]:02x}"
                full_mac = f"{mac_bytes[0]:02x}:{mac_bytes[1]:02x}:{groups[6]>>8 & 0xFF:02x}:{groups[6]&0xFF:02x}"
                # Build proper EUI-48 from EUI-64: remove bytes 3&4 (FF:FE)
                eui48 = [
                    g4_hi ^ 0x02,
                    g4_lo,
                    (groups[6] >> 8) & 0xFF,
                    groups[6] & 0xFF,
                    (groups[7] >> 8) & 0xFF,
                    groups[7] & 0xFF,
                ]
                embedded = ":".join(f"{b:02x}" for b in eui48)
                info["is_eui64"] = True
                info["embedded_mac"] = embedded
                info["notes"].append(
                    f"EUI-64 interface ID — MAC address derived from NIC: {embedded} "
                    f"(privacy concern: MAC embedded in IPv6 address)"
                )
            else:
                info["notes"].append(
                    "Interface ID does not follow EUI-64 — likely privacy extension (RFC 4941) "
                    "or manually/statically assigned"
                )

    except Exception:
        info["notes"].append("Address parse error during classification")

    return info


# ─── Analysis Functions ──────────────────────────────────────────────────────

def analyse_overview(pcap: str, ipv6: str) -> dict:
    """General traffic overview for the IPv6 address."""
    base_filter = f"ipv6.addr == {ipv6}"

    total = _count(pcap, base_filter)
    rows = _run_tshark(pcap, base_filter,
                       ["frame.time_relative", "frame.time_epoch", "frame.len",
                        "frame.protocols", "ipv6.src"])

    if not rows:
        return {"total_packets": 0}

    timestamps = []
    epoch_start = None
    total_bytes = 0
    tx_bytes = 0
    rx_bytes = 0
    tx_packets = 0
    rx_packets = 0
    protocol_stacks = defaultdict(int)

    for row in rows:
        try:
            t_rel = float(row[0])
            timestamps.append(t_rel)
            if epoch_start is None and row[1]:
                try:
                    epoch_start = float(row[1])
                except ValueError:
                    pass
            pkt_len = int(row[2])
            total_bytes += pkt_len
            src = row[4] if len(row) > 4 else ""
            if src == ipv6:
                tx_bytes += pkt_len
                tx_packets += 1
            else:
                rx_bytes += pkt_len
                rx_packets += 1
        except (ValueError, IndexError):
            pass
        if len(row) > 3 and row[3]:
            protocol_stacks[row[3]] += 1

    duration = max(timestamps) - min(timestamps) if timestamps else 0

    # Per-hour traffic timeline buckets
    timeline = defaultdict(int)
    for t in timestamps:
        bucket = int(t // 3600)
        timeline[bucket] += 1
    timeline_list = [{"hour_offset": k, "packets": v}
                     for k, v in sorted(timeline.items())]

    # Top protocol breakdown (highest layer)
    proto_summary = defaultdict(int)
    for stack, count in protocol_stacks.items():
        parts = stack.split(":")
        top_proto = parts[-1] if parts else "unknown"
        proto_summary[top_proto] += count

    # Full protocol stack distribution (top 10 stacks)
    top_stacks = dict(sorted(protocol_stacks.items(), key=lambda x: -x[1])[:10])

    # Peer addresses with tx/rx per peer
    peer_rows = _run_tshark(pcap, base_filter, ["ipv6.src", "ipv6.dst", "frame.len"])
    peers = defaultdict(lambda: {"packets": 0, "bytes": 0, "tx": 0, "rx": 0})
    for row in peer_rows:
        if len(row) >= 3:
            src, dst = row[0], row[1]
            try:
                plen = int(row[2])
            except ValueError:
                plen = 0
            if src == ipv6:
                peer = dst
                peers[peer]["tx"] += 1
            else:
                peer = src
                peers[peer]["rx"] += 1
            peers[peer]["packets"] += 1
            peers[peer]["bytes"] += plen

    top_peers = {k: v for k, v in sorted(peers.items(), key=lambda x: -x[1]["packets"])[:10]}

    capture_start = ""
    if epoch_start is not None:
        try:
            capture_start = datetime.fromtimestamp(epoch_start, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, OverflowError):
            pass

    return {
        "total_packets": total,
        "total_bytes": total_bytes,
        "tx_packets": tx_packets,
        "rx_packets": rx_packets,
        "tx_bytes": tx_bytes,
        "rx_bytes": rx_bytes,
        "duration_seconds": round(duration, 2),
        "capture_start": capture_start,
        "avg_packets_per_sec": round(total / max(duration, 1), 2),
        "avg_bytes_per_packet": round(total_bytes / max(total, 1), 1),
        "protocol_distribution": dict(sorted(proto_summary.items(), key=lambda x: -x[1])),
        "protocol_stacks": top_stacks,
        "top_peers": top_peers,
        "traffic_timeline": timeline_list,
    }


def analyse_address_info(pcap: str, ipv6: str) -> dict:
    """
    Classify the IPv6 address and discover all associated addresses
    (link-local, multicast memberships, any other GUAs seen from same MAC).
    """
    addr_info = _classify_ipv6_address(ipv6)

    # Discover MAC address from NA/NS frames where this host is source
    mac = None
    mac_rows = _run_tshark(
        pcap,
        f"(ipv6.src == {ipv6} && icmpv6.type == 136) || "
        f"(ipv6.src == {ipv6} && icmpv6.type == 135)",
        ["eth.src", "icmpv6.nd.na.target_address"]
    )
    macs_seen = defaultdict(int)
    for row in mac_rows:
        if row and row[0]:
            macs_seen[row[0]] += 1
    if not macs_seen:
        # Fall back to any frame from this source
        src_rows = _run_tshark(pcap, f"ipv6.src == {ipv6}", ["eth.src"])
        for row in src_rows:
            if row and row[0]:
                macs_seen[row[0]] += 1
    if macs_seen:
        mac = max(macs_seen, key=lambda k: macs_seen[k])
        addr_info["observed_mac"] = mac
        # Validate EUI-64 against observed MAC
        if addr_info.get("is_eui64") and addr_info.get("embedded_mac"):
            embedded = addr_info["embedded_mac"].lower().replace("-", ":")
            observed = mac.lower().replace("-", ":")
            if embedded == observed:
                addr_info["notes"].append(
                    f"EUI-64 MAC verification: MATCH — embedded MAC {embedded} "
                    "matches observed Ethernet source address"
                )
            else:
                addr_info["notes"].append(
                    f"EUI-64 MAC mismatch: embedded={embedded} vs observed={observed} "
                    "— possible address spoofing or incorrect EUI-64 derivation"
                )

    # All IPv6 source addresses seen from the same MAC (multi-address host detection)
    other_addrs = []
    if mac:
        other_rows = _run_tshark(
            pcap,
            f"eth.src == {mac} && ipv6",
            ["ipv6.src"]
        )
        seen_addrs = defaultdict(int)
        for row in other_rows:
            if row and row[0] and row[0] != ipv6:
                seen_addrs[row[0]] += 1
        for a, cnt in sorted(seen_addrs.items(), key=lambda x: -x[1]):
            classified = _classify_ipv6_address(a)
            other_addrs.append({
                "address": a,
                "packets": cnt,
                "type": classified.get("type", "unknown"),
                "scope": classified.get("scope", "unknown"),
            })
    addr_info["other_addresses_same_host"] = other_addrs[:15]

    # Solicited-node multicast address that maps to this host
    # Format: ff02::1:ffXX:XXXX where last 3 bytes come from host address
    try:
        parts = ipv6.split(":")
        last_part = parts[-1].zfill(4)
        second_last = parts[-2].zfill(4)
        sol_node = f"ff02::1:ff{second_last[2:4]}:{last_part}"
        addr_info["solicited_node_multicast"] = sol_node
        # Check if we see solicited-node NS for this address
        sol_ns_count = _count(pcap, f"ipv6.dst == {sol_node} && icmpv6.type == 135")
        addr_info["solicited_node_ns_count"] = sol_ns_count
    except (IndexError, ValueError):
        pass

    return addr_info


def analyse_neighbor_discovery(pcap: str, ipv6: str) -> dict:
    """
    Deep NDP analysis:
    - NS/NA pairing with RTT measurement
    - DAD (Duplicate Address Detection) events
    - Router Advertisements received (prefix, flags, lifetime)
    - Router Solicitations sent
    - Redirect messages
    - NDP cache poisoning signals (unsolicited NAs, conflicting NAs)
    """
    result = {
        "ns_sent": 0, "ns_received": 0,
        "na_sent": 0, "na_received": 0,
        "rs_sent": 0, "ra_received": 0,
        "redirect_received": 0,
        "dad_attempts": 0,
        "dad_conflicts": [],
        "na_rtt_ms": [],
        "avg_na_rtt_ms": None,
        "unsolicited_na_count": 0,
        "router_advertisements": [],
        "na_detail": [],
        "ns_detail": [],
        "ndp_security_notes": [],
    }

    # Counts
    result["ns_sent"] = _count(pcap, f"ipv6.src == {ipv6} && icmpv6.type == 135")
    result["ns_received"] = _count(pcap, f"ipv6.dst == {ipv6} && icmpv6.type == 135")
    result["na_sent"] = _count(pcap, f"ipv6.src == {ipv6} && icmpv6.type == 136")
    result["na_received"] = _count(pcap, f"ipv6.dst == {ipv6} && icmpv6.type == 136")
    result["rs_sent"] = _count(pcap, f"ipv6.src == {ipv6} && icmpv6.type == 133")
    result["ra_received"] = _count(pcap, f"ipv6.dst == {ipv6} && icmpv6.type == 134")
    result["redirect_received"] = _count(pcap, f"ipv6.dst == {ipv6} && icmpv6.type == 137")

    # DAD: NS from :: (unspecified source) for this address
    dad_rows = _run_tshark(
        pcap,
        f"icmpv6.nd.ns.target_address == {ipv6} && ipv6.src == ::",
        ["frame.number", "frame.time_relative", "eth.src"]
    )
    result["dad_attempts"] = len(dad_rows)
    for row in dad_rows:
        if len(row) >= 3:
            result["ns_detail"].append({
                "frame": row[0], "time": row[1],
                "src_mac": row[2], "type": "DAD probe (src=::)"
            })

    # DAD conflict: NA sent for same target during DAD window
    if dad_rows:
        for dad in dad_rows:
            try:
                dad_time = float(dad[1])
                conflict_rows = _run_tshark(
                    pcap,
                    f"icmpv6.nd.na.target_address == {ipv6} && "
                    f"frame.time_relative >= {dad_time} && "
                    f"frame.time_relative <= {dad_time + 2.0}",
                    ["frame.number", "frame.time_relative", "ipv6.src", "eth.src"]
                )
                for row in conflict_rows:
                    if len(row) >= 3 and row[2] != ipv6:
                        result["dad_conflicts"].append({
                            "frame": row[0], "time": row[1],
                            "conflicting_src": row[2], "conflicting_mac": row[3] if len(row) > 3 else ""
                        })
            except (ValueError, IndexError):
                pass

    # NS/NA RTT: pair each NS sent with corresponding NA received
    ns_sent_rows = _run_tshark(
        pcap,
        f"ipv6.src == {ipv6} && icmpv6.type == 135",
        ["frame.time_relative", "icmpv6.nd.ns.target_address"]
    )
    na_recv_rows = _run_tshark(
        pcap,
        f"ipv6.dst == {ipv6} && icmpv6.type == 136",
        ["frame.time_relative", "icmpv6.nd.na.target_address"]
    )

    # Build lookup: target → list of NA times
    na_times_by_target = defaultdict(list)
    for row in na_recv_rows:
        if len(row) >= 2:
            try:
                na_times_by_target[row[1]].append(float(row[0]))
            except ValueError:
                pass

    rtts = []
    for row in ns_sent_rows:
        if len(row) >= 2:
            try:
                ns_t = float(row[0])
                target = row[1]
                for na_t in na_times_by_target.get(target, []):
                    if 0 < na_t - ns_t < 5.0:
                        rtts.append(round((na_t - ns_t) * 1000, 2))
                        break
            except ValueError:
                pass

    result["na_rtt_ms"] = sorted(rtts)[:30]
    if rtts:
        result["avg_na_rtt_ms"] = round(sum(rtts) / len(rtts), 2)
        result["min_na_rtt_ms"] = min(rtts)
        result["max_na_rtt_ms"] = max(rtts)

    # Unsolicited NAs (Override flag set, no prior NS from recipient) — security signal
    unsol_rows = _run_tshark(
        pcap,
        f"ipv6.src == {ipv6} && icmpv6.type == 136 && icmpv6.nd.na.flag.o == 1",
        ["frame.number", "frame.time_relative", "ipv6.dst", "icmpv6.nd.na.target_address"]
    )
    result["unsolicited_na_count"] = len(unsol_rows)
    for row in unsol_rows[:10]:
        if len(row) >= 4:
            result["na_detail"].append({
                "frame": row[0], "time": row[1], "dst": row[2],
                "target": row[3], "flag": "Override (unsolicited)"
            })

    # Router Advertisements: extract prefix, lifetime, flags
    ra_rows = _run_tshark(
        pcap,
        f"ipv6.dst == {ipv6} && icmpv6.type == 134",
        ["frame.number", "frame.time_relative", "ipv6.src",
         "icmpv6.nd.ra.router_lifetime", "icmpv6.nd.ra.cur_hop_limit",
         "icmpv6.nd.ra.flag.m", "icmpv6.nd.ra.flag.o",
         "icmpv6.nd.ra.reachable_time", "icmpv6.nd.ra.retrans_timer"]
    ) or _run_tshark(
        # RA can be sent to all-nodes ff02::1 — also capture those
        pcap,
        "ipv6.dst == ff02::1 && icmpv6.type == 134",
        ["frame.number", "frame.time_relative", "ipv6.src",
         "icmpv6.nd.ra.router_lifetime", "icmpv6.nd.ra.cur_hop_limit",
         "icmpv6.nd.ra.flag.m", "icmpv6.nd.ra.flag.o",
         "icmpv6.nd.ra.reachable_time", "icmpv6.nd.ra.retrans_timer"]
    )

    for row in ra_rows[:10]:
        if len(row) >= 3:
            ra = {
                "frame": row[0],
                "time": row[1],
                "router": row[2],
                "router_lifetime_s": row[3] if len(row) > 3 else "",
                "hop_limit": row[4] if len(row) > 4 else "",
                "managed_flag_M": row[5] if len(row) > 5 else "",
                "other_flag_O": row[6] if len(row) > 6 else "",
                "reachable_time_ms": row[7] if len(row) > 7 else "",
                "retrans_timer_ms": row[8] if len(row) > 8 else "",
            }
            # Get prefix info from RA (separate tshark query for prefix options)
            pfx_rows = _run_tshark(
                pcap,
                f"frame.number == {row[0]}",
                ["icmpv6.nd.ra.prefix", "icmpv6.nd.ra.prefix.length",
                 "icmpv6.nd.ra.prefix.valid_lifetime",
                 "icmpv6.nd.ra.prefix.preferred_lifetime",
                 "icmpv6.nd.ra.prefix.flag.a", "icmpv6.nd.ra.prefix.flag.l"]
            )
            if pfx_rows:
                p = pfx_rows[0]
                ra["prefix"] = p[0] if p[0] else ""
                ra["prefix_length"] = p[1] if len(p) > 1 else ""
                ra["valid_lifetime"] = p[2] if len(p) > 2 else ""
                ra["preferred_lifetime"] = p[3] if len(p) > 3 else ""
                ra["autonomous_flag_A"] = p[4] if len(p) > 4 else ""
                ra["on_link_flag_L"] = p[5] if len(p) > 5 else ""
                # Lifetime of 0 = router withdrawal
                try:
                    if int(p[2]) == 0:
                        ra["notes"] = "valid_lifetime=0: prefix/router withdrawal"
                    elif int(p[2]) == 0xFFFFFFFF:
                        ra["notes"] = "valid_lifetime=infinite"
                except (ValueError, IndexError):
                    pass
            result["router_advertisements"].append(ra)

    # Security signals
    if result["unsolicited_na_count"] > 3:
        result["ndp_security_notes"].append(
            f"HIGH: {result['unsolicited_na_count']} unsolicited Neighbor Advertisements with "
            "Override flag — potential NDP cache poisoning / gratuitous NA flood"
        )
    if result["dad_conflicts"]:
        result["ndp_security_notes"].append(
            f"HIGH: {len(result['dad_conflicts'])} DAD conflict(s) — "
            "another host claimed this address during DAD window (address conflict)"
        )
    if result["redirect_received"] > 0:
        result["ndp_security_notes"].append(
            f"MEDIUM: {result['redirect_received']} ICMPv6 Redirect(s) received — "
            "router is changing the next-hop for some destinations"
        )
    if result["ra_received"] == 0 and result["rs_sent"] > 0:
        result["ndp_security_notes"].append(
            "INFO: Router Solicitation(s) sent but no Router Advertisement received — "
            "host may be using stateless autoconfig without router response (SLAAC failure)"
        )

    return result


def analyse_dns6(pcap: str, ipv6: str) -> dict:
    """
    DNS analysis focused on IPv6 resolution:
    - AAAA queries/responses involving this host
    - PTR reverse lookup for this address (ip6.arpa)
    - DNS response codes and latency
    - Hostnames associated with this IPv6 address
    """
    result = {
        "aaaa_queries_sent": 0,
        "aaaa_responses_received": 0,
        "ptr_queries": [],
        "ptr_responses": [],
        "hostnames_resolved": [],
        "dns_errors": [],
        "avg_dns_rtt_ms": None,
        "dns_servers": [],
        "nxdomain_count": 0,
        "dns_detail": [],
    }

    base_dns = f"ipv6.addr == {ipv6} && dns"

    # All DNS traffic involving this host
    dns_rows = _run_tshark(
        pcap, base_dns,
        ["frame.number", "frame.time_relative", "ipv6.src", "ipv6.dst",
         "dns.qry.name", "dns.qry.type", "dns.flags.response",
         "dns.flags.rcode", "dns.a", "dns.aaaa"]
    )

    dns_servers = set()
    query_times = {}  # transaction_id → time (approximate via frame number)
    rtts = []
    hostnames = set()

    DNS_RCODES = {
        "0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL",
        "3": "NXDOMAIN", "4": "NOTIMP", "5": "REFUSED",
    }
    DNS_QTYPES = {
        "1": "A", "28": "AAAA", "12": "PTR", "5": "CNAME",
        "15": "MX", "33": "SRV", "16": "TXT", "2": "NS",
    }

    for row in dns_rows:
        if len(row) < 8:
            continue
        frame_no, t_rel, src, dst = row[0], row[1], row[2], row[3]
        qname = row[4] if len(row) > 4 else ""
        qtype_raw = row[5] if len(row) > 5 else ""
        is_response = row[6] if len(row) > 6 else "0"
        rcode = row[7] if len(row) > 7 else "0"
        aaaa_val = row[9] if len(row) > 9 else ""

        qtype = DNS_QTYPES.get(qtype_raw, qtype_raw)

        if is_response == "0":
            # Query from this host
            if dst != ipv6:
                dns_servers.add(dst)
            if qtype == "AAAA":
                result["aaaa_queries_sent"] += 1
            if qtype == "PTR":
                result["ptr_queries"].append({
                    "frame": frame_no, "time": t_rel,
                    "name": qname, "dst": dst
                })
            try:
                query_times[frame_no] = float(t_rel)
            except ValueError:
                pass
        else:
            # Response to this host
            rcode_name = DNS_RCODES.get(rcode, rcode)
            if qtype == "AAAA":
                result["aaaa_responses_received"] += 1
            if qtype == "PTR" and qname:
                if aaaa_val or rcode == "0":
                    result["ptr_responses"].append({
                        "frame": frame_no, "time": t_rel,
                        "ptr_name": qname, "rcode": rcode_name
                    })
            if rcode == "3":
                result["nxdomain_count"] += 1
                result["dns_errors"].append({
                    "frame": frame_no, "time": t_rel,
                    "name": qname, "type": qtype, "rcode": "NXDOMAIN"
                })
            elif rcode not in ("0", ""):
                result["dns_errors"].append({
                    "frame": frame_no, "time": t_rel,
                    "name": qname, "type": qtype,
                    "rcode": rcode_name
                })
            # Collect resolved hostnames
            if aaaa_val and aaaa_val.lower() == ipv6.lower() and qname:
                hostnames.add(qname)

        result["dns_detail"].append({
            "frame": frame_no, "time": t_rel,
            "direction": "response" if is_response == "1" else "query",
            "name": qname, "type": qtype, "rcode": DNS_RCODES.get(rcode, rcode)
        })

    result["hostnames_resolved"] = sorted(hostnames)
    result["dns_servers"] = sorted(dns_servers)

    # Build PTR name for this address and check if queried
    # IPv6 PTR = reversed nibbles + .ip6.arpa
    try:
        parts = ipv6.split(":")
        expanded = []
        for p in parts:
            expanded.append(p.zfill(4))
        nibbles = "".join(expanded)
        ptr_name = ".".join(reversed(list(nibbles))) + ".ip6.arpa"
        result["ptr_reverse_name"] = ptr_name
        # Check if this PTR was queried
        ptr_queried = any(
            r.get("name", "").lower() == ptr_name.lower()
            for r in result["ptr_queries"]
        )
        result["ptr_was_queried"] = ptr_queried
    except Exception:
        result["ptr_reverse_name"] = ""
        result["ptr_was_queried"] = False

    return result


def analyse_extension_headers(pcap: str, ipv6: str) -> dict:
    """
    IPv6 Extension Header analysis:
    - Hop-by-Hop options (router alert, MLD, Jumbogram)
    - Destination options
    - Routing header type 0 (deprecated/dangerous) and type 2
    - Fragment headers (fragmentation behaviour, reassembly issues)
    - Flow label usage and consistency
    """
    result = {
        "hop_by_hop_count": 0,
        "routing_header_count": 0,
        "routing_type0_count": 0,
        "routing_type2_count": 0,
        "fragment_header_count": 0,
        "destination_options_count": 0,
        "flow_labels": {},
        "fragmented_packets": [],
        "routing_header_detail": [],
        "security_notes": [],
    }

    base = f"ipv6.addr == {ipv6}"

    # Hop-by-Hop
    result["hop_by_hop_count"] = _count(pcap, f"{base} && ipv6.hopopts")

    # Routing headers
    result["routing_header_count"] = _count(pcap, f"{base} && ipv6.routing")
    result["routing_type0_count"] = _count(pcap, f"{base} && ipv6.routing.type == 0")
    result["routing_type2_count"] = _count(pcap, f"{base} && ipv6.routing.type == 2")

    # Destination options
    result["destination_options_count"] = _count(pcap, f"{base} && ipv6.dstopts")

    # Fragment headers
    frag_rows = _run_tshark(
        pcap, f"{base} && ipv6.frag",
        ["frame.number", "frame.time_relative", "ipv6.src", "ipv6.dst",
         "ipv6.frag.id", "ipv6.frag.offset", "ipv6.frag.more"]
    )
    result["fragment_header_count"] = len(frag_rows)
    frag_ids = defaultdict(list)
    for row in frag_rows[:30]:
        if len(row) >= 7:
            result["fragmented_packets"].append({
                "frame": row[0], "time": row[1], "src": row[2], "dst": row[3],
                "frag_id": row[4], "offset": row[5], "more_frags": row[6]
            })
            if row[4]:
                frag_ids[row[4]].append(row[5])

    # Routing type 0 detail (deprecated per RFC 5095 — security risk)
    if result["routing_type0_count"] > 0:
        rh0_rows = _run_tshark(
            pcap, f"{base} && ipv6.routing.type == 0",
            ["frame.number", "frame.time_relative", "ipv6.src", "ipv6.dst",
             "ipv6.routing.segleft"]
        )
        for row in rh0_rows[:10]:
            if len(row) >= 5:
                result["routing_header_detail"].append({
                    "frame": row[0], "time": row[1], "src": row[2], "dst": row[3],
                    "type": 0, "segments_left": row[4]
                })

    # Flow labels
    fl_rows = _run_tshark(
        pcap, f"ipv6.src == {ipv6} && ipv6.flow != 0",
        ["ipv6.flow"]
    )
    flow_tally = defaultdict(int)
    for row in fl_rows:
        if row and row[0]:
            flow_tally[row[0]] += 1
    result["flow_labels"] = dict(sorted(flow_tally.items(), key=lambda x: -x[1])[:10])
    result["unique_flow_labels"] = len(flow_tally)

    # Security notes
    if result["routing_type0_count"] > 0:
        result["security_notes"].append(
            f"HIGH: {result['routing_type0_count']} packet(s) with IPv6 Routing Header Type 0 "
            "(RH0) — deprecated by RFC 5095. RH0 can be exploited for traffic amplification and "
            "source routing attacks. Drop these packets at the perimeter."
        )
    if result["fragment_header_count"] > 0:
        atomic_frags = _count(pcap, f"{base} && ipv6.frag.offset == 0 && ipv6.frag.more == 0")
        if atomic_frags > 0:
            result["atomic_fragment_count"] = atomic_frags
            result["security_notes"].append(
                f"MEDIUM: {atomic_frags} atomic fragment(s) detected (offset=0, M=0). "
                "Atomic fragments can be used for fragment ID collision attacks (RFC 8021). "
                "Firewall should drop or carefully handle atomic fragments."
            )
    if result["hop_by_hop_count"] > 0:
        result["security_notes"].append(
            f"INFO: {result['hop_by_hop_count']} packet(s) with Hop-by-Hop extension header. "
            "Hop-by-Hop headers are processed by every router — high volume can cause router CPU load."
        )

    return result


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
    }


def analyse_statistics(pcap: str, ipv6: str, overview: dict, udp: dict) -> dict:
    """
    Compute analytical and statistical metrics:
    - Inter-packet interval (IPI): mean, median, std deviation, jitter per protocol
    - Packet size distribution and percentile stats
    - Traffic burstiness (coefficient of variation)
    - SNMP polling interval and request rate analysis
    - Hourly traffic statistics derived from the timeline
    - TX/RX ratio and byte ratio
    - Protocol share percentages
    """
    base = f"ipv6.addr == {ipv6}"
    result = {}

    # ── All-traffic IPI and packet size stats ─────────────────────────────────
    rows = _run_tshark(pcap, base, ["frame.time_relative", "frame.len"])
    timestamps, sizes = [], []
    for row in rows:
        try:
            timestamps.append(float(row[0]))
            sizes.append(int(row[1]))
        except (ValueError, IndexError):
            pass

    if len(timestamps) > 1:
        timestamps.sort()
        ipis = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        ipis = [x for x in ipis if x >= 0]
        n = len(ipis)
        if n:
            mean_ipi = sum(ipis) / n
            s_ipis = sorted(ipis)
            median_ipi = s_ipis[n // 2]
            variance = sum((x - mean_ipi) ** 2 for x in ipis) / n
            std_ipi = math.sqrt(variance)
            cv = std_ipi / mean_ipi if mean_ipi > 0 else 0
            jitter = sum(abs(ipis[i + 1] - ipis[i]) for i in range(n - 1)) / max(n - 1, 1)
            result["ipi_all"] = {
                "mean_ms": round(mean_ipi * 1000, 2),
                "median_ms": round(median_ipi * 1000, 2),
                "std_ms": round(std_ipi * 1000, 2),
                "min_ms": round(s_ipis[0] * 1000, 2),
                "max_ms": round(s_ipis[-1] * 1000, 2),
                "jitter_ms": round(jitter * 1000, 2),
                "cv": round(cv, 3),
                "burstiness": "high" if cv > 2.0 else "moderate" if cv > 0.5 else "low/periodic",
            }

    if sizes:
        n = len(sizes)
        s_sizes = sorted(sizes)
        mean_sz = sum(sizes) / n
        std_sz = math.sqrt(sum((x - mean_sz) ** 2 for x in sizes) / n)
        buckets = {"tiny_lt64": 0, "small_64_256": 0, "medium_256_1024": 0, "large_gt1024": 0}
        for s in sizes:
            if s < 64:
                buckets["tiny_lt64"] += 1
            elif s < 256:
                buckets["small_64_256"] += 1
            elif s < 1024:
                buckets["medium_256_1024"] += 1
            else:
                buckets["large_gt1024"] += 1
        # Compute percentages
        buckets_pct = {k: round(v / n * 100, 1) for k, v in buckets.items()}
        result["packet_size_stats"] = {
            "min_bytes": s_sizes[0],
            "max_bytes": s_sizes[-1],
            "mean_bytes": round(mean_sz, 1),
            "median_bytes": s_sizes[n // 2],
            "std_bytes": round(std_sz, 1),
            "p95_bytes": s_sizes[min(int(0.95 * n), n - 1)],
            "p99_bytes": s_sizes[min(int(0.99 * n), n - 1)],
            "size_buckets": buckets,
            "size_buckets_pct": buckets_pct,
        }

    # ── Per-protocol IPI ──────────────────────────────────────────────────────
    proto_ipis: dict = {}
    for proto, filt in [
        ("snmp", f"{base} && snmp"),
        ("tcp", f"{base} && tcp"),
        ("icmpv6", f"{base} && icmpv6"),
        ("udp", f"{base} && udp && !snmp"),
    ]:
        p_rows = _run_tshark(pcap, filt, ["frame.time_relative"])
        p_ts = []
        for r in p_rows:
            try:
                p_ts.append(float(r[0]))
            except (ValueError, IndexError):
                pass
        if len(p_ts) > 2:
            p_ts.sort()
            p_ipis = [p_ts[i + 1] - p_ts[i] for i in range(len(p_ts) - 1)]
            p_ipis = [x for x in p_ipis if 0 < x < 300]
            if p_ipis:
                m = sum(p_ipis) / len(p_ipis)
                s_p = sorted(p_ipis)
                std_p = math.sqrt(sum((x - m) ** 2 for x in p_ipis) / len(p_ipis))
                proto_ipis[proto] = {
                    "mean_interval_ms": round(m * 1000, 2),
                    "median_interval_ms": round(s_p[len(s_p) // 2] * 1000, 2),
                    "std_ms": round(std_p * 1000, 2),
                    "sample_count": len(p_ipis),
                    "implied_rate_per_sec": round(1 / max(m, 0.001), 3),
                }
    if proto_ipis:
        result["per_protocol_intervals"] = proto_ipis

    # ── Protocol share percentages ────────────────────────────────────────────
    proto_dist = overview.get("protocol_distribution", {})
    total_pkts = overview.get("total_packets", 1)
    if proto_dist and total_pkts:
        result["protocol_share_pct"] = {
            k: round(v / total_pkts * 100, 1)
            for k, v in proto_dist.items()
        }

    # ── Hourly statistics ─────────────────────────────────────────────────────
    timeline = overview.get("traffic_timeline", [])
    if timeline:
        counts = [b["packets"] for b in timeline]
        if counts:
            peak = max(counts)
            peak_idx = counts.index(peak)
            result["hourly_stats"] = {
                "min_pkts_per_hour": min(counts),
                "max_pkts_per_hour": peak,
                "avg_pkts_per_hour": round(sum(counts) / len(counts), 1),
                "active_hours": len([c for c in counts if c > 0]),
                "total_hours": len(counts),
                "peak_hour_offset": timeline[peak_idx]["hour_offset"],
                "idle_hours": len([c for c in counts if c == 0]),
            }

    # ── TX/RX ratio ───────────────────────────────────────────────────────────
    tx_pkts = overview.get("tx_packets", 0)
    rx_pkts = overview.get("rx_packets", 0)
    total_p = tx_pkts + rx_pkts
    tx_bytes = overview.get("tx_bytes", 0)
    rx_bytes = overview.get("rx_bytes", 0)
    total_b = overview.get("total_bytes", 1)
    if total_p:
        result["traffic_ratio"] = {
            "tx_packets_pct": round(tx_pkts / total_p * 100, 1),
            "rx_packets_pct": round(rx_pkts / total_p * 100, 1),
            "tx_bytes_pct": round(tx_bytes / max(total_b, 1) * 100, 1),
            "rx_bytes_pct": round(rx_bytes / max(total_b, 1) * 100, 1),
            "tx_kb": round(tx_bytes / 1024, 1),
            "rx_kb": round(rx_bytes / 1024, 1),
        }

    # ── SNMP polling interval analysis ────────────────────────────────────────
    snmp = udp.get("snmp_analysis", {})
    if snmp.get("total_snmp_packets", 0) > 0:
        req_rows = _run_tshark(pcap, f"ipv6.dst == {ipv6} && snmp", ["frame.time_relative"])
        req_ts = []
        for r in req_rows:
            try:
                req_ts.append(float(r[0]))
            except (ValueError, IndexError):
                pass
        if len(req_ts) > 2:
            req_ts.sort()
            req_ipis = [req_ts[i + 1] - req_ts[i] for i in range(len(req_ts) - 1)]
            poll_ipis = [x for x in req_ipis if 0.05 < x < 120]
            if poll_ipis:
                m = sum(poll_ipis) / len(poll_ipis)
                s_poll = sorted(poll_ipis)
                std_poll = math.sqrt(sum((x - m) ** 2 for x in poll_ipis) / len(poll_ipis))
                # Estimate polling periods: look for a dominant cluster
                consistency = round(std_poll / max(m, 0.001), 2)
                result["snmp_polling"] = {
                    "estimated_poll_interval_s": round(m, 3),
                    "median_poll_interval_s": round(s_poll[len(s_poll) // 2], 3),
                    "std_poll_interval_s": round(std_poll, 3),
                    "consistency_cv": consistency,
                    "poll_regularity": (
                        "highly regular" if consistency < 0.1
                        else "regular" if consistency < 0.3
                        else "irregular"
                    ),
                    "sample_count": len(poll_ipis),
                    "estimated_requests_per_hour": round(3600 / max(m, 0.001), 0),
                    "error_rate_pct": snmp.get("error_rate_pct", 0),
                    "unanswered_pct": round(
                        snmp.get("unanswered_requests", 0)
                        / max(snmp.get("requests_to_host", 1), 1) * 100, 1
                    ),
                }

    # ── Peer share percentages ────────────────────────────────────────────────
    top_peers = overview.get("top_peers", {})
    if top_peers and total_pkts:
        result["peer_share_pct"] = {}
        for peer, pdata in top_peers.items():
            pkts = pdata.get("packets", 0) if isinstance(pdata, dict) else pdata
            result["peer_share_pct"][peer] = round(pkts / total_pkts * 100, 1)

    return result


def detect_issues(overview: dict, tcp: dict, udp: dict, icmpv6: dict,
                  ndp: dict = None, dns6: dict = None, ext_hdrs: dict = None) -> list:
    """Detect issues and anomalies from the analysis results."""
    issues = []
    ndp = ndp or {}
    dns6 = dns6 or {}
    ext_hdrs = ext_hdrs or {}

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

    # NDP / Neighbor Discovery issues
    if ndp:
        if ndp.get("dad_conflicts"):
            conflicting_hosts = ", ".join(c.get('conflicting_src', '') for c in ndp['dad_conflicts'][:3])
            issues.append({
                "severity": "high",
                "category": "NDP / Address",
                "title": f"Duplicate Address Detection (DAD) conflict — {len(ndp['dad_conflicts'])} conflict(s)",
                "detail": (
                    f"Another host responded during the DAD probe window, claiming the same "
                    f"address {ipv6.split(' ')[-1] if ' ' in str(ipv6) else ipv6}. "
                    f"Conflicting sources: {conflicting_hosts}"
                ),
                "remediation": (
                    f"Conflicting host(s) detected: {conflicting_hosts}. "
                    "Action: (1) Identify and reconfigure the conflicting host to use a unique IPv6 address. "
                    "(2) If SLAAC is in use, check for duplicate EUI-64 MAC derivations. "
                    "(3) If DHCPv6 is in use, verify the server is not issuing duplicate leases. "
                    "(4) Use SEND (RFC 3971) to cryptographically validate NDP messages."
                ),
            })
        if ndp.get("unsolicited_na_count", 0) > 3:
            na_count = ndp['unsolicited_na_count']
            # Try to identify which MAC/IP is sending the unsolicited NAs
            na_sources = ndp.get('unsolicited_na_sources', [])
            src_detail = f" Source(s): {', '.join(str(s) for s in na_sources[:3])}." if na_sources else ""
            issues.append({
                "severity": "high",
                "category": "Security / NDP",
                "title": f"Unsolicited Neighbor Advertisements with Override flag ({na_count})",
                "detail": (
                    f"{na_count} unsolicited NA(s) with Override=1 detected.{src_detail} "
                    "This pattern is used in NDP cache poisoning attacks to redirect traffic "
                    "by overriding legitimate neighbour cache entries."
                ),
                "remediation": (
                    f"{na_count} unsolicited Override-NA(s) indicate a potential NDP cache poisoning attack." 
                    + (f" Investigate host(s): {', '.join(str(s) for s in na_sources[:3])}." if na_sources else "")
                    + " Actions: (1) Deploy RA Guard (RFC 6105) on access switches to block unsolicited RAs/NAs. "
                    "(2) Enable IPv6 First-Hop Security (IPv6 FHS) on Cisco/Juniper equipment. "
                    "(3) Consider SEND (RFC 3971) for cryptographic NDP validation. "
                    "(4) Isolate any host confirmed as the NA source."
                ),
            })
        if ndp.get("ndp_security_notes"):
            for note in ndp["ndp_security_notes"]:
                level = note.split(":")[0].strip().lower()
                sev = "high" if level == "high" else "medium" if level == "medium" else "low"
                issues.append({
                    "severity": sev,
                    "category": "NDP",
                    "title": note.split(":", 1)[-1].strip()[:80],
                    "detail": note,
                    "remediation": "Review NDP security configuration on network equipment.",
                })
        if ndp.get("avg_na_rtt_ms") and ndp["avg_na_rtt_ms"] > 500:
            issues.append({
                "severity": "medium",
                "category": "NDP Performance",
                "title": f"High Neighbor Discovery RTT (avg {ndp['avg_na_rtt_ms']} ms)",
                "detail": (
                    f"Average NS→NA round-trip time is {ndp['avg_na_rtt_ms']} ms "
                    f"(max {ndp.get('max_na_rtt_ms', '?')} ms). "
                    "High NDP latency causes connection setup delays and temporary reachability loss."
                ),
                "remediation": "Check device CPU load, NDP cache size limits, and link-layer "
                               "congestion on the local segment.",
            })

    # DNS / Resolution issues
    if dns6:
        if dns6.get("nxdomain_count", 0) > 5:
            nxd_count = dns6['nxdomain_count']
            top_nxd = dns6.get('top_nxdomain_names', [])
            top_detail = f" Top queried non-existent names: {', '.join(top_nxd[:5])}." if top_nxd else ""
            issues.append({
                "severity": "medium",
                "category": "DNS / Resolution",
                "title": f"{nxd_count} NXDOMAIN responses in DNS traffic",
                "detail": (
                    f"{nxd_count} DNS queries returned NXDOMAIN.{top_detail} "
                    "High NXDOMAIN rates indicate misconfigured DNS, typos, or potentially "
                    "a host performing DNS reconnaissance."
                ),
                "remediation": (
                    f"{nxd_count} NXDOMAIN responses detected."
                    + (f" Most queried non-existent names: {', '.join(top_nxd[:5])}." if top_nxd else "")
                    + " Actions: (1) Review DNS query logs for the listed names and identify the querying application. "
                    "(2) Fix DNS misconfigurations (stale CNAME targets, removed services). "
                    "(3) If queries appear automated/random, investigate source host for malware (DGA activity)."
                ),
            })
        if not dns6.get("ptr_was_queried", True) and dns6.get("ptr_reverse_name"):
            issues.append({
                "severity": "low",
                "category": "DNS / Resolution",
                "title": "No PTR (reverse DNS) lookup observed for this IPv6 address",
                "detail": (
                    f"Reverse DNS name {dns6.get('ptr_reverse_name', '')} was not queried "
                    "in this capture. Many services require working reverse DNS for logging, "
                    "authentication (SMTP, SSH), and troubleshooting."
                ),
                "remediation": "Ensure a PTR record exists for this address in your DNS zone. "
                               "Verify reverse delegation is set up with the ISP for the /48 or /64.",
            })

    # Extension header issues
    if ext_hdrs:
        for note in ext_hdrs.get("security_notes", []):
            level = note.split(":")[0].strip().lower()
            sev = "high" if level == "high" else "medium" if level == "medium" else "low"
            issues.append({
                "severity": sev,
                "category": "Extension Headers",
                "title": note.split(":", 1)[-1].strip()[:80],
                "detail": note,
                "remediation": "Configure ACLs/firewall to filter or rate-limit these extension headers.",
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
    addr_info = results.get("address_info", {})
    ndp = results.get("ndp", {})
    dns6 = results.get("dns6", {})
    ext_hdrs = results.get("extension_headers", {})
    stats = results.get("statistics", {})
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

    # Protocol distribution chart (bar chart) with percentage annotations
    proto_dist = overview.get("protocol_distribution", {})
    proto_share_pct = stats.get("protocol_share_pct", {})
    total_pkts_ov = overview.get("total_packets", 1)
    proto_bars = ""
    if proto_dist:
        max_proto = max(proto_dist.values()) if proto_dist else 1
        for proto, count in list(proto_dist.items())[:10]:
            bar_pct = int(count / max_proto * 100)
            share = proto_share_pct.get(proto, round(count / max(total_pkts_ov, 1) * 100, 1))
            proto_bars += (
                f'<div style="margin:6px 0;display:flex;align-items:center;gap:8px;">'
                f'<span style="width:90px;text-align:right;font-size:0.82em;font-weight:600">{proto}</span>'
                f'<div style="flex:1;background:#ecf0f1;border-radius:3px;height:18px;">'
                f'<div style="background:#3498db;height:18px;width:{bar_pct}%;border-radius:3px;"></div></div>'
                f'<small style="width:85px;">{count:,} &nbsp;<em style="color:#7f8c8d">({share}%)</em></small></div>\n'
            )

    # Traffic timeline SVG bar chart
    timeline_svg = ""
    timeline_data = overview.get("traffic_timeline", [])
    if timeline_data:
        max_pkts = max(b["packets"] for b in timeline_data) or 1
        bar_w = max(4, min(30, int(500 / max(len(timeline_data), 1))))
        svg_w = len(timeline_data) * (bar_w + 2) + 60
        svg_h = 100
        bars_svg = ""
        labels_svg = ""
        for i, b in enumerate(timeline_data):
            bh = int(b["packets"] / max_pkts * 70)
            x = 40 + i * (bar_w + 2)
            y = svg_h - 20 - bh
            bars_svg += (f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bh}" '
                         f'fill="#3498db" rx="1">'
                         f'<title>Hour +{b["hour_offset"]}: {b["packets"]} packets</title></rect>')
            if i % max(1, len(timeline_data) // 8) == 0:
                labels_svg += (f'<text x="{x + bar_w//2}" y="{svg_h - 4}" '
                                f'font-size="9" text-anchor="middle" fill="#7f8c8d">+{b["hour_offset"]}h</text>')
        timeline_svg = (
            f'<svg width="{svg_w}" height="{svg_h}" style="max-width:100%;">'
            f'<text x="0" y="14" font-size="10" fill="#7f8c8d">pkts</text>'
            f'<text x="0" y="26" font-size="9" fill="#aaa">{max_pkts}</text>'
            f'{bars_svg}{labels_svg}'
            f'</svg>'
        )

    # TCP port table
    tcp_port_rows = ""
    SERVICE_MAP = {
        "631": "IPP (Printing)", "9100": "RAW Printing", "443": "HTTPS",
        "80": "HTTP", "22": "SSH", "53": "DNS", "8080": "HTTP Alt/Proxy",
        "8443": "HTTPS Alt", "21": "FTP", "25": "SMTP", "110": "POP3",
        "143": "IMAP", "161": "SNMP", "162": "SNMP Trap", "3389": "RDP",
    }
    for port, count in list(tcp.get("destination_ports", {}).items())[:10]:
        service = SERVICE_MAP.get(port, "")
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
    for fl in udp.get("top_flows", [])[:15]:
        kb = round(fl.get("bytes", 0) / 1024, 1)
        udp_flow_rows += (f'<tr><td>{fl.get("src","")}</td><td>{fl.get("sport","")}</td>'
                          f'<td>{fl.get("dst","")}</td><td>{fl.get("dport","")}</td>'
                          f'<td>{fl.get("frames",0)}</td><td>{kb} KB</td></tr>\n')

    # Peers table (enhanced with tx/rx and share %)
    peer_share_pct = stats.get("peer_share_pct", {})
    peers_html = ""
    for peer, pdata in list(overview.get("top_peers", {}).items())[:10]:
        share = peer_share_pct.get(peer, "")
        share_str = f"({share}%)" if share else ""
        if isinstance(pdata, dict):
            pkts = pdata.get("packets", 0)
            tx = pdata.get("tx", 0)
            rx = pdata.get("rx", 0)
            kb = round(pdata.get("bytes", 0) / 1024, 1)
            peers_html += (
                f'<tr><td>{peer}</td>'
                f'<td>{pkts:,} <small style="color:#aaa">{share_str}</small></td>'
                f'<td>{tx:,}</td><td>{rx:,}</td><td>{kb} KB</td></tr>\n'
            )
        else:
            peers_html += f'<tr><td>{peer}</td><td>{pdata} <small style="color:#aaa">{share_str}</small></td><td>-</td><td>-</td><td>-</td></tr>\n'

    # ── Statistics card ────────────────────────────────────────────────────────
    ipi_all = stats.get("ipi_all", {})
    pkt_sz = stats.get("packet_size_stats", {})
    hourly = stats.get("hourly_stats", {})
    tr_ratio = stats.get("traffic_ratio", {})
    snmp_poll = stats.get("snmp_polling", {})
    proto_ipi = stats.get("per_protocol_intervals", {})

    # IPI summary rows
    ipi_rows = ""
    if ipi_all:
        burst_color = "#e74c3c" if ipi_all.get("burstiness") == "high" else (
            "#f39c12" if ipi_all.get("burstiness") == "moderate" else "#27ae60")
        ipi_rows += (
            f'<tr><td>All traffic</td>'
            f'<td>{ipi_all["mean_ms"]} ms</td>'
            f'<td>{ipi_all["median_ms"]} ms</td>'
            f'<td>{ipi_all["std_ms"]} ms</td>'
            f'<td>{ipi_all["jitter_ms"]} ms</td>'
            f'<td><span style="color:{burst_color};font-weight:600">{ipi_all["burstiness"]}</span> '
            f'(CV={ipi_all["cv"]})</td></tr>\n'
        )
    for proto, pipi in proto_ipi.items():
        ipi_rows += (
            f'<tr><td>{proto}</td>'
            f'<td>{pipi["mean_interval_ms"]} ms</td>'
            f'<td>{pipi["median_interval_ms"]} ms</td>'
            f'<td>{pipi.get("std_ms","—")} ms</td>'
            f'<td>—</td>'
            f'<td>{pipi["implied_rate_per_sec"]:.3f} pkt/s</td></tr>\n'
        )

    # Packet size bucket chart
    sz_buckets = pkt_sz.get("size_buckets_pct", {})
    sz_bars = ""
    sz_labels = {"tiny_lt64": "<64B (tiny)", "small_64_256": "64–256B", "medium_256_1024": "256B–1KB", "large_gt1024": ">1KB"}
    sz_colors = {"tiny_lt64": "#2ecc71", "small_64_256": "#3498db", "medium_256_1024": "#9b59b6", "large_gt1024": "#e67e22"}
    for k, label in sz_labels.items():
        p = sz_buckets.get(k, 0)
        sz_bars += (
            f'<div style="margin:4px 0;display:flex;align-items:center;gap:6px;">'
            f'<span style="width:100px;font-size:0.8em">{label}</span>'
            f'<div style="flex:1;background:#ecf0f1;border-radius:3px;height:14px;">'
            f'<div style="background:{sz_colors[k]};height:14px;width:{int(p)}%;border-radius:3px;"></div></div>'
            f'<small style="width:45px">{p}%</small></div>\n'
        )

    # SNMP polling block
    snmp_poll_html = ""
    if snmp_poll:
        reg_color = "#27ae60" if "regular" in snmp_poll.get("poll_regularity", "") else "#e67e22"
        snmp_poll_html = f"""
        <div style="margin-top:14px;">
          <h4>📡 SNMP Polling Analysis</h4>
          <div class="summary-grid" style="margin-top:8px;">
            <div class="metric"><div class="val">{snmp_poll['estimated_poll_interval_s']}s</div><div class="label">Est. Poll Interval</div></div>
            <div class="metric"><div class="val">{snmp_poll['median_poll_interval_s']}s</div><div class="label">Median Interval</div></div>
            <div class="metric"><div class="val">{int(snmp_poll['estimated_requests_per_hour'])}</div><div class="label">Requests/Hour</div></div>
            <div class="metric"><div class="val" style="color:{reg_color}">{snmp_poll['poll_regularity']}</div><div class="label">Regularity (CV={snmp_poll['consistency_cv']})</div></div>
            <div class="metric"><div class="val">{snmp_poll['error_rate_pct']}%</div><div class="label">SNMP Error Rate</div></div>
            <div class="metric"><div class="val">{snmp_poll['unanswered_pct']}%</div><div class="label">Unanswered %</div></div>
          </div>
        </div>"""

    stats_section = f"""
    <div class="card">
      <div class="card-header">📈 Traffic Statistics &amp; Analytics</div>
      <div class="card-body">

        <!-- TX/RX Ratio -->
        <div class="two-col" style="margin-bottom:16px;">
          <div>
            <h4>Traffic Direction Split</h4>
            <div style="margin-top:8px;">
              <div style="margin:4px 0;display:flex;align-items:center;gap:6px;">
                <span style="width:70px;font-size:0.82em;">TX (sent)</span>
                <div style="flex:1;background:#ecf0f1;border-radius:3px;height:16px;">
                  <div style="background:#3498db;height:16px;width:{tr_ratio.get('tx_packets_pct',0)}%;border-radius:3px;"></div></div>
                <small style="width:100px">{tr_ratio.get('tx_packets_pct',0)}% &nbsp; {tr_ratio.get('tx_kb',0)} KB</small>
              </div>
              <div style="margin:4px 0;display:flex;align-items:center;gap:6px;">
                <span style="width:70px;font-size:0.82em;">RX (recv)</span>
                <div style="flex:1;background:#ecf0f1;border-radius:3px;height:16px;">
                  <div style="background:#27ae60;height:16px;width:{tr_ratio.get('rx_packets_pct',0)}%;border-radius:3px;"></div></div>
                <small style="width:100px">{tr_ratio.get('rx_packets_pct',0)}% &nbsp; {tr_ratio.get('rx_kb',0)} KB</small>
              </div>
            </div>
          </div>
          <div>
            <h4>Hourly Activity</h4>
            <div class="summary-grid" style="margin-top:8px;grid-template-columns:repeat(3,1fr);">
              <div class="metric" style="padding:8px 12px;"><div class="val">{hourly.get('avg_pkts_per_hour','—')}</div><div class="label">Avg pkts/hr</div></div>
              <div class="metric" style="padding:8px 12px;"><div class="val">{hourly.get('max_pkts_per_hour','—')}</div><div class="label">Peak pkts/hr</div></div>
              <div class="metric" style="padding:8px 12px;"><div class="val">{hourly.get('active_hours','—')}/{hourly.get('total_hours','—')}</div><div class="label">Active hours</div></div>
            </div>
            {'<p style="margin-top:8px;font-size:0.82em;color:#7f8c8d;">Peak at hour +' + str(hourly.get("peak_hour_offset","?")) + 'h offset from capture start</p>' if hourly else ''}
          </div>
        </div>

        <!-- IPI table -->
        {'<h4>Inter-Packet Interval (IPI) Statistics</h4><table><th>Protocol</th><th>Mean</th><th>Median</th><th>Std Dev</th><th>Jitter</th><th>Burstiness / Rate</th>' + ipi_rows + '</table>' if ipi_rows else ''}

        <!-- Packet size -->
        {'<div style="margin-top:16px;"><h4>Packet Size Distribution</h4><div class="two-col"><div>' + sz_bars + '</div><div><table><th>Metric</th><th>Value</th><tr><td>Min</td><td>' + str(pkt_sz.get("min_bytes","—")) + ' B</td></tr><tr><td>Max</td><td>' + str(pkt_sz.get("max_bytes","—")) + ' B</td></tr><tr><td>Mean</td><td>' + str(pkt_sz.get("mean_bytes","—")) + ' B</td></tr><tr><td>Median</td><td>' + str(pkt_sz.get("median_bytes","—")) + ' B</td></tr><tr><td>Std Dev</td><td>' + str(pkt_sz.get("std_bytes","—")) + ' B</td></tr><tr><td>P95</td><td>' + str(pkt_sz.get("p95_bytes","—")) + ' B</td></tr><tr><td>P99</td><td>' + str(pkt_sz.get("p99_bytes","—")) + ' B</td></tr></table></div></div></div>' if pkt_sz else ''}

        {snmp_poll_html}
      </div>
    </div>"""

    # ── Address Info card ──────────────────────────────────────────────────────
    addr_notes_html = "".join(f'<li>{n}</li>' for n in addr_info.get("notes", []))
    other_addrs_rows = "".join(
        f'<tr><td><code>{a["address"]}</code></td><td>{a["type"]}</td>'
        f'<td>{a["scope"]}</td><td>{a["packets"]}</td></tr>'
        for a in addr_info.get("other_addresses_same_host", [])
    )
    addr_section = f"""
    <div class="card">
      <div class="card-header">🏷️ IPv6 Address Classification</div>
      <div class="card-body">
        <div class="summary-grid">
          <div class="metric"><div class="val" style="font-size:1em;">{addr_info.get("type","?")}</div><div class="label">Address Type</div></div>
          <div class="metric"><div class="val" style="font-size:1em;">{addr_info.get("scope","?")}</div><div class="label">Scope</div></div>
          <div class="metric"><div class="val" style="font-size:0.85em;">{addr_info.get("prefix","?")}</div><div class="label">Network Prefix</div></div>
          <div class="metric {'style="border-color:#e74c3c"' if addr_info.get('is_eui64') else ''}">
            <div class="val">{'Yes' if addr_info.get('is_eui64') else 'No'}</div>
            <div class="label">EUI-64 Interface ID</div>
          </div>
        </div>
        <div style="margin-top:14px;">
          {'<p><strong>Embedded MAC (from EUI-64):</strong> <code>' + addr_info.get("embedded_mac","") + '</code></p>' if addr_info.get("embedded_mac") else ''}
          {'<p><strong>Observed Ethernet MAC:</strong> <code>' + addr_info.get("observed_mac","") + '</code></p>' if addr_info.get("observed_mac") else ''}
          {'<p><strong>Solicited-Node Multicast:</strong> <code>' + addr_info.get("solicited_node_multicast","") + '</code> &nbsp;(' + str(addr_info.get("solicited_node_ns_count",0)) + ' NS observed)</p>' if addr_info.get("solicited_node_multicast") else ''}
          {'<p><strong>PTR Reverse Name:</strong> <code>' + dns6.get("ptr_reverse_name","") + '</code></p>' if dns6.get("ptr_reverse_name") else ''}
        </div>
        {'<div style="margin-top:12px;"><h4>Addressing Notes</h4><ul style="font-size:0.85em;padding-left:18px;line-height:1.8;">' + addr_notes_html + '</ul></div>' if addr_notes_html else ''}
        {'<div style="margin-top:14px;"><h4>Other Addresses on Same Host (MAC: ' + addr_info.get("observed_mac","?") + ')</h4><table><th>Address</th><th>Type</th><th>Scope</th><th>Packets</th>' + other_addrs_rows + '</table></div>' if other_addrs_rows else ''}
      </div>
    </div>"""

    # ── NDP deep dive card ─────────────────────────────────────────────────────
    ndp_ra_rows = ""
    for ra in ndp.get("router_advertisements", []):
        flags = f"M={ra.get('managed_flag_M','?')} O={ra.get('other_flag_O','?')}"
        pfx = f"{ra.get('prefix','')}/{ra.get('prefix_length','')}" if ra.get('prefix') else "—"
        ndp_ra_rows += (f'<tr><td>{ra.get("frame","")}</td><td>{ra.get("time","")}</td>'
                        f'<td>{ra.get("router","")}</td><td>{pfx}</td>'
                        f'<td>{ra.get("router_lifetime_s","")}s</td>'
                        f'<td>{flags}</td></tr>')
    ndp_dad_rows = ""
    for d in ndp.get("dad_conflicts", []):
        ndp_dad_rows += (f'<tr><td>{d.get("frame","")}</td><td>{d.get("time","")}</td>'
                         f'<td>{d.get("conflicting_src","")}</td><td>{d.get("conflicting_mac","")}</td></tr>')
    ndp_sec_notes = "".join(
        f'<li style="color:{"#c0392b" if "HIGH" in n else "#e67e22" if "MEDIUM" in n else "#2980b9"};">{n}</li>'
        for n in ndp.get("ndp_security_notes", [])
    )

    rtt_info = ""
    if ndp.get("avg_na_rtt_ms") is not None:
        rtt_info = (f'avg={ndp["avg_na_rtt_ms"]} ms &nbsp;|&nbsp; '
                    f'min={ndp.get("min_na_rtt_ms","?")} ms &nbsp;|&nbsp; '
                    f'max={ndp.get("max_na_rtt_ms","?")} ms')

    ndp_section = f"""
    <div class="card">
      <div class="card-header">🔍 Neighbor Discovery Protocol (NDP) — Deep Analysis</div>
      <div class="card-body">
        <div class="summary-grid">
          <div class="metric"><div class="val">{ndp.get('ns_sent',0)}</div><div class="label">NS Sent</div></div>
          <div class="metric"><div class="val">{ndp.get('ns_received',0)}</div><div class="label">NS Received</div></div>
          <div class="metric"><div class="val">{ndp.get('na_sent',0)}</div><div class="label">NA Sent</div></div>
          <div class="metric"><div class="val">{ndp.get('na_received',0)}</div><div class="label">NA Received</div></div>
          <div class="metric"><div class="val">{ndp.get('rs_sent',0)}</div><div class="label">RS Sent</div></div>
          <div class="metric"><div class="val">{ndp.get('ra_received',0)}</div><div class="label">RA Received</div></div>
          <div class="metric {'style="border-color:#e74c3c"' if ndp.get('dad_attempts',0) > 0 else ''}">
            <div class="val">{ndp.get('dad_attempts',0)}</div><div class="label">DAD Probes Seen</div>
          </div>
          <div class="metric {'style="border-color:#e74c3c"' if ndp.get('unsolicited_na_count',0) > 0 else ''}">
            <div class="val">{ndp.get('unsolicited_na_count',0)}</div><div class="label">Unsolicited NAs</div>
          </div>
        </div>
        {f'<p style="margin-top:12px;"><strong>NS→NA RTT:</strong> {rtt_info}</p>' if rtt_info else ''}
        {f'<div style="margin-top:12px;"><h4>Router Advertisements</h4><table><th>Frame</th><th>Time</th><th>Router</th><th>Prefix</th><th>Lifetime</th><th>Flags</th>' + ndp_ra_rows + '</table></div>' if ndp_ra_rows else '<p style="margin-top:12px;color:#7f8c8d;">No Router Advertisements captured.</p>'}
        {f'<div style="margin-top:12px;"><h4 style="color:#c0392b;">⚠ DAD Conflicts</h4><table><th>Frame</th><th>Time</th><th>Conflicting Src</th><th>MAC</th>' + ndp_dad_rows + '</table></div>' if ndp_dad_rows else ''}
        {f'<div style="margin-top:12px;"><h4>NDP Security Observations</h4><ul style="font-size:0.85em;padding-left:18px;line-height:1.8;">' + ndp_sec_notes + '</ul></div>' if ndp_sec_notes else ''}
      </div>
    </div>"""

    # ── DNS6 card ──────────────────────────────────────────────────────────────
    dns_section = ""
    if dns6.get("dns_detail") or dns6.get("aaaa_queries_sent", 0) > 0 or dns6.get("nxdomain_count", 0) > 0:
        dns_detail_rows = ""
        for d in dns6.get("dns_detail", [])[:20]:
            dns_detail_rows += (f'<tr><td>{d.get("frame","")}</td><td>{d.get("time","")}</td>'
                                f'<td>{d.get("direction","")}</td><td>{d.get("name","")}</td>'
                                f'<td>{d.get("type","")}</td><td>{d.get("rcode","")}</td></tr>')
        ptr_rows = ""
        for p in dns6.get("ptr_queries", [])[:5]:
            ptr_rows += f'<tr><td>{p.get("frame","")}</td><td>{p.get("name","")}</td><td>{p.get("dst","")}</td></tr>'

        dns_section = f"""
        <div class="card">
          <div class="card-header">🔎 DNS / IPv6 Resolution Analysis</div>
          <div class="card-body">
            <div class="summary-grid">
              <div class="metric"><div class="val">{dns6.get('aaaa_queries_sent',0)}</div><div class="label">AAAA Queries Sent</div></div>
              <div class="metric"><div class="val">{dns6.get('aaaa_responses_received',0)}</div><div class="label">AAAA Responses</div></div>
              <div class="metric {'style="border-color:#e74c3c"' if dns6.get('nxdomain_count',0) > 5 else ''}">
                <div class="val">{dns6.get('nxdomain_count',0)}</div><div class="label">NXDOMAIN</div>
              </div>
              <div class="metric"><div class="val">{'Yes' if dns6.get('ptr_was_queried') else 'No'}</div><div class="label">PTR Queried</div></div>
            </div>
            <div style="margin-top:12px;">
              <p><strong>PTR Reverse Name:</strong> <code>{dns6.get('ptr_reverse_name','—')}</code></p>
              {'<p style="margin-top:6px;"><strong>Resolved Hostnames:</strong> ' + ', '.join(f'<code>{h}</code>' for h in dns6.get('hostnames_resolved',[])) + '</p>' if dns6.get('hostnames_resolved') else ''}
              {'<p style="margin-top:6px;"><strong>DNS Servers Used:</strong> ' + ', '.join(f'<code>{s}</code>' for s in dns6.get('dns_servers',[])) + '</p>' if dns6.get('dns_servers') else ''}
            </div>
            {f'<div style="margin-top:12px;"><h4>DNS Traffic Detail</h4><table><th>Frame</th><th>Time</th><th>Dir</th><th>Name</th><th>Type</th><th>Rcode</th>' + dns_detail_rows + '</table></div>' if dns_detail_rows else ''}
            {f'<div style="margin-top:12px;"><h4>PTR Queries</h4><table><th>Frame</th><th>Name</th><th>DNS Server</th>' + ptr_rows + '</table></div>' if ptr_rows else ''}
          </div>
        </div>"""

    # ── Extension Headers card ─────────────────────────────────────────────────
    ext_section = ""
    if any(ext_hdrs.get(k, 0) > 0 for k in
           ["hop_by_hop_count", "routing_header_count", "fragment_header_count",
            "destination_options_count"]):
        frag_rows = ""
        for f_ in ext_hdrs.get("fragmented_packets", [])[:10]:
            frag_rows += (f'<tr><td>{f_.get("frame","")}</td><td>{f_.get("time","")}</td>'
                          f'<td>{f_.get("src","")}</td><td>{f_.get("frag_id","")}</td>'
                          f'<td>{f_.get("offset","")}</td><td>{f_.get("more_frags","")}</td></tr>')
        ext_sec_notes = "".join(
            f'<li style="color:{"#c0392b" if "HIGH" in n else "#e67e22" if "MEDIUM" in n else "#2980b9"};">{n}</li>'
            for n in ext_hdrs.get("security_notes", [])
        )
        fl_items = "".join(
            f'<li><code>{fl}</code>: {cnt} packets</li>'
            for fl, cnt in list(ext_hdrs.get("flow_labels", {}).items())[:8]
        )
        ext_section = f"""
        <div class="card">
          <div class="card-header">📦 IPv6 Extension Headers</div>
          <div class="card-body">
            <div class="summary-grid">
              <div class="metric"><div class="val">{ext_hdrs.get('hop_by_hop_count',0)}</div><div class="label">Hop-by-Hop</div></div>
              <div class="metric {'style="border-color:#e74c3c"' if ext_hdrs.get('routing_type0_count',0) > 0 else ''}">
                <div class="val">{ext_hdrs.get('routing_header_count',0)}</div><div class="label">Routing Headers</div>
              </div>
              <div class="metric"><div class="val">{ext_hdrs.get('fragment_header_count',0)}</div><div class="label">Fragment Headers</div></div>
              <div class="metric"><div class="val">{ext_hdrs.get('destination_options_count',0)}</div><div class="label">Dest Options</div></div>
              <div class="metric"><div class="val">{ext_hdrs.get('routing_type0_count',0)}</div><div class="label">Routing Type 0 ⚠</div></div>
              <div class="metric"><div class="val">{ext_hdrs.get('unique_flow_labels',0)}</div><div class="label">Unique Flow Labels</div></div>
            </div>
            {f'<div style="margin-top:12px;"><h4>Security Notes</h4><ul style="font-size:0.85em;padding-left:18px;line-height:1.8;">' + ext_sec_notes + '</ul></div>' if ext_sec_notes else ''}
            {f'<div style="margin-top:12px;"><h4>Fragment Detail</h4><table><th>Frame</th><th>Time</th><th>Src</th><th>Frag ID</th><th>Offset</th><th>More</th>' + frag_rows + '</table></div>' if frag_rows else ''}
            {f'<div style="margin-top:12px;"><h4>Flow Labels Used</h4><ul style="font-size:0.85em;padding-left:18px;">' + fl_items + '</ul></div>' if fl_items else ''}
          </div>
        </div>"""

    # ── SNMP section ───────────────────────────────────────────────────────────
    snmp = udp.get("snmp_analysis", {})
    snmp_section = ""
    if snmp.get("total_snmp_packets", 0) > 0:
        err_breakdown = "".join(
            f'<tr><td>{err}</td><td>{count}</td></tr>'
            for err, count in snmp.get("error_breakdown", {}).items()
        )
        snmp_section = f"""
        <div class="card">
          <div class="card-header">📡 SNMP Analysis</div>
          <div class="card-body">
            <div class="summary-grid">
              <div class="metric"><div class="val">{snmp['total_snmp_packets']}</div><div class="label">Total SNMP Packets</div></div>
              <div class="metric" style="border-color:#e74c3c"><div class="val">{snmp['snmp_errors']}</div><div class="label">SNMP Errors</div></div>
              <div class="metric"><div class="val">{snmp['error_rate_pct']}%</div><div class="label">Error Rate</div></div>
              <div class="metric"><div class="val">{snmp.get('unanswered_requests', 0)}</div><div class="label">Unanswered Requests</div></div>
              <div class="metric"><div class="val">{snmp.get('requests_to_host',0)}</div><div class="label">Requests Received</div></div>
              <div class="metric"><div class="val">{snmp.get('responses_from_host',0)}</div><div class="label">Responses Sent</div></div>
            </div>
            <div style="margin-top:16px;">
              <h4>SNMP Versions</h4>
              <p>{'  |  '.join(f'<strong>{k}</strong>: {v} pkts' for k, v in snmp.get('versions', {}).items())}</p>
              <h4 style="margin-top:12px;">Community Strings</h4>
              <p>{'  |  '.join(f'<code>{k}</code>: {v} pkts' for k, v in snmp.get('communities', {}).items())}</p>
              <h4 style="margin-top:12px;">SNMP Peers</h4>
              <p>{', '.join(f'<code>{p}</code>' for p in snmp.get('snmp_peers', []))}</p>
            </div>
            {'<div style="margin-top:16px;"><h4>Error Breakdown</h4><table><th>Error Type</th><th>Count</th>' + err_breakdown + '</table></div>' if err_breakdown else ''}
          </div>
        </div>"""

    # ── ICMPv6 section ─────────────────────────────────────────────────────────
    icmpv6_section = ""
    if icmpv6_data.get("total_icmpv6_packets", 0) > 0:
        type_rows = "".join(
            f'<tr><td>{t}</td><td>{c}</td></tr>'
            for t, c in icmpv6_data.get("type_distribution", {}).items()
        )
        icmpv6_section = f"""
        <div class="card">
          <div class="card-header">📶 ICMPv6 Summary</div>
          <div class="card-body">
            <div class="summary-grid">
              <div class="metric"><div class="val">{icmpv6_data['total_icmpv6_packets']}</div><div class="label">Total ICMPv6</div></div>
              <div class="metric"><div class="val">{icmpv6_data.get('neighbor_solicitations_received', 0)}</div><div class="label">NS Received</div></div>
              <div class="metric"><div class="val">{icmpv6_data.get('neighbor_advertisements_sent', 0)}</div><div class="label">NA Sent</div></div>
              <div class="metric"><div class="val">{icmpv6_data.get('slow_na_responses', 0)}</div><div class="label">Slow NA (>1s)</div></div>
            </div>
            <div style="margin-top:16px;">
              <h4>ICMPv6 Type Distribution</h4>
              <table><th>Type</th><th>Count</th>{type_rows}</table>
            </div>
          </div>
        </div>"""

    # ── Issues section ─────────────────────────────────────────────────────────
    issues_html = ""
    for issue in sorted(issues, key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["severity"], 3)):
        sev = issue["severity"].upper()
        color = sev_colors.get(sev, "#555")
        issues_html += f"""
        <div class="finding {issue['severity']}">
          <h3><span style="background:{color};color:#fff;padding:2px 8px;border-radius:10px;font-size:0.75em;margin-right:8px;">{sev}</span> {issue['title']}</h3>
          <p style="margin-top:6px;"><strong>Category:</strong> {issue['category']}</p>
          <p>{issue['detail']}</p>
          <p style="margin-top:6px;color:#2c3e50;"><strong>Remediation:</strong> {issue.get('remediation','')}</p>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IPv6 Analysis – {ipv6}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f9;color:#2c3e50;font-size:14px}}
  header{{background:linear-gradient(135deg,#1a252f,#2c3e50);color:#fff;padding:28px 40px}}
  header h1{{font-size:1.5em;font-weight:700}}
  header p{{color:#aab;margin-top:6px;font-size:0.9em}}
  .container{{max-width:1200px;margin:24px auto;padding:0 24px}}
  .card{{background:#fff;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.08);margin-bottom:24px;overflow:hidden}}
  .card-header{{padding:14px 20px;font-weight:600;font-size:1em;border-bottom:1px solid #eee;background:#fafafa}}
  .card-body{{padding:16px 20px}}
  .summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}
  .metric{{background:#f8f9fb;border-radius:8px;padding:12px 16px;border-left:4px solid #3498db}}
  .metric .val{{font-size:1.5em;font-weight:700;color:#2c3e50}}
  .metric .label{{font-size:0.75em;color:#7f8c8d;margin-top:4px}}
  table{{border-collapse:collapse;width:100%;font-size:0.84em;margin-top:8px}}
  th{{background:#2c3e50;color:#fff;padding:8px 12px;text-align:left}}
  td{{padding:6px 12px;border-bottom:1px solid #eef}}
  tr:hover td{{background:#f5f9ff}}
  .finding{{border-left:4px solid;padding:12px 16px;margin-bottom:12px;border-radius:0 6px 6px 0;background:#fafafa}}
  .finding.high{{border-color:#e74c3c;background:#fdf2f2}}
  .finding.medium{{border-color:#f39c12;background:#fef9f0}}
  .finding.low{{border-color:#3498db;background:#eaf4fb}}
  .finding h3{{font-size:0.95em;margin-bottom:4px}}
  .finding p{{font-size:0.85em;color:#555;line-height:1.5}}
  code{{background:#e8e8e8;padding:2px 6px;border-radius:3px;font-size:0.88em;word-break:break-all}}
  h4{{font-size:0.9em;color:#34495e;margin-bottom:6px;margin-top:4px}}
  .two-col{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
  @media(max-width:700px){{.two-col{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<header>
  <h1>IPv6 Traffic Analysis Report</h1>
  <p>Target: <strong>{ipv6}</strong> &nbsp;|&nbsp; File: {pcap_name}
     &nbsp;|&nbsp; Capture start: {overview.get('capture_start','—')}
     &nbsp;|&nbsp; Generated: {now}</p>
</header>
<div class="container">

  <!-- ═══ Overall Status ═══ -->
  <div class="card">
    <div class="card-header" style="background:{sev_colors.get(overall_sev,'#555')};color:#fff;">
      Overall Assessment: {overall_sev} &nbsp;—&nbsp; {len(issues)} issue(s) found
    </div>
    <div class="card-body">
      <div class="summary-grid">
        <div class="metric"><div class="val">{overview['total_packets']:,}</div><div class="label">Total Packets</div></div>
        <div class="metric"><div class="val">{round(overview.get('total_bytes',0)/1024,1)} KB</div><div class="label">Total Data</div></div>
        <div class="metric"><div class="val">{overview.get('tx_packets',0):,}</div><div class="label">TX Packets (sent)</div></div>
        <div class="metric"><div class="val">{overview.get('rx_packets',0):,}</div><div class="label">RX Packets (recv)</div></div>
        <div class="metric"><div class="val">{round(overview.get('duration_seconds',0)/3600,1)}h</div><div class="label">Duration</div></div>
        <div class="metric"><div class="val">{overview.get('avg_packets_per_sec',0)}</div><div class="label">Pkts/sec avg</div></div>
        <div class="metric"><div class="val">{overview.get('avg_bytes_per_packet',0)}</div><div class="label">Bytes/pkt avg</div></div>
      </div>
    </div>
  </div>

  <!-- ═══ Issues ═══ -->
  <div class="card">
    <div class="card-header">⚠️ Issues &amp; Findings ({len(issues)})</div>
    <div class="card-body">
      {issues_html if issues_html else '<p style="color:#27ae60;padding:8px 0;">No significant issues detected.</p>'}
    </div>
  </div>

  <!-- ═══ Statistics & Analytics ═══ -->
  {stats_section}

  <!-- ═══ Address Classification ═══ -->
  {addr_section}

  <!-- ═══ Protocol & Timeline ═══ -->
  <div class="card">
    <div class="card-header">📊 Protocol Distribution &amp; Traffic Timeline</div>
    <div class="card-body">
      <div class="two-col">
        <div>
          <h4>Protocol Breakdown (top layer)</h4>
          {proto_bars}
        </div>
        <div>
          <h4>Traffic Over Time (per-hour buckets)</h4>
          {timeline_svg if timeline_svg else '<p style="color:#aaa;">No timeline data.</p>'}
          <p style="font-size:0.8em;color:#aaa;margin-top:4px;">X-axis: hours offset from capture start</p>
        </div>
      </div>
    </div>
  </div>

  <!-- ═══ Communication Peers ═══ -->
  <div class="card">
    <div class="card-header">🌐 Communication Peers (Top 10)</div>
    <div class="card-body">
      <table>
        <th>IPv6 Peer Address</th><th>Packets</th><th>TX (sent to)</th>
        <th>RX (recv from)</th><th>Volume</th>
        {peers_html}
      </table>
    </div>
  </div>

  <!-- ═══ NDP Deep Analysis ═══ -->
  {ndp_section}

  <!-- ═══ DNS / Resolution ═══ -->
  {dns_section}

  <!-- ═══ Extension Headers ═══ -->
  {ext_section}

  <!-- ═══ TCP Analysis ═══ -->
  {'<div class="card"><div class="card-header">🔌 TCP Analysis</div><div class="card-body">' + f"""
    <div class="summary-grid">
      <div class="metric"><div class="val">{tcp['total_tcp_packets']}</div><div class="label">TCP Packets</div></div>
      <div class="metric"><div class="val">{tcp.get('connections_to_host',0)}</div><div class="label">Inbound Conns</div></div>
      <div class="metric"><div class="val">{tcp.get('connections_from_host',0)}</div><div class="label">Outbound Conns</div></div>
      <div class="metric"><div class="val">{tcp.get('syn_ack_sent',0)}</div><div class="label">SYN-ACK Sent</div></div>
      <div class="metric" style="border-color:#e74c3c"><div class="val">{tcp.get('rst_sent',0)+tcp.get('rst_received',0)}</div><div class="label">RST Total</div></div>
      <div class="metric"><div class="val">{tcp.get('retransmissions',0)}</div><div class="label">Retransmissions</div></div>
      <div class="metric"><div class="val">{tcp.get('duplicate_acks',0)}</div><div class="label">Dup ACKs</div></div>
      <div class="metric"><div class="val">{tcp.get('out_of_order',0)}</div><div class="label">Out-of-Order</div></div>
      <div class="metric"><div class="val">{tcp.get('zero_window',0)}</div><div class="label">Zero Window</div></div>
      <div class="metric"><div class="val">{tcp.get('port_probes_detected',0)}</div><div class="label">Port Probes</div></div>
    </div>
    <div style="margin-top:16px;"><h4>Destination Ports</h4>
    <table><th>Port</th><th>Service</th><th>Packets</th>{tcp_port_rows}</table></div>
    {'<div style="margin-top:16px;"><h4>Inbound Connections (SYN)</h4><table><th>Frame</th><th>Time</th><th>Peer</th><th>Peer Port</th><th>Local Port</th>' + tcp_conn_rows + '</table></div>' if tcp_conn_rows else ''}
    {'<div style="margin-top:16px;"><h4>RST Packets</h4><table><th>Frame</th><th>Time</th><th>Source</th><th>Destination</th>' + rst_rows + '</table></div>' if rst_rows else ''}
  """ + '</div></div>' if tcp.get('total_tcp_packets',0) > 0 else ''}

  <!-- ═══ UDP Analysis ═══ -->
  {'<div class="card"><div class="card-header">📦 UDP Analysis</div><div class="card-body">' + f"""
    <div class="summary-grid">
      <div class="metric"><div class="val">{udp['total_udp_packets']}</div><div class="label">UDP Packets</div></div>
    </div>
    <div style="margin-top:16px;"><h4>Top UDP Flows</h4>
    <table><th>Source</th><th>SPort</th><th>Dest</th><th>DPort</th><th>Frames</th><th>Volume</th>{udp_flow_rows}</table></div>
  """ + '</div></div>' if udp.get('total_udp_packets',0) > 0 else ''}

  <!-- ═══ SNMP ═══ -->
  {snmp_section}

  <!-- ═══ ICMPv6 Summary ═══ -->
  {icmpv6_section}

</div>
</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)
    logger.info(f"HTML report saved to {output_path}")


# ─── Main ────────────────────────────────────────────────────────────────────

def run(pcap_file: str, ipv6_addr: str, output_dir: str = 'results') -> dict:
    """Callable entry point — usable from workers without subprocess."""
    ipv6_addr = ipv6_addr.replace("ipv6.addr==", "").replace("ipv6.addr == ", "").strip()
    addr_slug = ipv6_addr.replace(":", "_")
    output_json = str(Path(output_dir) / f"ipv6_{addr_slug}.json")
    output_html = str(Path(output_dir) / f"ipv6_{addr_slug}_report.html")

    logger.info(f"Analyzing IPv6 traffic for {ipv6_addr} in {pcap_file}")

    overview = analyse_overview(pcap_file, ipv6_addr)
    if overview["total_packets"] == 0:
        logger.warning("No packets found for this IPv6 address.")
        return {'error': 'No packets found', 'json_path': None, 'html_path': None}

    logger.info(f"Found {overview['total_packets']} packets — running all analysis modules...")

    addr_info = analyse_address_info(pcap_file, ipv6_addr)
    logger.info("Address classification done")

    tcp = analyse_tcp(pcap_file, ipv6_addr)
    logger.info("TCP analysis done")

    udp = analyse_udp(pcap_file, ipv6_addr)
    logger.info("UDP/SNMP analysis done")

    icmpv6_data = analyse_icmpv6(pcap_file, ipv6_addr)
    logger.info("ICMPv6 analysis done")

    ndp = analyse_neighbor_discovery(pcap_file, ipv6_addr)
    logger.info("NDP deep analysis done")

    dns6 = analyse_dns6(pcap_file, ipv6_addr)
    logger.info("DNS6 analysis done")

    ext_hdrs = analyse_extension_headers(pcap_file, ipv6_addr)
    logger.info("Extension headers analysis done")

    issues = detect_issues(overview, tcp, udp, icmpv6_data, ndp, dns6, ext_hdrs)

    statistics = analyse_statistics(pcap_file, ipv6_addr, overview, udp)
    logger.info("Statistical analysis done")

    results = {
        "target_ipv6": ipv6_addr,
        "pcap_file": str(pcap_file),
        "analysis_timestamp": datetime.now().isoformat(),
        "overview": overview,
        "address_info": addr_info,
        "statistics": statistics,
        "tcp": tcp,
        "udp": udp,
        "icmpv6": icmpv6_data,
        "ndp": ndp,
        "dns6": dns6,
        "extension_headers": ext_hdrs,
        "issues": issues,
    }

    Path(output_json).parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, "w") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"JSON results saved to {output_json}")

    generate_html_report(pcap_file, ipv6_addr, results, output_html)

    return {'json_path': output_json, 'html_path': output_html, 'results': results}


def main():
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else None
    ipv6_addr = sys.argv[2] if len(sys.argv) > 2 else None
    if not pcap_file or not ipv6_addr:
        print("Usage: python scripts/run_ipv6_analysis.py <pcap_file> <ipv6_address>")
        print("  Example: python scripts/run_ipv6_analysis.py capture.pcapng 2408:8a04:e001:0:faed:fcff:fefe:10c1")
        sys.exit(1)
    out = run(pcap_file, ipv6_addr)
    results = out.get('results', {})
    overview = results.get('overview', {})
    output_json = out.get('json_path', '')
    output_html = out.get('html_path', '')
    if not results:
        sys.exit(0)

    addr_info = results.get('address_info', {})
    tcp = results.get('tcp', {})
    udp = results.get('udp', {})
    icmpv6_data = results.get('icmpv6', {})
    ndp = results.get('ndp', {})
    dns6 = results.get('dns6', {})
    ext_hdrs = results.get('extension_headers', {})
    issues = results.get('issues', [])

    print(f"\n{'='*64}")
    print(f"  IPv6 ANALYSIS SUMMARY")
    print(f"{'='*64}")
    print(f"  Target:    {ipv6_addr}")
    print(f"  Type:      {addr_info.get('type','?')}  |  Scope: {addr_info.get('scope','?')}")
    print(f"  Prefix:    {addr_info.get('prefix','?')}")
    if addr_info.get('observed_mac'):
        print(f"  MAC:       {addr_info['observed_mac']}"
              + (" (EUI-64 derived)" if addr_info.get('is_eui64') else " (privacy ext / static)"))
    if addr_info.get('other_addresses_same_host'):
        print(f"  Other addrs on same host: "
              + ", ".join(a['address'] for a in addr_info['other_addresses_same_host'][:3]))
    print(f"{'─'*64}")
    print(f"  Packets:   {overview['total_packets']:,}  |  "
          f"TX: {overview.get('tx_packets',0):,}  RX: {overview.get('rx_packets',0):,}")
    print(f"  Duration:  {round(overview.get('duration_seconds',0)/3600,1)} hours  |  "
          f"Start: {overview.get('capture_start','?')}")
    print(f"  Data:      {round(overview.get('total_bytes',0)/1024,1)} KB  |  "
          f"Avg {overview.get('avg_bytes_per_packet',0)} B/pkt")
    print(f"{'─'*64}")
    print(f"  Protocol Breakdown:")
    for proto, count in list(overview.get("protocol_distribution", {}).items())[:6]:
        print(f"    {proto:15s} {count:>6,} packets")
    print(f"{'─'*64}")
    print(f"  TCP:       {tcp.get('total_tcp_packets',0)} pkts | "
          f"{tcp.get('connections_to_host',0)} inbound | "
          f"{tcp.get('rst_sent',0)+tcp.get('rst_received',0)} RSTs | "
          f"{tcp.get('retransmissions',0)} retrans")
    print(f"  UDP:       {udp.get('total_udp_packets',0)} pkts")
    snmp_info = udp.get("snmp_analysis", {})
    if snmp_info:
        print(f"  SNMP:      {snmp_info.get('total_snmp_packets',0)} pkts | "
              f"{snmp_info.get('snmp_errors',0)} errors ({snmp_info.get('error_rate_pct',0)}%) | "
              f"{snmp_info.get('unanswered_requests',0)} unanswered")
    print(f"  ICMPv6:    {icmpv6_data.get('total_icmpv6_packets',0)} pkts")
    print(f"  NDP:       NS sent={ndp.get('ns_sent',0)} recv={ndp.get('ns_received',0)} | "
          f"NA sent={ndp.get('na_sent',0)} recv={ndp.get('na_received',0)} | "
          f"DAD probes={ndp.get('dad_attempts',0)} | "
          f"Unsolicited NAs={ndp.get('unsolicited_na_count',0)}")
    if ndp.get('avg_na_rtt_ms'):
        print(f"             NS→NA RTT: avg={ndp['avg_na_rtt_ms']}ms "
              f"min={ndp.get('min_na_rtt_ms','?')}ms max={ndp.get('max_na_rtt_ms','?')}ms")
    print(f"  DNS6:      AAAA queries={dns6.get('aaaa_queries_sent',0)} | "
          f"NXDOMAIN={dns6.get('nxdomain_count',0)} | "
          f"PTR queried={'Yes' if dns6.get('ptr_was_queried') else 'No'}")
    if dns6.get('ptr_reverse_name'):
        print(f"             PTR name: {dns6['ptr_reverse_name']}")
    print(f"  Ext Hdrs:  HbH={ext_hdrs.get('hop_by_hop_count',0)} | "
          f"Routing={ext_hdrs.get('routing_header_count',0)} "
          f"(Type0={ext_hdrs.get('routing_type0_count',0)}) | "
          f"Fragments={ext_hdrs.get('fragment_header_count',0)}")
    print(f"{'─'*64}")

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

    print(f"{'='*64}")
    print(f"  Reports: {output_json}")
    print(f"           {output_html}")
    print(f"{'='*64}")


if __name__ == "__main__":
    main()
