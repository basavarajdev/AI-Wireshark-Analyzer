"""
WLAN RF & Medium-Access Monitor
================================
Detects RF-layer and MAC-level performance problems independently of the
authentication / connection-event analysis in WLANAnalyzer.

Detections
----------
- High data-frame retry rate        (interference / congestion)
- Scan-only / excessive scan cycles (power-save wake-to-scan)
- Control-frame anomalies           (RTS/CTS ratio, hidden-node indicator,
                                     PS-Poll storms, Block Ack failures,
                                     NAV/Duration abuse)
- Power-save anomalies              (null-frame storms, excessive PS transitions)
- Connection delays                 (multi-band scan overhead, passive scan
                                     periods, scan cycles, channel-switch overhead)

Usage
-----
    from src.protocols.wlan_rf_monitor import WLANRFMonitor

    monitor = WLANRFMonitor(wlan_config)
    findings = monitor.run_all(df)          # run all checks, returns {key: result}

    # Or run individual checks:
    retry_result = monitor.detect_high_retry(df)
    delay_result = monitor.detect_connection_delays(df)
"""

import pandas as pd
from typing import Dict, List, Any

# Data-frame subtype set (IEEE 802.11 type=2 subtypes)
DATA_SUBTYPES = {'0x0020', '0x0021', '0x0022', '0x0024', '0x0028', '0x002c'}


class WLANRFMonitor:
    """RF and medium-access performance monitor for 802.11 traffic DataFrames.

    Separates RF / MAC-layer performance checks from the authentication and
    connection-event logic in WLANAnalyzer, so the two suites can be run,
    extended, or disabled independently.

    Args:
        wlan_config: ``protocols.wlan`` section from ``config/default.yaml``.
                     Pass an empty dict or omit to use built-in defaults.
    """

    def __init__(self, wlan_config: Dict = None):
        self._cfg = wlan_config or {}

    # ------------------------------------------------------------------
    #  Convenience: run all checks
    # ------------------------------------------------------------------

    def run_all(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Run every RF/MAC check and return a findings dict.

        Returns:
            Dict keyed by threat name containing only detections that fired
            (``detected == True``).
        """
        results: Dict[str, Any] = {}
        checks = [
            ('high_retry_rate',      self.detect_high_retry),
            ('scan_failures',        self.detect_scan_failures),
            ('control_frame_issues', self.detect_control_frame_issues),
            ('power_save_issues',    self.detect_power_save_issues),
            ('connection_delays',    self.detect_connection_delays),
        ]
        for key, detector in checks:
            finding = detector(df)
            if finding.get('detected'):
                results[key] = finding
        return results

    # ------------------------------------------------------------------
    #  Retry Rate
    # ------------------------------------------------------------------

    def detect_high_retry(self, df: pd.DataFrame) -> Dict:
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
        threshold = self._cfg.get('max_retry_rate', 0.15)

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


    # ------------------------------------------------------------------
    #  Scan Behaviour
    # ------------------------------------------------------------------

    def detect_scan_failures(self, df: pd.DataFrame) -> Dict:
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
        threshold = self._cfg.get('scan_failure_device_threshold', 1)

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
    #  Control-Frame Anomalies  (RTS/CTS, hidden node, NAV, Block Ack)
    # ------------------------------------------------------------------

    def detect_control_frame_issues(self, df: pd.DataFrame) -> Dict:
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
    #  Power-Save Anomalies
    # ------------------------------------------------------------------

    def detect_power_save_issues(self, df: pd.DataFrame) -> Dict:
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
    #  Connection Delays
    # ------------------------------------------------------------------

    def detect_connection_delays(self, df: pd.DataFrame) -> Dict:
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


