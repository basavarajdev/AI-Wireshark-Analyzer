"""
HTML Report Generator for Network Analysis Results
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple
import base64
from io import BytesIO

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import seaborn as sns
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

from loguru import logger


# Remediation guidance keyed by threat name
REMEDIATION_GUIDE = {
    'syn_flood': {
        'description': 'SYN flood is a denial-of-service attack where an attacker sends a rapid succession of SYN requests without completing the TCP handshake, exhausting server resources.',
        'impact': 'Server connection table exhaustion, service unavailability, and potential cascading failures.',
        'remediation': [
            'Enable SYN cookies on the server (sysctl -w net.ipv4.tcp_syncookies=1)',
            'Reduce SYN-RECEIVED timeout (sysctl -w net.ipv4.tcp_synack_retries=2)',
            'Deploy rate-limiting on the firewall for SYN packets per source IP',
            'Consider a DDoS mitigation service or hardware-based SYN proxy',
        ],
    },
    'rst_storm': {
        'description': 'A large volume of TCP RST packets, which may indicate connection teardown issues, spoofed resets, or an active attack disrupting existing connections.',
        'impact': 'Legitimate connections may be reset unexpectedly, causing data loss and service interruptions.',
        'remediation': [
            'Investigate the top source IPs sending RST packets',
            'Check for misconfigured firewalls or NAT devices dropping idle connections',
            'Enable TCP RST rate-limiting at the network boundary',
        ],
    },
    'port_scanning': {
        'description': 'One or more hosts are probing a large number of destination ports, a common reconnaissance technique before launching targeted attacks.',
        'impact': 'Reveals open services and potential attack surface to the attacker.',
        'remediation': [
            'Block or rate-limit the scanner IPs at the firewall',
            'Reduce the attack surface by closing unnecessary ports',
            'Deploy an IDS/IPS to detect and auto-block scan activity',
            'Enable port-scan detection rules in firewall/NIDS',
        ],
    },
    'excessive_retransmissions': {
        'description': 'A high percentage of TCP segments are being retransmitted, indicating packet loss, network congestion, or an unreliable link.',
        'impact': 'Degraded application performance, increased latency, and poor user experience.',
        'remediation': [
            'Check for link-layer errors (CRC, interface drops) on switches and routers',
            'Verify MTU settings along the path (check for black-hole fragmentation)',
            'Investigate congestion on intermediate links; consider QoS policies',
            'Review TCP window scaling and buffer sizes on affected endpoints',
        ],
    },
    'connection_hijacking': {
        'description': 'Suspicious sequence number anomalies detected, which may indicate an attacker is attempting to inject data into an existing TCP session.',
        'impact': 'Data injection, session theft, credential interception, and unauthorized commands.',
        'remediation': [
            'Enable TCP sequence number randomization on servers',
            'Deploy encrypted channels (TLS/SSH) to prevent injection',
            'Monitor for unexpected sequence number jumps in IDS rules',
        ],
    },
    'udp_flood': {
        'description': 'An abnormally high rate of UDP packets targeting the network, aimed at overwhelming bandwidth and processing capacity.',
        'impact': 'Network saturation, service degradation, and potential outage of UDP-based services.',
        'remediation': [
            'Apply rate-limiting on inbound UDP traffic at the network edge',
            'Block traffic from known attacker source IPs',
            'Deploy DDoS scrubbing or upstream blackhole routing if volumetric',
        ],
    },
    'udp_amplification': {
        'description': 'Responses from UDP services (DNS, NTP, SSDP, etc.) are significantly larger than requests, suggesting the network is a victim or reflector in an amplification DDoS attack.',
        'impact': 'Bandwidth exhaustion on the victim, abuse of local services as reflectors.',
        'remediation': [
            'Disable or restrict open DNS/NTP/SSDP resolvers to authorized clients only',
            'Implement BCP38 (ingress filtering) to prevent IP spoofing',
            'Rate-limit responses from amplification-vulnerable services',
            'Contact upstream ISP for traffic filtering if the network is a victim',
        ],
    },
    'fragmentation_attack': {
        'description': 'High variance in UDP packet sizes with many unusually small fragments, which may indicate a fragmentation-based evasion or denial-of-service attack.',
        'impact': 'Firewall/IDS evasion, reassembly resource exhaustion, and potential crashes.',
        'remediation': [
            'Drop or reassemble fragmented packets at the network boundary',
            'Set minimum fragment size thresholds on the firewall',
            'Monitor for fragment overlap and tiny-fragment attacks in IDS',
        ],
    },
    'dns_tunneling': {
        'description': 'DNS queries contain unusually high entropy or deeply nested subdomains, a hallmark of data exfiltration or command-and-control over DNS.',
        'impact': 'Data exfiltration bypassing firewalls, covert C2 channels, and policy violations.',
        'remediation': [
            'Deploy DNS query logging and entropy-based anomaly detection',
            'Restrict DNS resolution to authorized internal resolvers',
            'Block direct outbound DNS (port 53) from endpoints; force proxy through monitored resolvers',
            'Investigate the queried domains and source hosts immediately',
        ],
    },
    'domain_generation_algorithm': {
        'description': 'Domains with algorithmically generated names detected, typically used by malware to locate command-and-control servers.',
        'impact': 'Active malware infection communicating with C2 infrastructure.',
        'remediation': [
            'Isolate and scan the source hosts for malware',
            'Block the identified DGA domains via DNS sinkholing',
            'Deploy a DNS firewall or threat intelligence feed for real-time DGA blocking',
        ],
    },
    'cache_poisoning': {
        'description': 'Multiple DNS responses for the same domain from different source IPs, which may indicate DNS cache poisoning attempts.',
        'impact': 'Users redirected to malicious sites, credential theft, malware delivery.',
        'remediation': [
            'Enable DNSSEC validation on resolvers',
            'Randomize DNS source ports and transaction IDs',
            'Restrict recursive resolution to trusted clients',
        ],
    },
    'excessive_nxdomain': {
        'description': 'A high rate of NXDOMAIN responses indicates queries for non-existent domains, possibly from DGA malware or misconfigured services.',
        'impact': 'Increased DNS resolver load, potential indicator of malware activity.',
        'remediation': [
            'Investigate the source hosts generating NXDOMAIN-heavy traffic',
            'Check for malware or misconfigured applications on those hosts',
            'Deploy DNS response rate-limiting (RRL) on authoritative servers',
        ],
    },
    'dns_amplification': {
        'description': 'Large DNS responses being sent to potentially spoofed source IPs, indicating the DNS server is being used as an amplification reflector.',
        'impact': 'Bandwidth exhaustion on the victim, abuse of local DNS infrastructure.',
        'remediation': [
            'Restrict recursive DNS queries to internal clients only',
            'Implement response rate-limiting (RRL) on DNS servers',
            'Enable BCP38 ingress filtering to prevent IP spoofing',
        ],
    },
    'sql_injection': {
        'description': 'HTTP requests contain SQL injection patterns (UNION SELECT, OR 1=1, etc.), indicating an attacker is attempting to manipulate backend databases.',
        'impact': 'Data breach, unauthorized data access, database corruption, and potential server compromise.',
        'remediation': [
            'Deploy a Web Application Firewall (WAF) with SQL injection rules',
            'Use parameterized queries / prepared statements in application code',
            'Apply input validation and output encoding',
            'Block the attacking IPs and review database access logs immediately',
        ],
    },
    'cross_site_scripting': {
        'description': 'HTTP requests contain XSS payloads (<script>, javascript:, onerror=, etc.), attempting to inject malicious scripts into web pages.',
        'impact': 'Session hijacking, credential theft, defacement, and malware distribution to users.',
        'remediation': [
            'Deploy a WAF with XSS filtering rules',
            'Implement Content Security Policy (CSP) headers',
            'Apply output encoding and input sanitization in the application',
        ],
    },
    'suspicious_user_agents': {
        'description': 'HTTP requests from known vulnerability scanning tools (sqlmap, nikto, nmap, etc.) detected.',
        'impact': 'Active reconnaissance and vulnerability scanning against web services.',
        'remediation': [
            'Block the scanner IPs at the WAF or firewall',
            'Review access logs for the scanned endpoints',
            'Ensure all web services are patched and hardened',
        ],
    },
    'http_flood': {
        'description': 'One or more IPs are sending HTTP requests at an anomalously high rate, consistent with an application-layer DDoS attack.',
        'impact': 'Web server resource exhaustion, service degradation, and potential outage.',
        'remediation': [
            'Rate-limit requests per source IP at the reverse proxy or WAF',
            'Deploy CAPTCHA or JavaScript challenges for suspicious clients',
            'Use a CDN with DDoS protection capabilities',
        ],
    },
    'directory_traversal': {
        'description': 'HTTP requests contain path traversal sequences (../, ....\\\\, etc.) attempting to access files outside the web root.',
        'impact': 'Exposure of sensitive files (config, credentials, source code) on the server.',
        'remediation': [
            'Validate and canonicalize file paths in the application',
            'Configure the web server to restrict access to the document root',
            'Deploy WAF rules to block path traversal patterns',
        ],
    },
    'ssl_downgrade': {
        'description': 'An unusually high ratio of small TLS packets suggests potential SSL/TLS downgrade attempts or protocol manipulation.',
        'impact': 'Weakened encryption, exposure to man-in-the-middle attacks.',
        'remediation': [
            'Enforce TLS 1.2+ and disable SSLv3/TLS 1.0/1.1 on servers',
            'Enable HSTS (HTTP Strict Transport Security)',
            'Monitor for TLS negotiation anomalies in IDS',
        ],
    },
    'certificate_issues': {
        'description': 'Potential TLS certificate anomalies detected (expired, self-signed, or mismatched certificates).',
        'impact': 'Users may be vulnerable to man-in-the-middle attacks if certificate warnings are ignored.',
        'remediation': [
            'Renew expired certificates and deploy valid CA-signed certificates',
            'Enable certificate pinning for critical services',
            'Monitor certificate transparency logs for unauthorized issuance',
        ],
    },
    'https_flood': {
        'description': 'High-rate encrypted connections from specific IPs, consistent with an encrypted DDoS attack.',
        'impact': 'TLS handshake exhaustion, increased CPU usage, and service degradation.',
        'remediation': [
            'Rate-limit TLS connections per source IP',
            'Deploy TLS-aware load balancers with connection limits',
            'Use a DDoS mitigation service that can inspect encrypted traffic',
        ],
    },
    'icmp_flood': {
        'description': 'An abnormally high rate of ICMP packets (ping flood) targeting the network.',
        'impact': 'Bandwidth consumption and CPU overhead on targeted hosts.',
        'remediation': [
            'Rate-limit ICMP traffic at the network boundary',
            'Drop ICMP echo requests from untrusted sources on the firewall',
        ],
    },
    'ping_of_death': {
        'description': 'Oversized ICMP packets detected that exceed the maximum IP packet size, targeting vulnerable TCP/IP stack implementations.',
        'impact': 'Potential system crash or buffer overflow on vulnerable hosts.',
        'remediation': [
            'Ensure all systems are patched against oversized ICMP vulnerabilities',
            'Drop ICMP packets exceeding 1024 bytes at the firewall',
        ],
    },
    'smurf_attack': {
        'description': 'ICMP echo requests sent to broadcast addresses, causing all hosts on the subnet to reply to the victim (spoofed source IP).',
        'impact': 'Amplified traffic flood directed at the victim IP.',
        'remediation': [
            'Disable directed broadcast on all router interfaces',
            'Implement ingress filtering (BCP38) to block spoofed source IPs',
        ],
    },
    'icmp_tunneling': {
        'description': 'ICMP packets with unusually large payloads detected, which may indicate data exfiltration or covert channels over ICMP.',
        'impact': 'Data exfiltration bypassing firewall rules that allow ICMP.',
        'remediation': [
            'Restrict ICMP payload sizes at the firewall (drop payloads > 64 bytes)',
            'Monitor ICMP traffic volume and payload entropy',
            'Investigate source hosts for tunneling tools (icmptunnel, ptunnel, etc.)',
        ],
    },
    'network_scanning': {
        'description': 'ICMP-based network scanning (ping sweeps) detected, probing for live hosts across the network.',
        'impact': 'Network reconnaissance revealing live hosts and topology.',
        'remediation': [
            'Block ICMP echo requests from external sources',
            'Deploy deception technology (honeypots) to detect and alert on scans',
        ],
    },
    # WLAN threats
    'deauth_flood': {
        'description': 'A large number of 802.11 deauthentication frames detected, indicating a WiFi denial-of-service attack forcing clients to disconnect.',
        'impact': 'All wireless clients are forcibly disconnected from the AP, causing service outage and enabling follow-up attacks (Evil Twin, credential capture).',
        'remediation': [
            'Enable 802.11w (Protected Management Frames / PMF) on access points',
            'Deploy a Wireless Intrusion Prevention System (WIPS)',
            'Locate the attacker using RF triangulation or WIPS sensors',
            'Consider moving to WPA3 which mandates PMF',
        ],
    },
    'disassoc_flood': {
        'description': 'Excessive 802.11 disassociation frames detected, a variant of WiFi denial-of-service.',
        'impact': 'Clients are forcibly disassociated from the network, causing connectivity loss.',
        'remediation': [
            'Enable 802.11w (PMF) on all access points',
            'Deploy WIPS to auto-detect and contain the source',
        ],
    },
    'evil_twin': {
        'description': 'The same SSID is being advertised from multiple BSSIDs, which may indicate a rogue access point impersonating a legitimate network.',
        'impact': 'Users may unknowingly connect to a malicious AP, exposing credentials and traffic to interception.',
        'remediation': [
            'Deploy WIPS to detect and auto-contain rogue APs',
            'Enable 802.1X/EAP for mutual authentication',
            'Monitor for unauthorized BSSIDs using wireless surveys',
            'Educate users to verify network certificates before connecting',
        ],
    },
    'beacon_flood': {
        'description': 'Abnormally high beacon frame rate detected, potentially from a beacon flood attack creating fake wireless networks.',
        'impact': 'Client device WiFi scanning becomes unusable due to thousands of fake SSIDs.',
        'remediation': [
            'Deploy WIPS to filter and alert on beacon anomalies',
            'Locate the source of the beacon flood using RF tools',
        ],
    },
    'probe_reconnaissance': {
        'description': 'Devices sending excessive probe requests, scanning for available WiFi networks — a common reconnaissance technique.',
        'impact': 'Reveals network topology, SSID names, and client device information to the attacker.',
        'remediation': [
            'Disable SSID broadcast on sensitive networks',
            'Monitor for excessive probe requests via WIPS',
            'Consider MAC address filtering as a supplementary measure',
        ],
    },
    'weak_signal_coverage': {
        'description': 'A significant portion of wireless frames have weak signal strength, indicating coverage gaps or distance issues.',
        'impact': 'Poor application performance, high packet loss, increased retransmissions, and client disconnections.',
        'remediation': [
            'Conduct a wireless site survey to identify coverage gaps',
            'Add or reposition access points in weak areas',
            'Increase AP transmit power if within regulatory limits',
            'Check for sources of RF interference (microwaves, Bluetooth, neighboring APs)',
        ],
    },
    'unprotected_traffic': {
        'description': 'Data frames transmitted without encryption detected, exposing payload content to anyone within radio range.',
        'impact': 'Sensitive data (credentials, session tokens, personal information) visible to passive eavesdroppers.',
        'remediation': [
            'Ensure all SSIDs use WPA2/WPA3 encryption',
            'Disable open/unencrypted SSIDs',
            'Use 802.1X/EAP for enterprise-grade authentication',
        ],
    },
    'high_retry_rate': {
        'description': 'A high percentage of wireless frames are being retransmitted, indicating RF interference, channel congestion, or hardware issues.',
        'impact': 'Degraded throughput, increased latency, and poor user experience on the wireless network.',
        'remediation': [
            'Check for co-channel interference and adjust channel assignments',
            'Reduce AP transmit power to minimize overlap with neighboring APs',
            'Move to 5 GHz or 6 GHz bands to reduce 2.4 GHz congestion',
            'Inspect for faulty hardware (cables, antennas, APs)',
        ],
    },
    'auth_flood': {
        'description': 'An abnormally large number of 802.11 authentication frames detected, potentially a brute-force or resource-exhaustion attack.',
        'impact': 'AP authentication queue saturation, preventing legitimate clients from connecting.',
        'remediation': [
            'Enable 802.11w (PMF) to protect authentication frames',
            'Rate-limit authentication attempts on the AP',
            'Deploy WIPS to detect and block the attack source',
        ],
    },
    # DHCP threats
    'dhcp_starvation': {
        'description': 'Many DHCP Discover messages from different MAC addresses, indicating an attacker is trying to exhaust the DHCP address pool.',
        'impact': 'Legitimate clients cannot obtain IP addresses, causing network denial-of-service.',
        'remediation': [
            'Enable DHCP snooping on the switch to validate DHCP messages',
            'Configure port security to limit MAC addresses per port',
            'Deploy dynamic ARP inspection (DAI) as a secondary defense',
        ],
    },
    'rogue_dhcp_server': {
        'description': 'Multiple DHCP servers responding to client requests — unauthorized servers may redirect traffic or perform man-in-the-middle attacks.',
        'impact': 'Clients may receive incorrect DNS/gateway settings, enabling traffic interception or service disruption.',
        'remediation': [
            'Enable DHCP snooping and mark only authorized DHCP server ports as trusted',
            'Investigate and disconnect the rogue DHCP server',
            'Use 802.1X port authentication to prevent unauthorized devices',
        ],
    },
    'rapid_dhcp_requests': {
        'description': 'DHCP requests arriving at an abnormally high rate, potentially from an automated attack or misconfigured clients.',
        'impact': 'DHCP server overload and potential address pool exhaustion.',
        'remediation': [
            'Enable DHCP rate-limiting on the switch',
            'Investigate the source MACs for misconfiguration or attack tools',
        ],
    },
    'dhcp_nak_flood': {
        'description': 'Excessive DHCP NAK (Negative Acknowledgement) responses detected, indicating address conflicts or a DHCP server under stress.',
        'impact': 'Clients repeatedly fail to obtain valid IP addresses, causing connectivity issues.',
        'remediation': [
            'Check for IP address conflicts in the DHCP scope',
            'Verify DHCP server pool is not exhausted',
            'Investigate if a rogue DHCP server is sending NAKs',
        ],
    },
    # TCP enhanced threats
    'zero_window': {
        'description': 'TCP zero window conditions detected — the receiver is advertising a window size of 0, telling the sender to stop transmitting until buffer space is available.',
        'impact': 'Data transfer stalls, application timeouts, and degraded throughput on affected connections.',
        'remediation': [
            'Investigate the receiving host for CPU / memory pressure or slow application processing',
            'Increase TCP receive buffer sizes (net.core.rmem_max, net.ipv4.tcp_rmem)',
            'Check for application-level bottlenecks that are not consuming data fast enough',
            'Monitor for window size recovery (Window Update) to confirm transient vs persistent issues',
        ],
    },
    'connection_resets': {
        'description': 'TCP RST packets indicating abrupt connection terminations — connections refused by the server, firewall resets, or application crashes.',
        'impact': 'Data loss on in-flight transfers, failed transactions, and poor user experience.',
        'remediation': [
            'Check server logs for application errors or crashes causing RSTs',
            'Verify firewall rules are not prematurely resetting idle connections',
            'Investigate NAT/load balancer timeout settings',
            'Review connection refused errors (RST after SYN) for misconfigured services',
        ],
    },
    'data_transmission_gaps': {
        'description': 'Significant silence periods detected within active TCP flows, indicating stalled data transfer or connection breaks.',
        'impact': 'Application timeouts, retransmission delays, and degraded performance.',
        'remediation': [
            'Check for network path issues (packet loss, route changes) during gap periods',
            'Investigate TCP keepalive settings to prevent idle connection drops',
            'Review application-level flow control and buffering',
            'Monitor for correlating events (link flaps, failovers) at gap timestamps',
        ],
    },
    # HTTPS enhanced threats
    'tls_handshake_failure': {
        'description': 'TLS connections terminated during the handshake phase (RST/FIN after SYN), indicating certificate validation errors, protocol version mismatches, or cipher suite incompatibilities.',
        'impact': 'Clients unable to establish secure connections, service unavailability for HTTPS endpoints.',
        'remediation': [
            'Check server TLS certificates for expiry, chain issues, or hostname mismatches',
            'Verify TLS version compatibility between client and server (TLS 1.2+ recommended)',
            'Review cipher suite configuration — ensure modern ciphers are supported',
            'Check server logs for TLS alert messages indicating the failure reason',
        ],
    },
    'incomplete_tls_connections': {
        'description': 'A significant number of TLS connections completed only a few packets before terminating, indicating systematic connection setup failures.',
        'impact': 'Service degradation, failed API calls, broken client connectivity to HTTPS services.',
        'remediation': [
            'Investigate if a load balancer or proxy is dropping connections prematurely',
            'Check server capacity — connection limits, file descriptor exhaustion',
            'Review client-side TLS library compatibility and error logs',
            'Test connectivity with openssl s_client to diagnose handshake issues',
        ],
    },
}


class HTMLReportGenerator:
    """Generate HTML reports for network analysis results"""

    def __init__(self):
        self.report_template = self._get_template()

    # ------------------------------------------------------------------
    #  Helpers to extract data from the multi-protocol results structure
    # ------------------------------------------------------------------

    def _collect_all_threats(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Walk protocol_analysis and collect every detected threat."""
        threats = []
        proto_analysis = results.get('protocol_analysis', {})
        # Handle single-protocol results (keys are 'threats', 'statistics', …)
        if 'threats' in results and isinstance(results['threats'], dict):
            for name, data in results['threats'].items():
                if isinstance(data, dict) and (data.get('detected') or data.get('high_rate')):
                    threats.append({'protocol': 'N/A', 'name': name, **data})

        for proto, analysis in proto_analysis.items():
            if not isinstance(analysis, dict):
                continue
            for name, data in analysis.get('threats', {}).items():
                if not isinstance(data, dict):
                    continue
                if data.get('detected') or data.get('high_rate'):
                    threats.append({'protocol': proto.upper(), 'name': name, **data})

        # Sort: critical first, then high, medium, low
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        threats.sort(key=lambda t: severity_order.get(t.get('severity', 'info'), 5))
        return threats

    def _collect_protocol_summaries(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect per-protocol packet counts and statistics."""
        summaries = []
        proto_analysis = results.get('protocol_analysis', {})
        for proto, analysis in proto_analysis.items():
            if not isinstance(analysis, dict):
                continue
            summaries.append({
                'protocol': proto.upper(),
                'total_packets': analysis.get('total_packets', 0),
                'statistics': analysis.get('statistics', {}),
                'threats': analysis.get('threats', {}),
            })
        return summaries

    # ------------------------------------------------------------------
    #  Public entry point
    # ------------------------------------------------------------------

    def generate_report(
        self,
        results: Dict[str, Any],
        pcap_file: str,
        output_file: str,
        protocol: str = "All"
    ) -> str:
        logger.info(f"Generating HTML report: {output_file}")

        html_content = self.report_template

        html_content = html_content.replace("{{TITLE}}", f"Network Analysis Report - {protocol}")
        html_content = html_content.replace("{{PCAP_FILE}}", Path(pcap_file).name)
        html_content = html_content.replace("{{ANALYSIS_DATE}}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        html_content = html_content.replace("{{PROTOCOL}}", protocol)

        all_threats = self._collect_all_threats(results)
        proto_summaries = self._collect_protocol_summaries(results)

        summary_html = self._generate_summary(results, all_threats, proto_summaries)
        critical_issues_html = self._generate_critical_issues(all_threats)
        statistics_html = self._generate_statistics(results, proto_summaries)
        threats_html = self._generate_threats(all_threats)
        charts_html = self._generate_charts(results, proto_summaries, all_threats)

        html_content = html_content.replace("{{SUMMARY}}", summary_html)
        html_content = html_content.replace("{{CRITICAL_ISSUES}}", critical_issues_html)
        html_content = html_content.replace("{{STATISTICS}}", statistics_html)
        html_content = html_content.replace("{{THREATS}}", threats_html)
        html_content = html_content.replace("{{CHARTS}}", charts_html)

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"Report generated: {output_path}")
        return str(output_path)

    # ------------------------------------------------------------------
    #  Section generators
    # ------------------------------------------------------------------

    def _generate_summary(self, results: Dict[str, Any], all_threats: List, proto_summaries: List) -> str:
        total_packets = results.get('total_packets', 0)
        threat_count = len(all_threats)
        protocols_analyzed = len(proto_summaries)

        # Count by severity
        sev_counts: Dict[str, int] = {}
        for t in all_threats:
            s = t.get('severity', 'info').lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        critical_high = sev_counts.get('critical', 0) + sev_counts.get('high', 0)

        if sev_counts.get('critical', 0) > 0 or critical_high >= 3:
            severity_class = "critical"
            severity_text = "CRITICAL"
        elif critical_high >= 1:
            severity_class = "high"
            severity_text = "HIGH RISK"
        elif threat_count > 0:
            severity_class = "medium"
            severity_text = "MEDIUM RISK"
        else:
            severity_class = "low"
            severity_text = "LOW RISK"

        # Protocol breakdown table
        proto_dist = results.get('protocols', {})
        proto_table = ''
        if proto_dist:
            proto_table = '''
            <div style="margin-top:20px">
                <h3 style="color:#667eea;margin-bottom:10px">Protocol Distribution (All Packets)</h3>
                <table class="data-table"><thead><tr><th>Protocol</th><th>Packets</th><th>Percentage</th></tr></thead><tbody>'''
            for pname, pcount in sorted(proto_dist.items(), key=lambda x: x[1], reverse=True):
                pct = (pcount / total_packets * 100) if total_packets else 0
                proto_table += f'<tr><td>{pname}</td><td>{pcount:,}</td><td>{pct:.1f}%</td></tr>'
            proto_table += '</tbody></table></div>'

        # Per-analyzer packet counts
        analyzer_table = ''
        if proto_summaries:
            analyzer_table = '''
            <div style="margin-top:20px">
                <h3 style="color:#667eea;margin-bottom:10px">Per-Protocol Analyzer Results</h3>
                <table class="data-table"><thead><tr><th>Analyzer</th><th>Packets Analyzed</th><th>Threats Found</th></tr></thead><tbody>'''
            for ps in proto_summaries:
                detected = sum(1 for td in ps['threats'].values()
                               if isinstance(td, dict) and (td.get('detected') or td.get('high_rate')))
                analyzer_table += f'<tr><td>{ps["protocol"]}</td><td>{ps["total_packets"]:,}</td><td>{detected}</td></tr>'
            analyzer_table += '</tbody></table></div>'

        html = f"""
        <div class="summary-cards">
            <div class="summary-card">
                <div class="card-label">Total Packets Captured</div>
                <div class="card-value">{total_packets:,}</div>
            </div>
            <div class="summary-card">
                <div class="card-label">Protocols Analyzed</div>
                <div class="card-value">{protocols_analyzed}</div>
            </div>
            <div class="summary-card">
                <div class="card-label">Threats Detected</div>
                <div class="card-value {"critical" if critical_high > 0 else "warning" if threat_count > 0 else ""}">{threat_count}</div>
            </div>
            <div class="summary-card">
                <div class="card-label">Risk Level</div>
                <div class="card-value {severity_class}">{severity_text}</div>
            </div>
        </div>
        {proto_table}
        {analyzer_table}
        """
        return html

    def _generate_critical_issues(self, all_threats: List[Dict[str, Any]]) -> str:
        if not all_threats:
            return '<div class="alert alert-success">&#10003; No critical issues detected</div>'

        html = '<div class="critical-issues-list">'
        for t in all_threats:
            severity = t.get('severity', 'medium').upper()
            severity_class = severity.lower()
            threat_name = t.get('name', 'unknown')
            protocol = t.get('protocol', '')
            message = t.get('message', threat_name.replace('_', ' ').title())
            guide = REMEDIATION_GUIDE.get(threat_name, {})
            description = guide.get('description', '')
            impact = guide.get('impact', '')
            remediation_steps = guide.get('remediation', [])

            html += f"""
            <div class="issue-card {severity_class}">
                <div class="issue-header">
                    <span class="severity-badge {severity_class}">{severity}</span>
                    <span class="protocol-badge">{protocol}</span>
                    <h3>{threat_name.replace('_', ' ').title()}</h3>
                </div>
                <div class="issue-body">
                    <p class="threat-message">{message}</p>
            """

            if description:
                html += f'<p style="margin-top:8px"><strong>What is this?</strong> {description}</p>'
            if impact:
                html += f'<p style="margin-top:4px"><strong>Impact:</strong> {impact}</p>'

            # Show key numeric details from the threat data
            detail_keys = [
                ('retransmission_rate', 'Retransmission Rate', lambda v: f"{v*100:.2f}%"),
                ('retransmission_count', 'Retransmissions', lambda v: f"{v:,}"),
                ('syn_rate', 'SYN Rate', lambda v: f"{v:.1f} pkts/sec"),
                ('rst_rate', 'RST Rate', lambda v: f"{v:.1f} pkts/sec"),
                ('packet_rate', 'Packet Rate', lambda v: f"{v:.1f} pkts/sec"),
                ('amplification_packet_count', 'Amplified Responses', lambda v: f"{v:,}"),
                ('scanner_count', 'Scanner Count', lambda v: f"{v:,}"),
                ('sqli_attempt_count', 'SQLi Attempts', lambda v: f"{v:,}"),
                ('xss_attempt_count', 'XSS Attempts', lambda v: f"{v:,}"),
                ('high_rate_ip_count', 'High-Rate IPs', lambda v: f"{v:,}"),
                ('suspicious_query_count', 'Suspicious Queries', lambda v: f"{v:,}"),
                ('dga_domain_count', 'DGA Domains', lambda v: f"{v:,}"),
                ('nxdomain_rate', 'NXDOMAIN Rate', lambda v: f"{v*100:.1f}%"),
                ('nxdomain_count', 'NXDOMAIN Count', lambda v: f"{v:,}"),
                ('traversal_attempt_count', 'Traversal Attempts', lambda v: f"{v:,}"),
                ('suspicious_request_count', 'Suspicious Requests', lambda v: f"{v:,}"),
                ('small_packet_ratio', 'Small Packet Ratio', lambda v: f"{v*100:.1f}%"),
                ('packet_size_variance', 'Packet Size Variance', lambda v: f"{v:.2f}"),
            ]
            details_html = ''
            for key, label, fmt in detail_keys:
                if key in t:
                    details_html += f'<div class="detail-item"><strong>{label}:</strong> {fmt(t[key])}</div>'

            # IP/domain tables (scanners, top_targets, top_sources, etc.)
            ip_tables = [
                ('top_targets', 'Top Targets', 'IP Address', 'Packets'),
                ('top_sources', 'Top Sources', 'IP Address', 'Packets'),
                ('scanners', 'Scanners', 'IP Address', 'Ports Scanned'),
                ('scanner_ips', 'Scanners', 'IP Address', 'Ports Scanned'),
                ('attacker_ips', 'Attacker IPs', 'IP Address', 'Requests'),
                ('scanner_ips_http', 'Scanner IPs', 'IP Address', 'Requests'),
                ('victim_ips', 'Victim IPs', 'IP Address', 'Packets'),
                ('top_requesters', 'Top Requesters', 'IP Address', 'Req/sec'),
                ('abused_services', 'Abused Services', 'Service', 'Packets'),
                ('top_failing_domains', 'Top Failing Domains', 'Domain', 'Count'),
                ('user_agents', 'Suspicious User Agents', 'User Agent', 'Count'),
            ]
            for key, title, col1, col2 in ip_tables:
                data = t.get(key, {})
                if data and isinstance(data, dict):
                    details_html += f'<h4 style="margin-top:10px">{title}</h4>'
                    details_html += f'<table class="data-table"><thead><tr><th>{col1}</th><th>{col2}</th></tr></thead><tbody>'
                    for k, v in sorted(data.items(), key=lambda x: x[1], reverse=True)[:10]:
                        v_str = f"{v:.2f}" if isinstance(v, float) else f"{v:,}" if isinstance(v, int) else str(v)
                        details_html += f'<tr><td>{k}</td><td>{v_str}</td></tr>'
                    details_html += '</tbody></table>'

            # Sample domains / URIs
            for key, title in [('sample_domains', 'Sample Domains'), ('sample_uris', 'Sample URIs')]:
                items = t.get(key, [])
                if items:
                    details_html += f'<h4 style="margin-top:10px">{title}</h4><ul>'
                    for item in items[:10]:
                        details_html += f'<li><code>{item}</code></li>'
                    details_html += '</ul>'

            if details_html:
                html += f'<div class="issue-details">{details_html}</div>'

            # ── WLAN-specific rich details ──────────────────────────────
            threat_name_raw = t.get('name', '')

            # Connection failures: breakdown, client timelines, frame details
            if threat_name_raw == 'connection_failures':
                breakdown = t.get('failure_breakdown', {})
                if breakdown:
                    html += '<h4 style="margin-top:14px">Failure Breakdown by Root Cause</h4>'
                    html += '<table class="data-table"><thead><tr><th>Root Cause</th><th>Count</th></tr></thead><tbody>'
                    for cat, cnt in sorted(breakdown.items(), key=lambda x: x[1], reverse=True):
                        html += f'<tr><td>{cat}</td><td>{cnt}</td></tr>'
                    html += '</tbody></table>'

                remediations = t.get('remediations', {})
                if remediations:
                    html += '<h4 style="margin-top:14px">&#128736; Recommended Remediations per Root Cause</h4>'
                    html += '<table class="data-table"><thead><tr><th>Root Cause</th><th>Recommended Action</th></tr></thead><tbody>'
                    for cat, action in remediations.items():
                        html += f'<tr><td><strong>{cat}</strong></td><td>{action}</td></tr>'
                    html += '</tbody></table>'

                timelines = t.get('client_timelines', {})
                if timelines:
                    html += '<h4 style="margin-top:14px">Per-Client Failure Timeline</h4>'
                    for client, events in timelines.items():
                        html += f'<div style="margin-bottom:12px"><strong>Device / AP: <code>{client}</code></strong>'
                        html += '<table class="data-table" style="margin-top:4px"><thead><tr>'
                        html += '<th>Frame #</th><th>Type</th><th>Root Cause</th><th>Code</th><th>IEEE Reason</th><th>Signal (dBm)</th></tr></thead><tbody>'
                        from datetime import datetime as _dt
                        for ev in events:
                            ts_str = ''
                            try:
                                ts_str = _dt.fromtimestamp(ev['timestamp']).strftime('%H:%M:%S.%f')[:-3]
                            except Exception:
                                ts_str = str(ev.get('timestamp', ''))
                            sig = ev.get('signal_dbm', '')
                            sig_str = f'{sig} dBm' if sig else '—'
                            frame_str = str(ev.get('frame', '—'))
                            html += (
                                f'<tr>'
                                f'<td>{frame_str}</td>'
                                f'<td>{ev.get("type","")}</td>'
                                f'<td>{ev.get("root_cause","")}</td>'
                                f'<td>{ev.get("code","")}</td>'
                                f'<td>{ev.get("reason","")}</td>'
                                f'<td>{sig_str}</td>'
                                f'</tr>'
                            )
                        html += '</tbody></table></div>'

                # EAPOL 4-way handshake analysis block
                eapol_analysis = t.get('eapol_handshake_analysis', {})
                if eapol_analysis:
                    wrong_psk = eapol_analysis.get('wrong_psk_likely', False)
                    box_color = '#ffebee' if wrong_psk else '#e8f5e9'
                    border_color = '#e53935' if wrong_psk else '#43a047'
                    icon = '&#10060;' if wrong_psk else '&#9989;'
                    pattern = eapol_analysis.get('pattern', '')
                    note = eapol_analysis.get('note', '')
                    action = eapol_analysis.get('immediate_action', '')
                    html += (
                        f'<h4 style="margin-top:14px">&#128273; EAPOL 4-Way Handshake Analysis</h4>'
                        f'<div style="background:{box_color};border-left:4px solid {border_color};'
                        f'padding:12px 16px;border-radius:4px;margin-top:8px">'
                        f'<p><strong>{icon} Pattern:</strong> {pattern}</p>'
                        f'<table class="data-table" style="margin-top:8px">'
                        f'<thead><tr><th>Message</th><th>Direction</th><th>Count</th></tr></thead><tbody>'
                        f'<tr><td>Msg 1 (ANonce)</td><td>AP &#8594; Client</td><td>{eapol_analysis.get("msg1_count",0)}</td></tr>'
                        f'<tr><td>Msg 2 (SNonce + MIC)</td><td>Client &#8594; AP</td><td>{eapol_analysis.get("msg2_count",0)}</td></tr>'
                        f'<tr><td>Msg 3 (PTK Install)</td><td>AP &#8594; Client</td><td><strong>{eapol_analysis.get("msg3_count",0)}</strong></td></tr>'
                        f'</tbody></table>'
                    )
                    if note:
                        html += f'<p style="margin-top:10px">&#128203; <em>{note}</em></p>'
                    if wrong_psk and action:
                        html += (
                            f'<p style="margin-top:8px;font-weight:bold;color:#b71c1c">'
                            f'&#128161; Immediate Action: {action}</p>'
                        )
                    html += '</div>'

                # ── Per-client connection flow analysis ──────────────────────
                conn_flows = t.get('connection_flows', {})
                if conn_flows:
                    from datetime import datetime as _dt2
                    # Category → CSS colour
                    CAT_COLOR = {
                        'scan':       '#f5f5f5',
                        'auth':       '#e3f2fd',
                        'success':    '#e8f5e9',
                        'failure':    '#ffebee',
                        'assoc':      '#e3f2fd',
                        'eapol':      '#fff8e1',
                        'disconnect': '#fce4ec',
                    }
                    CAT_ICON = {
                        'scan':       '&#128269;',
                        'auth':       '&#128274;',
                        'success':    '&#9989;',
                        'failure':    '&#10060;',
                        'assoc':      '&#128279;',
                        'eapol':      '&#128273;',
                        'disconnect': '&#128680;',
                    }
                    html += '<h4 style="margin-top:20px">&#128196; Connection Flow Analysis (per Client)</h4>'
                    for client_mac, sessions in conn_flows.items():
                        html += (
                            f'<details style="margin-bottom:12px;border:1px solid #ddd;border-radius:4px">'
                            f'<summary style="padding:8px 12px;cursor:pointer;font-weight:bold;'
                            f'background:#f5f5f5">&#128100; Client: <code>{client_mac}</code> '
                            f'&mdash; {len(sessions)} connection session(s)</summary>'
                            f'<div style="padding:10px 14px">'
                        )
                        for si, sess in enumerate(sessions, 1):
                            diag  = sess.get('diagnosis', {})
                            phase = diag.get('phase', 'Unknown phase')
                            ap    = sess.get('ap_bssid') or '—'
                            vd    = diag.get('validated_disconnect', '')
                            ev_list = diag.get('evidence', [])
                            action  = diag.get('recommended_action', '')
                            mc    = diag.get('eapol_stats', {})
                            data_cnt = diag.get('data_frames', 0)
                            is_wrong_psk = 'Wrong PSK' in vd or 'wrong passphrase' in vd.lower()
                            phase_color = '#b71c1c' if 'Failed' in phase else '#1565c0'

                            html += (
                                f'<h5 style="margin-top:14px;color:{phase_color}">'
                                f'Session {si} &mdash; {phase}</h5>'
                                f'<p style="margin:2px 0"><strong>AP BSSID:</strong> <code>{ap}</code></p>'
                            )

                            # Event timeline table
                            events_list = sess.get('events', [])
                            if events_list:
                                html += (
                                    '<table class="data-table" style="margin-top:8px;font-size:0.88em">'
                                    '<thead><tr>'
                                    '<th>Frame</th><th>Time</th><th>Direction</th>'
                                    '<th>Step</th><th>Details</th><th>Signal</th>'
                                    '</tr></thead><tbody>'
                                )
                                for ev in events_list:
                                    cat    = ev.get('category', '')
                                    bg     = CAT_COLOR.get(cat, '#ffffff')
                                    icon   = CAT_ICON.get(cat, '')
                                    fn_str = str(ev.get('frame', '—'))
                                    step   = ev.get('step', '')
                                    note   = ev.get('note', '')
                                    sig    = ev.get('signal_dbm')
                                    sig_s  = f'{sig} dBm' if sig else '—'
                                    ts_s   = ''
                                    try:
                                        ts_s = _dt2.fromtimestamp(ev['timestamp']).strftime('%H:%M:%S.%f')[:-3]
                                    except Exception:
                                        ts_s = str(ev.get('timestamp', ''))
                                    dirn   = ev.get('direction', '')
                                    # Validated reason for terminal events
                                    if ev.get('is_terminal') and ev.get('validated_reason'):
                                        note = (
                                            f'<strong>{note}</strong>'
                                            f'<br><span style="color:#b71c1c">'
                                            f'&#128161; Validated: {ev["validated_reason"]}</span>'
                                        )
                                    html += (
                                        f'<tr style="background:{bg}">'
                                        f'<td>{fn_str}</td>'
                                        f'<td style="white-space:nowrap">{ts_s}</td>'
                                        f'<td style="white-space:nowrap">{dirn}</td>'
                                        f'<td><strong>{icon} {step}</strong></td>'
                                        f'<td>{note}</td>'
                                        f'<td style="white-space:nowrap">{sig_s}</td>'
                                        f'</tr>'
                                    )
                                html += '</tbody></table>'

                            # Data frame summary row
                            if data_cnt > 0:
                                html += (
                                    f'<p style="margin:4px 0;font-size:0.88em;color:#555">'
                                    f'&#128190; {data_cnt} data frame(s) exchanged in this session</p>'
                                )
                            # EAPOL stats
                            if any(mc.get(i, 0) > 0 for i in range(1, 5)):
                                m_str = ' / '.join(
                                    f'Msg{i}: {mc.get(i,0)}' for i in range(1, 5)
                                )
                                html += (
                                    f'<p style="margin:4px 0;font-size:0.88em">'
                                    f'&#128273; EAPOL 4-way handshake &mdash; {m_str}</p>'
                                )

                            # Diagnosis box
                            diag_bg     = '#ffebee' if is_wrong_psk else '#e3f2fd'
                            diag_border = '#e53935' if is_wrong_psk else '#1565c0'
                            if vd:
                                html += (
                                    f'<div style="background:{diag_bg};border-left:4px solid {diag_border};'
                                    f'padding:10px 14px;margin-top:10px;border-radius:4px">'
                                    f'<p><strong>&#128202; Validated Disconnect Reason:</strong><br>'
                                    f'<span style="color:{diag_border}">{vd}</span></p>'
                                )
                                if ev_list:
                                    html += '<p style="margin-top:8px"><strong>Frame Evidence:</strong></p><ul style="margin:4px 0 0 18px">'
                                    for e_item in ev_list:
                                        html += f'<li style="margin-bottom:3px">{e_item}</li>'
                                    html += '</ul>'
                                if action:
                                    html += (
                                        f'<p style="margin-top:10px"><strong>&#128736; Recommended Action:</strong>'
                                        f'<br>{action}</p>'
                                    )
                                html += '</div>'

                        html += '</div></details>'


            elif threat_name_raw == 'beacon_loss':
                bssid_detail = t.get('bssid_detail', {})
                if bssid_detail:
                    html += '<h4 style="margin-top:14px">Beacon Loss Detail per BSSID</h4>'
                    html += '<table class="data-table"><thead><tr><th>BSSID</th><th>Loss Events</th><th>Max Gap (s)</th><th>Avg Gap (s)</th><th>Total Beacons</th></tr></thead><tbody>'
                    for bssid, detail in sorted(bssid_detail.items(), key=lambda x: x[1]['loss_events'], reverse=True):
                        html += (
                            f'<tr><td><code>{bssid}</code></td>'
                            f'<td>{detail["loss_events"]}</td>'
                            f'<td>{detail["max_gap_sec"]}</td>'
                            f'<td>{detail["avg_gap_sec"]}</td>'
                            f'<td>{detail["total_beacons"]}</td></tr>'
                        )
                    html += '</tbody></table>'

            # Scan failures: devices that probed but never associated
            elif threat_name_raw == 'scan_failures':
                details_list = t.get('scan_only_details', [])
                if details_list:
                    for dev in details_list:
                        client_mac = dev.get('client', '')
                        is_ps = dev.get('power_save_scanning', False)
                        interp = dev.get('interpretation', '')
                        n_probes = dev.get('probe_requests', 0)
                        responding_aps = dev.get('responding_aps', [])

                        html += (
                            f'<div style="background:#fff8e1;border-left:4px solid #f9a825;'
                            f'padding:14px 18px;border-radius:4px;margin:14px 0">'
                            f'<p style="margin:0 0 8px"><strong>Client:</strong> <code>{client_mac}</code>'
                            f'&nbsp;&nbsp;<strong>Probe Requests sent:</strong> {n_probes}'
                        )
                        if is_ps:
                            html += (
                                '&nbsp;&nbsp;<span style="background:#e3f2fd;color:#1565c0;'
                                'padding:2px 8px;border-radius:10px;font-size:0.8em;font-weight:600">'
                                '&#128264; Power-Save Scan</span>'
                            )
                        html += f'</p><p style="margin:0 0 8px;color:#444">{interp}</p>'

                        if responding_aps:
                            html += (
                                '<h4 style="margin:10px 0 6px">APs That Responded with Probe Response</h4>'
                                '<table class="data-table"><thead><tr>'
                                '<th>AP BSSID</th><th>SSID</th><th>Probe Responses</th>'
                                '</tr></thead><tbody>'
                            )
                            for ap in responding_aps:
                                ssid_disp = ap.get('ssid') or '<em style="color:#888">(hidden)</em>'
                                html += (
                                    f'<tr><td><code>{ap.get("bssid","")}</code></td>'
                                    f'<td>{ssid_disp}</td>'
                                    f'<td>{ap.get("responses",0)}</td></tr>'
                                )
                            html += '</tbody></table>'
                        else:
                            html += '<p style="color:#777;font-style:italic">No probe responses captured for this client.</p>'
                        html += '</div>'
                # Legacy fallback (old format)
                elif t.get('scan_only_device_probes'):
                    scan_probes = t['scan_only_device_probes']
                    html += '<h4 style="margin-top:14px">Scan-Only Devices (Probed but No Association)</h4>'
                    html += '<table class="data-table"><thead><tr><th>Device MAC</th><th>Probe Requests Sent</th></tr></thead><tbody>'
                    for mac, cnt in sorted(scan_probes.items(), key=lambda x: x[1], reverse=True)[:15]:
                        html += f'<tr><td><code>{mac}</code></td><td>{cnt}</td></tr>'
                    html += '</tbody></table>'

            # Probe failures: low response rate
            elif threat_name_raw == 'probe_failures':
                scanners = t.get('top_scanning_devices', {})
                if scanners:
                    html += '<h4 style="margin-top:14px">Top Devices Sending Unanswered Probe Requests</h4>'
                    html += '<table class="data-table"><thead><tr><th>Device MAC</th><th>Probe Requests</th></tr></thead><tbody>'
                    for mac, cnt in sorted(scanners.items(), key=lambda x: x[1], reverse=True)[:10]:
                        html += f'<tr><td><code>{mac}</code></td><td>{cnt}</td></tr>'
                    html += '</tbody></table>'

            # Unprotected traffic: WPA2/WPA3 context note
            elif threat_name_raw == 'unprotected_traffic':
                sec_ctx = t.get('security_context', '')
                null_excl = t.get('null_frames_excluded', 0)
                if sec_ctx:
                    html += f'<div class="remediation-box" style="background:#e8f5e9;border-left-color:#43a047"><p>&#128274; <strong>Security Context:</strong> {sec_ctx}</p></div>'
                if null_excl:
                    html += (
                        f'<p style="font-size:0.88em;color:#555;margin-top:6px">'
                        f'&#128221; Note: {null_excl:,} QoS-Null / Null data frames excluded from '
                        f'unprotected count — these are legitimately unencrypted by IEEE 802.11 spec '
                        f'(power-save management frames carrying no data).</p>'
                    )

            # IP connectivity failure: post-handshake no AP unicast
            elif threat_name_raw == 'ip_connectivity_failure':
                sessions = t.get('sessions', [])
                rc = t.get('root_cause_candidates', [])
                actions = t.get('recommended_actions', [])
                html += (
                    '<div style="background:#fff3e0;border-left:4px solid #e65100;'
                    'padding:12px 16px;border-radius:4px;margin-top:10px">'
                    '<p><strong>&#128268; 802.11 Association + WPA2 Handshake: '
                    '<span style="color:#2e7d32">SUCCEEDED</span></strong></p>'
                    '<p style="margin-top:4px"><strong>&#128683; IP Layer Connectivity: '
                    '<span style="color:#b71c1c">FAILED</span></strong> &mdash; '
                    'AP sent no unicast data after the completed handshake.</p>'
                    '</div>'
                )
                if sessions:
                    html += '<h4 style="margin-top:14px">Session Detail</h4>'
                    for si, sess in enumerate(sessions, 1):
                        html += (
                            f'<div style="border:1px solid #ddd;border-radius:4px;'
                            f'padding:10px 14px;margin-bottom:10px">'
                            f'<p><strong>Session {si}</strong> &mdash; '
                            f'Client: <code>{sess.get("client","")}</code> &nbsp;|&nbsp; '
                            f'AP BSSID: <code>{sess.get("ap_bssid","")}</code></p>'
                            f'<table class="data-table" style="margin-top:8px">'
                            f'<thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>'
                            f'<tr><td>EAPOL Msg4 Frame #</td><td>{sess.get("eapol_msg4_frame","")}</td></tr>'
                            f'<tr><td>Protected frames FROM client (post-Msg4)</td>'
                            f'<td>{sess.get("from_client_frames",0)}</td></tr>'
                            f'<tr style="background:#ffebee"><td>Protected frames TO client FROM AP (post-Msg4)</td>'
                            f'<td><strong>{sess.get("to_client_frames",0)}</strong></td></tr>'
                            f'<tr><td>QoS-Null power-save polls (client)</td>'
                            f'<td>{sess.get("null_polls",0)}</td></tr>'
                            f'<tr><td>Client multicast-only pattern</td>'
                            f'<td>{"&#10060; Yes (IPv6 DAD/RS/mDNS only)" if sess.get("multicast_only_client") else "No"}</td></tr>'
                            f'</tbody></table>'
                        )
                        obs = sess.get('observations', [])
                        if obs:
                            html += '<p style="margin-top:8px"><strong>Observations:</strong></p><ul style="margin:4px 0 0 18px">'
                            for o in obs:
                                html += f'<li style="margin-bottom:3px">{o}</li>'
                            html += '</ul>'
                        html += '</div>'
                if rc:
                    html += '<h4 style="margin-top:14px">&#128269; Likely Root Causes</h4><ul style="margin:4px 0 0 18px">'
                    for item in rc:
                        html += f'<li style="margin-bottom:4px">{item}</li>'
                    html += '</ul>'
                if actions:
                    html += '<h4 style="margin-top:12px">&#128736; Recommended Actions</h4><ol style="margin:4px 0 0 18px">'
                    for item in actions:
                        html += f'<li style="margin-bottom:4px">{item}</li>'
                    html += '</ol>'

            # ── WLAN-specific rich details end ──────────────────────────

            elif threat_name_raw == 'wpa3_sae_failures':
                sae_sessions  = t.get('sae_sessions', [])
                issues        = t.get('issues', [])
                fail_counts   = t.get('failure_counts', {})
                sae_advertised = t.get('sae_akm_advertised', False)
                owe_advertised = t.get('owe_advertised', False)

                # Header badges
                html += '<div style="display:flex;gap:10px;flex-wrap:wrap;margin:10px 0">'
                if sae_advertised:
                    html += (
                        '<span style="background:#e8f5e9;color:#1b5e20;padding:4px 12px;'
                        'border-radius:12px;font-weight:600;font-size:0.85em">&#128274; WPA3-SAE Advertised (AKM=8)</span>'
                    )
                if owe_advertised:
                    html += (
                        '<span style="background:#e3f2fd;color:#0d47a1;padding:4px 12px;'
                        'border-radius:12px;font-weight:600;font-size:0.85em">&#128274; OWE / Enhanced Open Advertised (AKM=18)</span>'
                    )
                html += '</div>'

                # WPA3 connection flow (SAE phases)
                if sae_sessions:
                    html += '<h4 style="margin-top:14px">&#9888; SAE Session Failures</h4>'
                    for si, sess in enumerate(sae_sessions, 1):
                        phase    = sess.get('failure_phase', '')
                        rc       = sess.get('root_cause', '')
                        remedy   = sess.get('remediation', '')
                        note     = sess.get('note', '')
                        client   = sess.get('client', '')
                        ap       = sess.get('ap_bssid', '')
                        status   = sess.get('status_code')
                        status_t = sess.get('status_text', '')

                        # Color-code by severity
                        border_color = '#b71c1c' if 'wrong' in rc.lower() or 'reject' in rc.lower() \
                                       else ('#e65100' if 'stall' in phase.lower() else '#f9a825')
                        bg_color = '#ffebee' if 'wrong' in rc.lower() or 'reject' in rc.lower() \
                                   else ('#fff8e1' if 'token' in phase.lower() else '#fff8e1')

                        html += (
                            f'<div style="background:{bg_color};border-left:4px solid {border_color};'
                            f'padding:14px 18px;border-radius:4px;margin:10px 0">'
                        )
                        html += f'<p style="margin:0 0 6px"><strong>Failure #{si} — {phase}</strong>'
                        if client:
                            html += f'&nbsp;&nbsp;<code style="font-size:0.85em">{client}</code> → <code style="font-size:0.85em">{ap}</code>'
                        html += '</p>'

                        if status is not None:
                            html += (
                                f'<p style="margin:0 0 6px">'
                                f'Status code: <strong>{status}</strong> — <em>{status_t}</em></p>'
                            )

                        # SAE Commit loop specific table
                        c_cnt = sess.get('commit_count', 0)
                        cf_cnt = sess.get('confirm_count', 0)
                        eapol1 = sess.get('eapol_msg1_count', 0)
                        eapol3 = sess.get('eapol_msg3_count', 0)
                        if c_cnt or eapol1:
                            html += (
                                '<table class="data-table" style="margin:8px 0">'
                                '<thead><tr><th>SAE/EAPOL Frame</th><th>Count</th><th>Expected</th></tr></thead><tbody>'
                            )
                            if c_cnt:
                                html += (
                                    f'<tr><td>SAE Commit (both sides)</td>'
                                    f'<td><strong>{c_cnt}</strong></td><td>2 (1 from each side)</td></tr>'
                                    f'<tr style="background:#ffebee"><td>SAE Confirm</td>'
                                    f'<td><strong style="color:#b71c1c">{cf_cnt}</strong></td><td>2 (1 from each side)</td></tr>'
                                )
                            if eapol1:
                                html += (
                                    f'<tr><td>EAPOL Msg1 (ANonce)</td>'
                                    f'<td><strong>{eapol1}</strong></td><td>1+</td></tr>'
                                    f'<tr style="background:#ffebee"><td>EAPOL Msg3 (PTK Install)</td>'
                                    f'<td><strong style="color:#b71c1c">{eapol3}</strong></td>'
                                    f'<td>1+ (never arrived)</td></tr>'
                                )
                            html += '</tbody></table>'

                        if rc:
                            html += (
                                f'<p style="margin:6px 0"><strong>&#128270; Root Cause:</strong> {rc}</p>'
                            )
                        if note:
                            html += f'<p style="margin:4px 0;color:#555;font-style:italic">{note}</p>'
                        if remedy:
                            html += (
                                '<div class="remediation-box" style="margin:8px 0 0">'
                                '<p><strong>&#128736; Remediation:</strong></p>'
                                f'<p style="margin:4px 0">{remedy}</p>'
                                '</div>'
                            )
                        html += '</div>'

                # Advisory notices
                if issues:
                    html += '<h4 style="margin-top:14px">&#128221; Advisory Notices</h4>'
                    for issue in issues:
                        html += (
                            '<div style="background:#e8f5e9;border-left:4px solid #43a047;'
                            'padding:10px 16px;border-radius:4px;margin:8px 0">'
                            f'<p style="margin:0">{issue}</p></div>'
                        )

                # Failure counts summary table
                if fail_counts:
                    html += '<h4 style="margin-top:14px">Failure Summary</h4>'
                    html += (
                        '<table class="data-table"><thead>'
                        '<tr><th>Failure Type</th><th>Count</th></tr>'
                        '</thead><tbody>'
                    )
                    for k, v in sorted(fail_counts.items(), key=lambda x: x[1], reverse=True):
                        html += f'<tr><td>{k}</td><td><strong>{v}</strong></td></tr>'
                    html += '</tbody></table>'

                # WPA3 spec reference note
                html += (
                    '<p style="font-size:0.82em;color:#777;margin-top:12px">'
                    '&#128214; WPA3-SAE (Simultaneous Authentication of Equals) uses the Dragonfly '
                    'key exchange (IEEE 802.11-2020 §12.4). Auth frames use algorithm=3 (SAE), '
                    'seq=1 = SAE Commit, seq=2 = SAE Confirm. After SAE, a standard 4-way EAPOL/PTK '
                    'handshake completes the session setup. Status codes 72–78 are SAE-specific.'
                    '</p>'
                )

            # ── Action Frame Issues ──────────────────────────────────────
            elif threat_name_raw == 'action_frame_issues':
                cat_dist = t.get('category_distribution', {})
                action_summary = t.get('summary', {})
                action_issues = t.get('issues', [])

                # Category distribution table
                if cat_dist:
                    html += '<h4 style="margin-top:14px">&#128225; Action Frame Category Distribution</h4>'
                    html += '<table class="data-table"><thead><tr><th>Category</th><th>Frame Count</th></tr></thead><tbody>'
                    for cat, cnt in sorted(cat_dist.items(), key=lambda x: x[1], reverse=True):
                        html += f'<tr><td>{cat}</td><td>{cnt:,}</td></tr>'
                    html += '</tbody></table>'

                # Key metrics from summary
                metric_keys = [
                    ('addba_requests', 'ADDBA Requests'),
                    ('addba_responses', 'ADDBA Responses'),
                    ('delba_frames', 'DELBA (Teardown)'),
                    ('neighbor_report_requests', '802.11k Neighbor Report Requests'),
                    ('neighbor_report_responses', '802.11k Neighbor Report Responses'),
                    ('ft_requests', '802.11r FT Requests'),
                    ('ft_responses', '802.11r FT Responses'),
                    ('sa_query_requests', '802.11w SA Query Requests'),
                    ('sa_query_responses', '802.11w SA Query Responses'),
                    ('btm_requests', '802.11v BTM Requests'),
                    ('btm_responses', '802.11v BTM Responses'),
                    ('vht_opmode_notifications', 'VHT Op Mode Notifications'),
                ]
                visible_metrics = [(label, action_summary[k]) for k, label in metric_keys if k in action_summary and action_summary[k] > 0]
                if visible_metrics:
                    html += '<h4 style="margin-top:14px">&#128202; Action Frame Metrics</h4>'
                    html += '<table class="data-table"><thead><tr><th>Metric</th><th>Count</th></tr></thead><tbody>'
                    for label, val in visible_metrics:
                        html += f'<tr><td>{label}</td><td>{val}</td></tr>'
                    html += '</tbody></table>'

                # Issues detail cards
                if action_issues and isinstance(action_issues, list):
                    html += '<h4 style="margin-top:14px">&#9888; Detected Issues</h4>'
                    ISSUE_COLORS = {'high': ('#ffebee', '#c62828'), 'medium': ('#fff8e1', '#e65100'),
                                    'low': ('#e8f5e9', '#2e7d32'), 'info': ('#e3f2fd', '#1565c0')}
                    for issue in action_issues:
                        if not isinstance(issue, dict):
                            continue
                        isev = issue.get('severity', 'info')
                        bg, border = ISSUE_COLORS.get(isev, ('#f5f5f5', '#757575'))
                        html += (
                            f'<div style="background:{bg};border-left:4px solid {border};'
                            f'padding:12px 18px;border-radius:4px;margin:10px 0">'
                            f'<p style="margin:0 0 6px"><span class="severity-badge {isev}">{isev.upper()}</span> '
                            f'<strong>{issue.get("category", "")}</strong> — {issue.get("issue", "")}</p>'
                        )
                        if issue.get('description'):
                            html += f'<p style="margin:4px 0;color:#333">{issue["description"]}</p>'
                        if issue.get('impact'):
                            html += f'<p style="margin:4px 0"><strong>Impact:</strong> {issue["impact"]}</p>'

                        # Steering details (BTM)
                        if issue.get('steering_aps'):
                            html += '<p style="margin:6px 0"><strong>Steering APs:</strong></p><ul style="margin:2px 0 0 18px">'
                            for ap, cnt in issue['steering_aps'].items():
                                html += f'<li><code>{ap}</code> — {cnt} BTM request(s)</li>'
                            html += '</ul>'
                        if issue.get('steered_clients'):
                            html += '<p style="margin:6px 0"><strong>Steered Clients:</strong></p><ul style="margin:2px 0 0 18px">'
                            for cl, cnt in issue['steered_clients'].items():
                                html += f'<li><code>{cl}</code> — {cnt} BTM request(s)</li>'
                            html += '</ul>'
                        if issue.get('affected_bssids'):
                            html += '<p style="margin:6px 0"><strong>Affected BSSIDs:</strong> '
                            html += ', '.join(f'<code>{b}</code>' for b in issue['affected_bssids']) + '</p>'

                        if issue.get('remediation'):
                            html += (
                                f'<div class="remediation-box" style="margin:8px 0 0">'
                                f'<p><strong>&#128736; Fix:</strong> {issue["remediation"]}</p></div>'
                            )
                        html += '</div>'

            # ── Control Frame Issues ─────────────────────────────────────
            elif threat_name_raw == 'control_frame_issues':
                ctrl_summary = t.get('control_frame_summary', {})
                ctrl_issues = t.get('issues', [])

                # Control frame counts table
                if ctrl_summary:
                    ctrl_metrics = [
                        ('rts_frames', 'RTS Frames'),
                        ('cts_frames', 'CTS Frames'),
                        ('ack_frames', 'ACK Frames'),
                        ('ps_poll_frames', 'PS-Poll Frames'),
                        ('block_ack_requests', 'Block Ack Requests (BAR)'),
                        ('block_ack_responses', 'Block Ack Responses (BA)'),
                        ('cf_end_frames', 'CF-End Frames'),
                    ]
                    html += '<h4 style="margin-top:14px">&#128225; Control Frame Summary</h4>'
                    html += '<table class="data-table"><thead><tr><th>Frame Type</th><th>Count</th></tr></thead><tbody>'
                    for key, label in ctrl_metrics:
                        val = ctrl_summary.get(key, 0)
                        html += f'<tr><td>{label}</td><td>{val:,}</td></tr>'
                    html += '</tbody></table>'

                    # RTS/CTS ratio
                    rts = ctrl_summary.get('rts_frames', 0)
                    cts = ctrl_summary.get('cts_frames', 0)
                    if rts > 0:
                        ratio = cts / rts
                        ratio_color = '#2e7d32' if ratio > 0.7 else ('#e65100' if ratio > 0.3 else '#b71c1c')
                        html += (
                            f'<div style="background:#f5f5f5;padding:10px 14px;border-radius:4px;margin:10px 0">'
                            f'<strong>RTS/CTS Ratio:</strong> '
                            f'<span style="color:{ratio_color};font-weight:bold;font-size:1.1em">'
                            f'{ratio*100:.1f}%</span> ({cts:,} CTS / {rts:,} RTS)'
                            f'{" — &#9989; Healthy" if ratio > 0.7 else (" — &#9888; Partial hidden node" if ratio > 0.3 else " — &#10060; Hidden node problem likely")}'
                            f'</div>'
                        )

                    # Top RTS senders
                    rts_senders = ctrl_summary.get('top_rts_senders', {})
                    if rts_senders:
                        html += '<h4 style="margin-top:14px">Top RTS Senders</h4>'
                        html += '<table class="data-table"><thead><tr><th>Device</th><th>RTS Frames</th></tr></thead><tbody>'
                        for dev, cnt in sorted(rts_senders.items(), key=lambda x: x[1], reverse=True):
                            html += f'<tr><td><code>{dev}</code></td><td>{cnt:,}</td></tr>'
                        html += '</tbody></table>'

                    # BA buffer size
                    if ctrl_summary.get('ba_buffer_size_max', 0) > 0:
                        html += (
                            f'<p style="margin:10px 0"><strong>Block Ack Buffer Size:</strong> '
                            f'min={ctrl_summary.get("ba_buffer_size_min",0)}, '
                            f'max={ctrl_summary.get("ba_buffer_size_max",0)}, '
                            f'mean={ctrl_summary.get("ba_buffer_size_mean",0)}</p>'
                        )

                    # Duration/NAV stats
                    if ctrl_summary.get('max_duration_us', 0) > 0:
                        html += (
                            f'<p style="margin:6px 0"><strong>NAV/Duration:</strong> '
                            f'avg={ctrl_summary.get("avg_duration_us",0):.0f} &mu;s, '
                            f'max={ctrl_summary.get("max_duration_us",0):,} &mu;s</p>'
                        )

                # Issues detail cards
                if ctrl_issues and isinstance(ctrl_issues, list):
                    html += '<h4 style="margin-top:14px">&#9888; Detected Issues</h4>'
                    ISSUE_COLORS = {'high': ('#ffebee', '#c62828'), 'medium': ('#fff8e1', '#e65100'),
                                    'low': ('#e8f5e9', '#2e7d32'), 'info': ('#e3f2fd', '#1565c0')}
                    for issue in ctrl_issues:
                        if not isinstance(issue, dict):
                            continue
                        isev = issue.get('severity', 'info')
                        bg, border = ISSUE_COLORS.get(isev, ('#f5f5f5', '#757575'))
                        html += (
                            f'<div style="background:{bg};border-left:4px solid {border};'
                            f'padding:12px 18px;border-radius:4px;margin:10px 0">'
                            f'<p style="margin:0 0 6px"><span class="severity-badge {isev}">{isev.upper()}</span> '
                            f'<strong>{issue.get("category", "")}</strong> — {issue.get("issue", "")}</p>'
                        )
                        if issue.get('description'):
                            html += f'<p style="margin:4px 0;color:#333">{issue["description"]}</p>'
                        if issue.get('impact'):
                            html += f'<p style="margin:4px 0"><strong>Impact:</strong> {issue["impact"]}</p>'

                        # Extra numeric context
                        for extra_key, extra_label in [
                            ('rts_count', 'RTS Frames'), ('cts_count', 'CTS Frames'),
                            ('cts_ratio', 'CTS/RTS Ratio'), ('count', 'Count'),
                            ('pspoll_to_data_ratio', 'PS-Poll / Data Ratio'),
                            ('ba_req_count', 'BA Requests'), ('ba_resp_count', 'BA Responses'),
                            ('max_buffer_size', 'Max BA Buffer'), ('max_duration_us', 'Max NAV (μs)'),
                        ]:
                            if extra_key in issue:
                                val = issue[extra_key]
                                if isinstance(val, float) and 'ratio' in extra_key.lower():
                                    val_str = f'{val*100:.1f}%'
                                elif isinstance(val, (int, float)):
                                    val_str = f'{val:,}' if isinstance(val, int) else f'{val:.1f}'
                                else:
                                    val_str = str(val)
                                html += f'<p style="margin:2px 0;font-size:0.9em"><strong>{extra_label}:</strong> {val_str}</p>'

                        # Top clients (PS-Poll)
                        top_clients = issue.get('top_clients', {})
                        if top_clients:
                            html += '<p style="margin:6px 0"><strong>Top PS-Poll Clients:</strong></p><ul style="margin:2px 0 0 18px">'
                            for cl, cnt in top_clients.items():
                                html += f'<li><code>{cl}</code> — {cnt:,} PS-Poll frames</li>'
                            html += '</ul>'

                        # NAV sources
                        sources = issue.get('sources', {})
                        if sources:
                            html += '<p style="margin:6px 0"><strong>Sources of Excessive NAV:</strong></p><ul style="margin:2px 0 0 18px">'
                            for src, cnt in sources.items():
                                html += f'<li><code>{src}</code> — {cnt:,} frame(s)</li>'
                            html += '</ul>'

                        if issue.get('remediation'):
                            html += (
                                f'<div class="remediation-box" style="margin:8px 0 0">'
                                f'<p><strong>&#128736; Fix:</strong> {issue["remediation"]}</p></div>'
                            )
                        html += '</div>'

            # ── Power Save / Null Data Issues ────────────────────────────
            elif threat_name_raw == 'power_save_issues':
                ps_summary = t.get('power_save_summary', {})
                ps_issues = t.get('issues', [])

                # Overview metrics
                if ps_summary:
                    null_total = ps_summary.get('total_null_frames', 0)
                    real_data = ps_summary.get('real_data_frames', 0)
                    null_ratio = ps_summary.get('null_to_data_ratio', 0)

                    ratio_color = '#2e7d32' if null_ratio < 0.3 else ('#e65100' if null_ratio < 0.6 else '#b71c1c')
                    html += (
                        '<div style="display:flex;gap:20px;flex-wrap:wrap;margin:14px 0">'
                        f'<div style="background:#f5f5f5;padding:12px 20px;border-radius:6px;text-align:center;min-width:150px">'
                        f'<div style="font-size:1.8em;font-weight:bold;color:#1565c0">{null_total:,}</div>'
                        f'<div style="font-size:0.85em;color:#555">Null / QoS-Null Frames</div></div>'
                        f'<div style="background:#f5f5f5;padding:12px 20px;border-radius:6px;text-align:center;min-width:150px">'
                        f'<div style="font-size:1.8em;font-weight:bold;color:#1565c0">{real_data:,}</div>'
                        f'<div style="font-size:0.85em;color:#555">Real Data Frames</div></div>'
                        f'<div style="background:#f5f5f5;padding:12px 20px;border-radius:6px;text-align:center;min-width:150px">'
                        f'<div style="font-size:1.8em;font-weight:bold;color:{ratio_color}">{null_ratio*100:.1f}%</div>'
                        f'<div style="font-size:0.85em;color:#555">Null-to-Data Ratio</div></div>'
                        '</div>'
                    )

                    # Per-client null frame table
                    top_null = ps_summary.get('top_null_senders', {})
                    if top_null:
                        html += '<h4 style="margin-top:14px">&#128100; Per-Client Null Frame Activity</h4>'
                        html += '<table class="data-table"><thead><tr><th>Client MAC</th><th>Null Frames Sent</th></tr></thead><tbody>'
                        for mac, cnt in sorted(top_null.items(), key=lambda x: x[1], reverse=True):
                            html += f'<tr><td><code>{mac}</code></td><td>{cnt:,}</td></tr>'
                        html += '</tbody></table>'

                    # Power management transitions
                    pm_trans = ps_summary.get('pm_transitions_by_client', {})
                    if pm_trans:
                        html += '<h4 style="margin-top:14px">&#9889; Power Management Transitions per Client</h4>'
                        html += ('<table class="data-table"><thead><tr>'
                                 '<th>Client MAC</th><th>PM Transitions</th>'
                                 '<th>Frames in PS</th><th>Frames Active</th><th>Total Frames</th>'
                                 '</tr></thead><tbody>')
                        for mac, stats in pm_trans.items():
                            trans = stats.get('transitions', 0)
                            in_ps = stats.get('frames_in_ps', 0)
                            active = stats.get('frames_active', 0)
                            total = stats.get('total_frames', 0)
                            rate = trans / max(total, 1)
                            rate_color = '#2e7d32' if rate < 0.1 else ('#e65100' if rate < 0.2 else '#b71c1c')
                            html += (
                                f'<tr><td><code>{mac}</code></td>'
                                f'<td><strong style="color:{rate_color}">{trans:,}</strong> ({rate*100:.1f}%)</td>'
                                f'<td>{in_ps:,}</td><td>{active:,}</td><td>{total:,}</td></tr>'
                            )
                        html += '</tbody></table>'

                # Issues detail cards
                if ps_issues and isinstance(ps_issues, list):
                    html += '<h4 style="margin-top:14px">&#9888; Detected Issues</h4>'
                    ISSUE_COLORS = {'high': ('#ffebee', '#c62828'), 'medium': ('#fff8e1', '#e65100'),
                                    'low': ('#e8f5e9', '#2e7d32'), 'info': ('#e3f2fd', '#1565c0')}
                    for issue in ps_issues:
                        if not isinstance(issue, dict):
                            continue
                        isev = issue.get('severity', 'info')
                        bg, border = ISSUE_COLORS.get(isev, ('#f5f5f5', '#757575'))
                        html += (
                            f'<div style="background:{bg};border-left:4px solid {border};'
                            f'padding:12px 18px;border-radius:4px;margin:10px 0">'
                            f'<p style="margin:0 0 6px"><span class="severity-badge {isev}">{isev.upper()}</span> '
                            f'<strong>{issue.get("category", "")}</strong> — {issue.get("issue", "")}</p>'
                        )
                        if issue.get('description'):
                            html += f'<p style="margin:4px 0;color:#333">{issue["description"]}</p>'
                        if issue.get('impact'):
                            html += f'<p style="margin:4px 0"><strong>Impact:</strong> {issue["impact"]}</p>'

                        # Client-specific details
                        if issue.get('client'):
                            html += (
                                f'<p style="margin:6px 0"><strong>Client:</strong> '
                                f'<code>{issue["client"]}</code></p>'
                            )
                        for extra_key, extra_label in [
                            ('null_polls', 'Null Poll Frames'),
                            ('ap_data_to_client', 'AP Data Frames to Client'),
                            ('null_count', 'Null Frames'),
                            ('data_count', 'Real Data Frames'),
                            ('null_ratio', 'Null Ratio'),
                            ('transitions', 'PM Transitions'),
                            ('transition_rate', 'Transition Rate'),
                            ('transitions_per_sec', 'Transitions/sec'),
                        ]:
                            if extra_key in issue:
                                val = issue[extra_key]
                                if val is None:
                                    continue
                                if isinstance(val, float) and ('ratio' in extra_key or 'rate' in extra_key):
                                    val_str = f'{val*100:.1f}%'
                                elif isinstance(val, (int, float)):
                                    val_str = f'{val:,}' if isinstance(val, int) else f'{val:.1f}'
                                else:
                                    val_str = str(val)
                                html += f'<p style="margin:2px 0;font-size:0.9em"><strong>{extra_label}:</strong> {val_str}</p>'

                        if issue.get('remediation'):
                            html += (
                                f'<div class="remediation-box" style="margin:8px 0 0">'
                                f'<p><strong>&#128736; Fix:</strong> {issue["remediation"]}</p></div>'
                            )
                        html += '</div>'

                # Reference note
                html += (
                    '<p style="font-size:0.82em;color:#777;margin-top:12px">'
                    '&#128214; Null (0x0024) and QoS-Null (0x002c) frames carry no payload and are '
                    'used for power-save signaling. The PM bit in the Frame Control field indicates '
                    'whether the STA is entering (1) or exiting (0) power-save mode. Excessive PS '
                    'cycling increases latency and wastes airtime. WMM-PS (U-APSD) is preferred '
                    'over legacy PS-Poll for efficient buffered frame delivery.</p>'
                )

            # ── Catch-all end marker ─────────────────────────────────────

            if remediation_steps:
                html += '<div class="remediation-box"><h4>&#128736; Recommended Remediation</h4><ol>'
                for step in remediation_steps:
                    html += f'<li>{step}</li>'
                html += '</ol></div>'

            html += '</div></div>'

        html += '</div>'
        return html

    def _generate_statistics(self, results: Dict[str, Any], proto_summaries: List) -> str:
        if not proto_summaries:
            return '<p>No statistics available</p>'

        html = ''
        for ps in proto_summaries:
            proto = ps['protocol']
            stats = ps.get('statistics', {})
            pkt_count = ps.get('total_packets', 0)
            if not stats:
                continue

            html += f'<div class="proto-section"><h3 class="proto-heading">{proto} Statistics <span class="pkt-count">({pkt_count:,} packets)</span></h3>'
            html += '<div class="stats-grid">'

            # Render all numeric stats
            stat_labels = {
                'syn_packets': 'SYN Packets', 'ack_packets': 'ACK Packets',
                'fin_packets': 'FIN Packets', 'rst_packets': 'RST Packets',
                'unique_source_ips': 'Unique Src IPs', 'unique_dest_ips': 'Unique Dst IPs',
                'unique_sources': 'Unique Sources', 'unique_destinations': 'Unique Destinations',
                'unique_dest_ports': 'Unique Dst Ports', 'unique_clients': 'Unique Clients',
                'unique_servers': 'Unique Servers', 'unique_domains': 'Unique Domains',
                'avg_packet_size': 'Avg Pkt Size', 'min_packet_size': 'Min Pkt Size',
                'max_packet_size': 'Max Pkt Size', 'total_bytes': 'Total Bytes',
                'total_queries': 'DNS Queries', 'total_responses': 'DNS Responses',
                'total_requests': 'HTTP Requests', 'unique_uris': 'Unique URIs',
                'total_udp_packets': 'Total UDP Pkts', 'total_icmp_packets': 'Total ICMP Pkts',
                'total_connections': 'TLS Connections', 'potential_handshakes': 'TLS Handshakes',
                'echo_requests': 'Echo Requests', 'echo_replies': 'Echo Replies',
                'dest_unreachable': 'Dest Unreachable', 'time_exceeded': 'Time Exceeded',
                'nxdomain_count': 'NXDOMAIN Count', 'packet_size_variance': 'Size Variance',
                # WLAN stats
                'total_wlan_frames': 'Total WLAN Frames',
                'management_frames': 'Management Frames', 'control_frames': 'Control Frames',
                'data_frames': 'Data Frames', 'unique_bssids': 'Unique BSSIDs',
                'unique_ssids': 'Unique SSIDs', 'avg_signal_dbm': 'Avg Signal (dBm)',
                'min_signal_dbm': 'Min Signal (dBm)', 'max_signal_dbm': 'Max Signal (dBm)',
                'retry_rate': 'Retry Rate (%)', 'encrypted_frames': 'Encrypted Frames',
                'unencrypted_frames': 'Unencrypted Frames',
                # DHCP stats
                'dhcpv4_packets': 'DHCPv4 Packets', 'dhcpv6_packets': 'DHCPv6 Packets',
                'total_dhcp_packets': 'Total DHCP Packets',
                # TCP enhanced stats
                'push_packets': 'PSH Packets', 'syn_only_packets': 'SYN-Only',
                'syn_ack_packets': 'SYN-ACK', 'zero_window_count': 'Zero Window Pkts',
                'avg_window_size': 'Avg Window Size', 'min_window_size': 'Min Window Size',
                'max_window_size': 'Max Window Size',
                # HTTPS enhanced stats
                'tls_rst_packets': 'TLS RST Packets', 'tls_fin_packets': 'TLS FIN Packets',
                'tls_syn_packets': 'TLS SYN Packets',
            }

            for key, label in stat_labels.items():
                if key in stats:
                    value = stats[key]
                    if isinstance(value, float):
                        value_str = f"{value:,.2f}"
                    elif isinstance(value, int):
                        value_str = f"{value:,}"
                    else:
                        value_str = str(value)
                    html += f'''
                    <div class="stat-item">
                        <div class="stat-label">{label}</div>
                        <div class="stat-value">{value_str}</div>
                    </div>'''

            html += '</div>'

            # NXDOMAIN rate
            nxr = stats.get('nxdomain_rate')
            if nxr is not None:
                html += f'<p style="margin-top:5px"><strong>NXDOMAIN Rate:</strong> {nxr*100:.1f}%</p>'

            # Methods / status codes
            methods = stats.get('methods', {})
            if methods:
                html += '<h4 style="margin-top:15px">HTTP Methods</h4><table class="data-table"><thead><tr><th>Method</th><th>Count</th></tr></thead><tbody>'
                for m, c in sorted(methods.items(), key=lambda x: x[1], reverse=True):
                    html += f'<tr><td>{m}</td><td>{c:,}</td></tr>'
                html += '</tbody></table>'

            status_codes = stats.get('status_codes', {})
            if status_codes:
                html += '<h4 style="margin-top:15px">HTTP Status Codes</h4><table class="data-table"><thead><tr><th>Code</th><th>Count</th></tr></thead><tbody>'
                for sc, c in sorted(status_codes.items(), key=lambda x: x[1], reverse=True):
                    html += f'<tr><td>{sc}</td><td>{c:,}</td></tr>'
                html += '</tbody></table>'

            # ICMP types
            icmp_types = stats.get('icmp_types', {})
            if icmp_types:
                html += '<h4 style="margin-top:15px">ICMP Types</h4><table class="data-table"><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>'
                for it, c in sorted(icmp_types.items(), key=lambda x: x[1], reverse=True):
                    html += f'<tr><td>{it}</td><td>{c:,}</td></tr>'
                html += '</tbody></table>'

            # WLAN frame type distribution
            frame_types = stats.get('frame_type_distribution', {})
            if frame_types:
                html += '<h4 style="margin-top:15px">Frame Type Distribution</h4><table class="data-table"><thead><tr><th>Frame Type</th><th>Count</th></tr></thead><tbody>'
                for ft, c in sorted(frame_types.items(), key=lambda x: x[1], reverse=True):
                    html += f'<tr><td>{ft}</td><td>{c:,}</td></tr>'
                html += '</tbody></table>'

            # WLAN channel distribution
            channels = stats.get('channel_distribution', {})
            if channels:
                html += '<h4 style="margin-top:15px">Channel Distribution</h4><table class="data-table"><thead><tr><th>Channel</th><th>Frames</th></tr></thead><tbody>'
                for ch, c in sorted(channels.items(), key=lambda x: x[1], reverse=True):
                    html += f'<tr><td>{ch}</td><td>{c:,}</td></tr>'
                html += '</tbody></table>'

            # WLAN detected SSIDs
            ssids = stats.get('detected_ssids', {})
            if ssids:
                html += '<h4 style="margin-top:15px">Detected SSIDs</h4><table class="data-table"><thead><tr><th>SSID</th><th>Beacons/Probes</th></tr></thead><tbody>'
                for ssid, c in sorted(ssids.items(), key=lambda x: x[1], reverse=True)[:20]:
                    html += f'<tr><td>{ssid}</td><td>{c:,}</td></tr>'
                html += '</tbody></table>'

            # WLAN PHY distribution
            phy_dist = stats.get('phy_distribution', {})
            if phy_dist:
                html += '<h4 style="margin-top:15px">PHY Type Distribution</h4><table class="data-table"><thead><tr><th>PHY</th><th>Frames</th></tr></thead><tbody>'
                for p, c in sorted(phy_dist.items(), key=lambda x: x[1], reverse=True):
                    html += f'<tr><td>{p}</td><td>{c:,}</td></tr>'
                html += '</tbody></table>'

            # DHCP message types
            msg_types = stats.get('message_types', {})
            if msg_types:
                html += '<h4 style="margin-top:15px">DHCP Message Types</h4><table class="data-table"><thead><tr><th>Message Type</th><th>Count</th></tr></thead><tbody>'
                for mt, c in sorted(msg_types.items(), key=lambda x: x[1], reverse=True):
                    html += f'<tr><td>{mt}</td><td>{c:,}</td></tr>'
                html += '</tbody></table>'

            # DHCP servers
            dhcp_servers = stats.get('dhcp_servers', {})
            if dhcp_servers:
                html += '<h4 style="margin-top:15px">DHCP Servers</h4><table class="data-table"><thead><tr><th>Server IP</th><th>Responses</th></tr></thead><tbody>'
                for srv, c in sorted(dhcp_servers.items(), key=lambda x: x[1], reverse=True):
                    html += f'<tr><td>{srv}</td><td>{c:,}</td></tr>'
                html += '</tbody></table>'

            # DHCP hostnames
            hostnames = stats.get('hostnames', {})
            if hostnames:
                html += '<h4 style="margin-top:15px">Client Hostnames</h4><table class="data-table"><thead><tr><th>Hostname</th><th>Count</th></tr></thead><tbody>'
                for hn, c in sorted(hostnames.items(), key=lambda x: x[1], reverse=True)[:15]:
                    html += f'<tr><td>{hn}</td><td>{c:,}</td></tr>'
                html += '</tbody></table>'

            # Top ports
            top_ports = stats.get('top_ports', {})
            if top_ports:
                html += '<h4 style="margin-top:15px">Top Destination Ports</h4>'
                html += '<table class="data-table"><thead><tr><th>Port</th><th>Packets</th><th>% of Protocol</th></tr></thead><tbody>'
                for port, count in sorted(top_ports.items(), key=lambda x: x[1], reverse=True)[:10]:
                    pct = (count / pkt_count * 100) if pkt_count else 0
                    html += f'<tr><td>{port}</td><td>{count:,}</td><td>{pct:.1f}%</td></tr>'
                html += '</tbody></table>'

            # Top domains
            top_domains = stats.get('top_domains', {})
            if top_domains:
                html += '<h4 style="margin-top:15px">Top Queried Domains</h4>'
                html += '<table class="data-table"><thead><tr><th>Domain</th><th>Queries</th></tr></thead><tbody>'
                for dom, cnt in sorted(top_domains.items(), key=lambda x: x[1], reverse=True)[:10]:
                    html += f'<tr><td>{dom}</td><td>{cnt:,}</td></tr>'
                html += '</tbody></table>'

            html += '</div>'

            # --- WLAN Connection Events (rendered within protocol section) ---
            proto_data = results.get('protocol_analysis', {}).get(proto, {})
            conn_events = proto_data.get('connection_events', {})
            if conn_events:
                html += '<h4 style="margin-top:20px; border-bottom:2px solid #667eea; padding-bottom:5px">Connection Lifecycle Events</h4>'
                html += '<div class="stats-grid">'
                event_labels = {
                    'association_requests': 'Association Requests',
                    'association_responses': 'Association Responses',
                    'associating_clients': 'Associating Clients',
                    'reassociation_requests': 'Reassociation Requests',
                    'reassociation_responses': 'Reassociation Responses',
                    'roaming_clients': 'Roaming Clients',
                    'authentication_frames': 'Authentication Frames',
                    'auth_clients': 'Auth Clients',
                    'deauthentication_frames': 'Deauthentication Frames',
                    'disassociation_frames': 'Disassociation Frames',
                    'total_disconnections': 'Total Disconnections',
                    'channel_switch_clients': 'Channel Switch Clients',
                    'band_switch_clients': 'Band Switch Clients',
                }
                for key, label in event_labels.items():
                    val = conn_events.get(key)
                    if val is not None:
                        html += f'<div class="stat-item"><div class="stat-label">{label}</div><div class="stat-value">{val:,}</div></div>'
                html += '</div>'

                # Roaming details table
                roaming = conn_events.get('roaming_details', {})
                if roaming:
                    html += '<h4 style="margin-top:15px">Roaming Clients (Reassociation to Different BSSIDs)</h4>'
                    html += '<table class="data-table"><thead><tr><th>Client MAC</th><th>BSSIDs</th></tr></thead><tbody>'
                    for client, bssids in list(roaming.items())[:10]:
                        html += f'<tr><td>{client}</td><td>{", ".join(bssids)}</td></tr>'
                    html += '</tbody></table>'

                # Channel switch details
                ch_switches = conn_events.get('channel_switch_details', {})
                if ch_switches:
                    html += '<h4 style="margin-top:15px">Channel Switching Clients</h4>'
                    html += '<table class="data-table"><thead><tr><th>Client MAC</th><th>Channels</th></tr></thead><tbody>'
                    for client, channels in list(ch_switches.items())[:10]:
                        html += f'<tr><td>{client}</td><td>{", ".join(str(c) for c in channels)}</td></tr>'
                    html += '</tbody></table>'

                # Band switch details
                band_switches = conn_events.get('band_switch_details', {})
                if band_switches:
                    html += '<h4 style="margin-top:15px">Band Switching Clients (Dual-Band)</h4>'
                    html += '<table class="data-table"><thead><tr><th>Client MAC</th><th>Bands</th></tr></thead><tbody>'
                    for client, bands in list(band_switches.items())[:10]:
                        html += f'<tr><td>{client}</td><td>{", ".join(bands)}</td></tr>'
                    html += '</tbody></table>'

                # Disconnect sources
                disc_sources = conn_events.get('disconnect_sources', {})
                if disc_sources:
                    html += '<h4 style="margin-top:15px">Disconnection Sources</h4>'
                    html += '<table class="data-table"><thead><tr><th>Source MAC</th><th>Disconnections</th></tr></thead><tbody>'
                    for src, cnt in sorted(disc_sources.items(), key=lambda x: x[1], reverse=True)[:10]:
                        html += f'<tr><td>{src}</td><td>{cnt:,}</td></tr>'
                    html += '</tbody></table>'

        return html if html else '<p>No statistics available</p>'

    def _generate_threats(self, all_threats: List[Dict[str, Any]]) -> str:
        """Generate a concise threat overview table (details are in Critical Issues)."""
        if not all_threats:
            return '<div class="alert alert-success">&#10003; No threats detected</div>'

        html = '<table class="data-table"><thead><tr>'
        html += '<th>#</th><th>Protocol</th><th>Threat</th><th>Severity</th><th>Summary</th>'
        html += '</tr></thead><tbody>'

        for i, t in enumerate(all_threats, 1):
            severity = t.get('severity', 'info').upper()
            sev_class = severity.lower()
            name = t.get('name', '').replace('_', ' ').title()
            proto = t.get('protocol', '')
            msg = t.get('message', '')
            html += f'<tr><td>{i}</td><td>{proto}</td><td>{name}</td>'
            html += f'<td><span class="severity-badge {sev_class}">{severity}</span></td>'
            html += f'<td>{msg}</td></tr>'

        html += '</tbody></table>'
        return html

    # ------------------------------------------------------------------
    #  Charts
    # ------------------------------------------------------------------

    def _generate_charts(self, results: Dict[str, Any], proto_summaries: List, all_threats: List) -> str:
        if not MATPLOTLIB_AVAILABLE:
            return '<p>Matplotlib not available. Install it to see charts.</p>'

        html = '<div class="charts-section">'

        # 1. Protocol distribution (from top-level 'protocols')
        proto_dist = results.get('protocols', {})
        if proto_dist:
            chart_data = self._create_protocol_dist_chart(proto_dist)
            if chart_data:
                html += f'<div class="chart-container"><h3>Protocol Distribution</h3><img src="data:image/png;base64,{chart_data}" alt="Protocol Distribution"/></div>'

        # 2. Per-analyzer packet counts
        if proto_summaries:
            chart_data = self._create_analyzer_packets_chart(proto_summaries)
            if chart_data:
                html += f'<div class="chart-container"><h3>Packets per Analyzer</h3><img src="data:image/png;base64,{chart_data}" alt="Analyzer Packets"/></div>'

        # 3. Threat severity pie
        if all_threats:
            chart_data = self._create_threat_severity_chart(all_threats)
            if chart_data:
                html += f'<div class="chart-container"><h3>Threat Severity Breakdown</h3><img src="data:image/png;base64,{chart_data}" alt="Threat Severity"/></div>'

        # 4. Top ports across all protocols
        combined_ports: Dict[str, int] = {}
        for ps in proto_summaries:
            for port, cnt in ps.get('statistics', {}).get('top_ports', {}).items():
                combined_ports[str(port)] = combined_ports.get(str(port), 0) + cnt
        if combined_ports:
            chart_data = self._create_port_chart(combined_ports)
            if chart_data:
                html += f'<div class="chart-container"><h3>Top Destination Ports (All Protocols)</h3><img src="data:image/png;base64,{chart_data}" alt="Port Distribution"/></div>'

        html += '</div>'
        return html

    def _fig_to_base64(self, fig) -> str:
        buffer = BytesIO()
        fig.savefig(buffer, format='png', dpi=120, bbox_inches='tight', facecolor='white')
        buffer.seek(0)
        data = base64.b64encode(buffer.read()).decode()
        plt.close(fig)
        return data

    def _create_protocol_dist_chart(self, proto_dist: Dict[str, int]) -> str:
        try:
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
            sorted_items = sorted(proto_dist.items(), key=lambda x: x[1], reverse=True)[:10]
            names = [x[0] for x in sorted_items]
            counts = [x[1] for x in sorted_items]

            colors = sns.color_palette('Set2', len(names))
            ax1.barh(names[::-1], counts[::-1], color=colors)
            ax1.set_xlabel('Packet Count')
            ax1.set_title('Top Protocols by Packet Count', fontweight='bold')
            ax1.grid(axis='x', alpha=0.3)
            for i, v in enumerate(counts[::-1]):
                ax1.text(v + max(counts)*0.01, i, f'{v:,}', va='center', fontsize=9)

            top5 = sorted_items[:5]
            ax2.pie([x[1] for x in top5], labels=[x[0] for x in top5],
                    autopct='%1.1f%%', startangle=90, colors=sns.color_palette('Set2', 5))
            ax2.set_title('Top 5 Protocol Share', fontweight='bold')

            fig.tight_layout()
            return self._fig_to_base64(fig)
        except Exception as e:
            logger.error(f"Error creating protocol chart: {e}")
            return ""

    def _create_analyzer_packets_chart(self, proto_summaries: List) -> str:
        try:
            fig, ax = plt.subplots(figsize=(10, 5))
            names = [ps['protocol'] for ps in proto_summaries]
            counts = [ps['total_packets'] for ps in proto_summaries]
            bar_colors = sns.color_palette('muted', len(names))
            bars = ax.bar(names, counts, color=bar_colors)
            ax.set_ylabel('Packets Analyzed')
            ax.set_title('Packets Analyzed per Protocol', fontweight='bold')
            ax.grid(axis='y', alpha=0.3)
            for bar, c in zip(bars, counts):
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(counts)*0.01,
                        f'{c:,}', ha='center', va='bottom', fontsize=9)
            fig.tight_layout()
            return self._fig_to_base64(fig)
        except Exception as e:
            logger.error(f"Error creating analyzer packets chart: {e}")
            return ""

    def _create_port_chart(self, top_ports: Dict[str, int]) -> str:
        try:
            fig, ax = plt.subplots(figsize=(10, 6))
            sorted_items = sorted(top_ports.items(), key=lambda x: x[1], reverse=True)[:10]
            ports = [str(x[0]) for x in sorted_items]
            counts = [x[1] for x in sorted_items]

            ax.barh(ports[::-1], counts[::-1], color='steelblue')
            ax.set_xlabel('Packet Count')
            ax.set_title('Top 10 Destination Ports', fontweight='bold')
            ax.grid(axis='x', alpha=0.3)
            for i, v in enumerate(counts[::-1]):
                ax.text(v + max(counts)*0.01, i, f'{v:,}', va='center', fontsize=9)

            fig.tight_layout()
            return self._fig_to_base64(fig)
        except Exception as e:
            logger.error(f"Error creating port chart: {e}")
            return ""

    def _create_threat_severity_chart(self, all_threats: List) -> str:
        try:
            severity_counts: Dict[str, int] = {}
            for t in all_threats:
                s = t.get('severity', 'info').lower()
                severity_counts[s] = severity_counts.get(s, 0) + 1

            filtered = {k: v for k, v in severity_counts.items() if v > 0}
            if not filtered:
                return ""

            fig, ax = plt.subplots(figsize=(8, 8))
            colors_map = {'critical': '#dc3545', 'high': '#fd7e14', 'medium': '#ffc107', 'low': '#28a745', 'info': '#6c757d'}
            labels = list(filtered.keys())
            sizes = list(filtered.values())
            pie_colors = [colors_map.get(l, '#999') for l in labels]

            wedges, texts, autotexts = ax.pie(
                sizes, labels=[f"{l.upper()} ({v})" for l, v in zip(labels, sizes)],
                autopct='%1.1f%%', colors=pie_colors, startangle=90,
                textprops={'fontsize': 11})
            for at in autotexts:
                at.set_fontweight('bold')
            ax.set_title('Threat Severity Distribution', fontweight='bold', fontsize=14)

            fig.tight_layout()
            return self._fig_to_base64(fig)
        except Exception as e:
            logger.error(f"Error creating severity chart: {e}")
            return ""

    # ------------------------------------------------------------------
    #  HTML Template
    # ------------------------------------------------------------------

    def _get_template(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{TITLE}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6; color: #333; background: #f5f5f5;
        }

        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }

        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 30px; border-radius: 10px;
            margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        header h1 { font-size: 2.5em; margin-bottom: 10px; }

        .report-meta {
            display: flex; gap: 30px; font-size: 0.95em; opacity: 0.9; flex-wrap: wrap;
        }
        .report-meta div { display: flex; align-items: center; gap: 8px; }

        section {
            background: white; padding: 30px; margin-bottom: 20px;
            border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        section h2 {
            font-size: 1.8em; margin-bottom: 20px; color: #667eea;
            border-bottom: 3px solid #667eea; padding-bottom: 10px;
        }

        /* Summary cards */
        .summary-cards {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px; margin-bottom: 20px;
        }
        .summary-card {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 25px; border-radius: 10px; text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); transition: transform 0.2s;
        }
        .summary-card:hover { transform: translateY(-5px); }
        .card-label {
            font-size: 0.85em; color: #666; text-transform: uppercase;
            letter-spacing: 1px; margin-bottom: 8px;
        }
        .card-value { font-size: 2.2em; font-weight: bold; color: #333; }
        .card-value.critical { color: #dc3545; }
        .card-value.warning  { color: #fd7e14; }
        .card-value.high     { color: #dc3545; }
        .card-value.medium   { color: #e6a800; }
        .card-value.low      { color: #28a745; }

        /* Alerts */
        .alert { padding: 15px 20px; border-radius: 5px; margin-bottom: 20px; }
        .alert-success { background: #d4edda; color: #155724; border-left: 4px solid #28a745; }

        /* Issue / threat cards */
        .critical-issues-list, .threats-list { display: flex; flex-direction: column; gap: 20px; }
        .issue-card, .threat-card {
            border-left: 5px solid #ffc107; border-radius: 5px;
            padding: 20px; background: #f8f9fa;
        }
        .issue-card.critical, .threat-card.critical { border-left-color: #dc3545; background: #fff5f5; }
        .issue-card.high, .threat-card.high         { border-left-color: #fd7e14; background: #fff8f0; }
        .issue-card.medium, .threat-card.medium      { border-left-color: #ffc107; background: #fffdf0; }
        .issue-card.low, .threat-card.low            { border-left-color: #28a745; background: #f0fff0; }
        .issue-card.info, .threat-card.info          { border-left-color: #6c757d; background: #f8f9fa; }

        .issue-header, .threat-header {
            display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap;
        }
        .severity-badge {
            padding: 4px 12px; border-radius: 20px; font-size: 0.75em;
            font-weight: bold; text-transform: uppercase; letter-spacing: 1px;
            display: inline-block;
        }
        .severity-badge.critical { background: #dc3545; color: white; }
        .severity-badge.high     { background: #fd7e14; color: white; }
        .severity-badge.medium   { background: #ffc107; color: #333; }
        .severity-badge.low      { background: #28a745; color: white; }
        .severity-badge.info     { background: #6c757d; color: white; }

        .protocol-badge {
            padding: 4px 10px; border-radius: 20px; font-size: 0.75em;
            font-weight: bold; background: #667eea; color: white;
            letter-spacing: 1px;
        }

        .issue-card h3, .threat-card h3 { margin: 0; font-size: 1.2em; color: #333; }
        .issue-body, .threat-body { color: #555; }
        .threat-message { font-size: 1.05em; }

        .issue-details {
            margin-top: 15px; padding: 15px; background: white;
            border-radius: 5px; border: 1px solid #e9ecef;
        }
        .detail-item { padding: 5px 0; border-bottom: 1px solid #eee; }
        .detail-item:last-child { border-bottom: none; }

        /* Remediation box */
        .remediation-box {
            margin-top: 15px; padding: 15px 20px; background: #e8f4fd;
            border-left: 4px solid #2196F3; border-radius: 5px;
        }
        .remediation-box h4 { color: #1565C0; margin-bottom: 8px; }
        .remediation-box ol { margin-left: 20px; }
        .remediation-box li { margin-bottom: 4px; }

        /* Protocol sections */
        .proto-section {
            margin-bottom: 30px; padding-bottom: 20px;
            border-bottom: 2px solid #e9ecef;
        }
        .proto-section:last-child { border-bottom: none; }
        .proto-heading {
            font-size: 1.3em; color: #764ba2; margin-bottom: 12px;
        }
        .pkt-count { font-size: 0.75em; color: #888; font-weight: normal; }

        /* Stats grid */
        .stats-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px; margin-bottom: 20px;
        }
        .stat-item {
            padding: 12px 15px; background: #f8f9fa; border-radius: 5px;
            border-left: 3px solid #667eea;
        }
        .stat-label { font-size: 0.8em; color: #666; margin-bottom: 3px; }
        .stat-value { font-size: 1.3em; font-weight: bold; color: #333; }

        /* Tables */
        .data-table { width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 10px; }
        .data-table th {
            background: #667eea; color: white; padding: 10px 12px;
            text-align: left; font-weight: 600; font-size: 0.9em;
        }
        .data-table td { padding: 8px 12px; border-bottom: 1px solid #eee; font-size: 0.92em; }
        .data-table tr:hover { background: #f8f9fa; }
        .data-table code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }

        /* Charts */
        .charts-section {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
        }
        .chart-container { text-align: center; }
        .chart-container h3 { margin-bottom: 15px; color: #667eea; }
        .chart-container img {
            max-width: 100%; border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        footer { text-align: center; padding: 20px; color: #666; font-size: 0.9em; }

        @media print {
            body { background: white; }
            section { box-shadow: none; border: 1px solid #ddd; page-break-inside: avoid; }
            .summary-card:hover { transform: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>&#128737; {{TITLE}}</h1>
            <div class="report-meta">
                <div>&#128193; File: {{PCAP_FILE}}</div>
                <div>&#128197; Date: {{ANALYSIS_DATE}}</div>
                <div>&#128269; Protocol: {{PROTOCOL}}</div>
            </div>
        </header>

        <section>
            <h2>&#128202; Executive Summary</h2>
            {{SUMMARY}}
        </section>

        <section>
            <h2>&#128680; Critical Issues &amp; Remediation</h2>
            {{CRITICAL_ISSUES}}
        </section>

        <section>
            <h2>&#9888;&#65039; Threat Overview</h2>
            {{THREATS}}
        </section>

        <section>
            <h2>&#128200; Traffic Statistics (Per Protocol)</h2>
            {{STATISTICS}}
        </section>

        <section>
            <h2>&#128201; Visualizations</h2>
            {{CHARTS}}
        </section>

        <footer>
            <p>Generated by AI-Wireshark-Analyzer | Network Security Analysis Tool</p>
            <p>Report generated on {{ANALYSIS_DATE}}</p>
        </footer>
    </div>
</body>
</html>"""
