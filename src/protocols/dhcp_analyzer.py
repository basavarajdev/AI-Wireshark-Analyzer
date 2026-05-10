"""
DHCP Protocol Analyzer
Detects DHCP-specific issues and security threats
"""

import argparse
import pyshark
import pandas as pd
from pathlib import Path
from loguru import logger
import yaml
import json
from typing import Dict, List, Any

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))


# DHCP message types
DHCP_MSG_TYPES = {
    '1': 'DHCP Discover',
    '2': 'DHCP Offer',
    '3': 'DHCP Request',
    '4': 'DHCP Decline',
    '5': 'DHCP ACK',
    '6': 'DHCP NAK',
    '7': 'DHCP Release',
    '8': 'DHCP Inform',
}


class DHCPAnalyzer:
    """Analyze DHCP traffic for critical issues"""

    def __init__(self, config_path: str = "config/default.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.dhcp_config = self.config.get('protocols', {}).get('dhcp', {})

    def analyze(self, pcap_file: str, display_filter: str = None) -> Dict[str, Any]:
        """
        Analyze DHCP traffic from PCAP file.

        Args:
            pcap_file: Path to PCAP file
            display_filter: Optional additional Wireshark display filter

        Returns:
            Dictionary with DHCP analysis results
        """
        logger.info(f"Analyzing DHCP traffic in {pcap_file}")

        if not Path(pcap_file).exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

        packets = self._parse_dhcp_packets(pcap_file, display_filter=display_filter)

        if not packets:
            logger.warning("No DHCP packets found")
            return {"error": "No DHCP packets found"}

        df = pd.DataFrame(packets)
        logger.info(f"Parsed {len(df)} DHCP packets")

        results = {
            "total_packets": len(df),
            "statistics": self._calculate_statistics(df),
            "threats": self._detect_threats(df),
        }

        return results

    def _parse_dhcp_packets(self, pcap_file: str, display_filter: str = None) -> List[Dict]:
        """Parse DHCP packets using PyShark."""
        packets_data = []
        dhcp_base = 'dhcp || bootp || dhcpv6'
        dhcp_filter = f'({dhcp_base}) && ({display_filter})' if display_filter else dhcp_base

        try:
            capture = pyshark.FileCapture(
                pcap_file,
                display_filter=dhcp_filter,
                use_json=True,
                include_raw=True,
            )

            for i, pkt in enumerate(capture):
                try:
                    features = self._extract_dhcp_features(pkt)
                    if features:
                        packets_data.append(features)
                except Exception as e:
                    logger.debug(f"Error parsing DHCP packet {i}: {e}")
                    continue

            capture.close()
        except Exception as e:
            logger.error(f"Error reading PCAP for DHCP analysis: {e}")
            raise

        return packets_data

    def _extract_dhcp_features(self, pkt) -> Dict:
        """Extract DHCP features from a packet."""
        features: Dict[str, Any] = {}

        try:
            features['timestamp'] = float(pkt.sniff_timestamp)
        except Exception:
            features['timestamp'] = 0.0

        try:
            features['length'] = int(pkt.length)
        except Exception:
            features['length'] = 0

        # Determine if DHCPv4 or DHCPv6
        features['dhcp_version'] = 'v4'
        dhcp_layer = None

        for layer in pkt.layers:
            if layer.layer_name == 'dhcp':
                dhcp_layer = layer
                features['dhcp_version'] = 'v4'
                break
            elif layer.layer_name == 'dhcpv6':
                dhcp_layer = layer
                features['dhcp_version'] = 'v6'
                break

        if dhcp_layer is None:
            return {}

        # Source/dest IP
        if hasattr(pkt, 'ip'):
            features['src_ip'] = getattr(pkt.ip, 'src', None)
            features['dst_ip'] = getattr(pkt.ip, 'dst', None)
        elif hasattr(pkt, 'ipv6'):
            features['src_ip'] = getattr(pkt.ipv6, 'src', None)
            features['dst_ip'] = getattr(pkt.ipv6, 'dst', None)
        else:
            features['src_ip'] = None
            features['dst_ip'] = None

        # Source MAC (from Ethernet or WLAN)
        features['src_mac'] = None
        if hasattr(pkt, 'eth'):
            features['src_mac'] = getattr(pkt.eth, 'src', None)
        elif hasattr(pkt, 'wlan'):
            features['src_mac'] = getattr(pkt.wlan, 'sa', None)

        # DHCPv4 specifics
        if features['dhcp_version'] == 'v4':
            try:
                features['msg_type'] = getattr(dhcp_layer, 'option_dhcp', None)
            except Exception:
                features['msg_type'] = None

            try:
                features['client_mac'] = getattr(dhcp_layer, 'hw_mac_addr', None)
            except Exception:
                features['client_mac'] = None

            try:
                features['requested_ip'] = getattr(dhcp_layer, 'option_requested_ip_address', None)
            except Exception:
                features['requested_ip'] = None

            try:
                features['server_ip'] = getattr(dhcp_layer, 'option_dhcp_server_id', None)
            except Exception:
                features['server_ip'] = None

            try:
                features['hostname'] = getattr(dhcp_layer, 'option_hostname', None)
            except Exception:
                features['hostname'] = None

        # DHCPv6 specifics
        elif features['dhcp_version'] == 'v6':
            try:
                features['msg_type'] = getattr(dhcp_layer, 'msgtype', None)
            except Exception:
                features['msg_type'] = None

            features['client_mac'] = features.get('src_mac')
            features['requested_ip'] = None
            features['server_ip'] = None
            features['hostname'] = None

        return features

    # ------------------------------------------------------------------
    #  Statistics
    # ------------------------------------------------------------------

    def _calculate_statistics(self, df: pd.DataFrame) -> Dict:
        stats: Dict[str, Any] = {}

        stats['total_dhcp_packets'] = len(df)

        # Version distribution
        if 'dhcp_version' in df.columns:
            ver_counts = df['dhcp_version'].value_counts().to_dict()
            stats['dhcpv4_packets'] = int(ver_counts.get('v4', 0))
            stats['dhcpv6_packets'] = int(ver_counts.get('v6', 0))

        # Message type distribution
        if 'msg_type' in df.columns:
            mt = df['msg_type'].dropna()
            if not mt.empty:
                type_counts = mt.value_counts().to_dict()
                stats['message_types'] = {
                    DHCP_MSG_TYPES.get(str(k), f'Type {k}'): int(v)
                    for k, v in type_counts.items()
                }

        # Unique clients
        if 'client_mac' in df.columns:
            clients = df['client_mac'].dropna()
            stats['unique_clients'] = int(clients.nunique())
            stats['top_clients'] = clients.value_counts().head(10).to_dict()

        # Unique servers
        if 'server_ip' in df.columns:
            servers = df['server_ip'].dropna()
            stats['unique_servers'] = int(servers.nunique())
            if not servers.empty:
                stats['dhcp_servers'] = servers.value_counts().to_dict()

        # Hostnames
        if 'hostname' in df.columns:
            hosts = df['hostname'].dropna()
            if not hosts.empty:
                stats['unique_hostnames'] = int(hosts.nunique())
                stats['hostnames'] = hosts.value_counts().head(20).to_dict()

        # Requested IPs
        if 'requested_ip' in df.columns:
            rips = df['requested_ip'].dropna()
            if not rips.empty:
                stats['requested_ips'] = rips.value_counts().head(10).to_dict()

        return stats

    # ------------------------------------------------------------------
    #  Threat detection
    # ------------------------------------------------------------------

    def _detect_threats(self, df: pd.DataFrame) -> Dict:
        threats = {}

        starvation = self._detect_dhcp_starvation(df)
        if starvation['detected']:
            threats['dhcp_starvation'] = starvation

        rogue = self._detect_rogue_server(df)
        if rogue['detected']:
            threats['rogue_dhcp_server'] = rogue

        rapid = self._detect_rapid_requests(df)
        if rapid['detected']:
            threats['rapid_dhcp_requests'] = rapid

        nak_flood = self._detect_nak_flood(df)
        if nak_flood['detected']:
            threats['dhcp_nak_flood'] = nak_flood

        return threats

    def _detect_dhcp_starvation(self, df: pd.DataFrame) -> Dict:
        """Detect DHCP starvation attacks (many Discovers from different MACs)."""
        result = {"detected": False, "severity": "info"}

        if 'msg_type' not in df.columns:
            return result

        discovers = df[df['msg_type'].astype(str) == '1']
        if len(discovers) < 5:
            return result

        if 'client_mac' in discovers.columns:
            unique_macs = discovers['client_mac'].nunique()
            threshold = self.dhcp_config.get('starvation_mac_threshold', 20)

            if unique_macs >= threshold:
                result['detected'] = True
                result['severity'] = 'critical'
                result['unique_macs'] = unique_macs
                result['discover_count'] = len(discovers)
                result['message'] = (
                    f"DHCP starvation attack suspected: {unique_macs} unique MAC addresses "
                    f"sending DHCP Discover ({len(discovers)} total)"
                )
                result['top_sources'] = (
                    discovers['client_mac'].value_counts().head(10).to_dict()
                )

        return result

    def _detect_rogue_server(self, df: pd.DataFrame) -> Dict:
        """Detect rogue DHCP servers (multiple servers offering addresses)."""
        result = {"detected": False, "severity": "info"}

        if 'msg_type' not in df.columns or 'server_ip' not in df.columns:
            return result

        offers = df[df['msg_type'].astype(str) == '2']
        if offers.empty:
            return result

        servers = offers['server_ip'].dropna().unique()
        max_servers = self.dhcp_config.get('max_dhcp_servers', 2)

        if len(servers) > max_servers:
            result['detected'] = True
            result['severity'] = 'critical'
            result['server_count'] = len(servers)
            result['servers'] = {
                str(s): int((offers['server_ip'] == s).sum()) for s in servers
            }
            result['message'] = (
                f"Rogue DHCP server detected: {len(servers)} DHCP servers responding "
                f"(expected max: {max_servers})"
            )

        return result

    def _detect_rapid_requests(self, df: pd.DataFrame) -> Dict:
        """Detect abnormally rapid DHCP request rates."""
        result = {"detected": False, "severity": "info"}

        if 'timestamp' not in df.columns or len(df) < 10:
            return result

        time_span = df['timestamp'].max() - df['timestamp'].min()
        if time_span <= 0:
            return result

        request_rate = len(df) / time_span
        threshold = self.dhcp_config.get('max_request_rate', 10)

        if request_rate > threshold:
            result['detected'] = True
            result['severity'] = 'high'
            result['request_rate'] = float(round(request_rate, 2))
            result['message'] = (
                f"Rapid DHCP requests: {request_rate:.1f} requests/sec "
                f"(threshold: {threshold})"
            )

        return result

    def _detect_nak_flood(self, df: pd.DataFrame) -> Dict:
        """Detect excessive DHCP NAK responses."""
        result = {"detected": False, "severity": "info"}

        if 'msg_type' not in df.columns:
            return result

        naks = df[df['msg_type'].astype(str) == '6']
        threshold = self.dhcp_config.get('max_nak_count', 10)

        if len(naks) >= threshold:
            result['detected'] = True
            result['severity'] = 'high'
            result['nak_count'] = len(naks)
            result['message'] = (
                f"DHCP NAK flood: {len(naks)} NAK responses detected "
                f"(threshold: {threshold})"
            )

        return result


def main():
    """Standalone CLI entry point"""
    parser = argparse.ArgumentParser(description='Analyze DHCP traffic from PCAP file')
    parser.add_argument('--input', '-i', required=True, help='Input PCAP file')
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('--html-report', '-r', help='Generate HTML report file')
    parser.add_argument('--config', '-c', default='config/default.yaml', help='Config file')

    args = parser.parse_args()

    analyzer = DHCPAnalyzer(config_path=args.config)
    results = analyzer.analyze(args.input)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))

    if args.html_report:
        try:
            from src.reports.html_generator import HTMLReportGenerator
            generator = HTMLReportGenerator()
            report_path = generator.generate_report(
                results={'total_packets': results.get('total_packets', 0),
                         'protocol_analysis': {'dhcp': results}},
                pcap_file=args.input,
                output_file=args.html_report,
                protocol="DHCP"
            )
            print(f"\nHTML Report generated: {report_path}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")

    if results.get('threats'):
        print("\n=== DHCP THREATS DETECTED ===")
        for name, data in results['threats'].items():
            print(f"\n[{data.get('severity', 'unknown').upper()}] {name.replace('_', ' ').title()}")
            if 'message' in data:
                print(f"  {data['message']}")


if __name__ == '__main__':
    main()
