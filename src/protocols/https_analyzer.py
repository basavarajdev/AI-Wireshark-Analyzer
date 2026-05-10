"""
HTTPS/TLS Protocol Analyzer
Detects HTTPS-specific critical security issues
"""

import argparse
import pandas as pd
from pathlib import Path
from loguru import logger
import yaml
import json
from collections import Counter
from typing import Dict

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.parsers.packet_parser import PacketParser
from src.preprocessing.cleaning import DataCleaner


class HTTPSAnalyzer:
    """Analyze HTTPS/TLS traffic for critical security issues"""
    
    def __init__(self, config_path: str = "config/default.yaml"):
        """Initialize HTTPS Analyzer"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.parser = PacketParser(config_path)
        self.cleaner = DataCleaner()
    
    def analyze(self, pcap_file: str, display_filter: str = None) -> Dict:
        """Analyze HTTPS/TLS traffic from PCAP file"""
        logger.info(f"Analyzing HTTPS traffic in {pcap_file}")
        
        # Parse TLS packets (port 443)
        proto_filter = f'tcp.port==443 && ({display_filter})' if display_filter else 'tcp.port==443'
        df = self.parser.parse_pcap(pcap_file, display_filter=proto_filter)
        
        if df.empty:
            logger.warning("No HTTPS packets found")
            return {"error": "No HTTPS packets found"}
        
        df = self.cleaner.clean(df)
        
        results = {
            "total_packets": len(df),
            "statistics": self._calculate_statistics(df),
            "threats": self._detect_threats(df)
        }
        
        return results
    
    def _calculate_statistics(self, df: pd.DataFrame) -> Dict:
        """Calculate HTTPS statistics"""
        stats = {}
        
        stats['total_connections'] = len(df)
        
        if 'src_ip' in df.columns:
            stats['unique_clients'] = df['src_ip'].nunique()
        
        if 'dst_ip' in df.columns:
            stats['unique_servers'] = df['dst_ip'].nunique()
        
        if 'length' in df.columns:
            stats['total_bytes'] = int(df['length'].sum())
            stats['avg_packet_size'] = float(df['length'].mean())
        
        # SSL/TLS handshake detection (simplified - based on packet sizes)
        if 'length' in df.columns and 'tcp_flags' in df.columns:
            # Typical handshake packets are larger
            handshakes = df[df['length'] > 100]
            stats['potential_handshakes'] = len(handshakes)

            # RST and FIN counts on port 443
            rst_count = ((df['tcp_flags'] & 0x04) > 0).sum()
            fin_count = ((df['tcp_flags'] & 0x01) > 0).sum()
            syn_count = ((df['tcp_flags'] & 0x02) > 0).sum()
            stats['tls_rst_packets'] = int(rst_count)
            stats['tls_fin_packets'] = int(fin_count)
            stats['tls_syn_packets'] = int(syn_count)
        
        return stats
    
    def _detect_threats(self, df: pd.DataFrame) -> Dict:
        """Detect HTTPS-specific threats"""
        threats = {}
        
        # SSL/TLS Downgrade Attack
        downgrade = self._detect_ssl_downgrade(df)
        if downgrade['detected']:
            threats['ssl_downgrade'] = downgrade
        
        # Certificate Issues (simplified detection)
        cert_issues = self._detect_certificate_issues(df)
        if cert_issues['detected']:
            threats['certificate_issues'] = cert_issues
        
        # HTTPS Flood
        flood = self._detect_https_flood(df)
        if flood['detected']:
            threats['https_flood'] = flood
        
        # Suspicious SNI Patterns
        sni_issues = self._detect_suspicious_sni(df)
        if sni_issues['detected']:
            threats['suspicious_sni'] = sni_issues

        # TLS Handshake Failures
        hs_fail = self._detect_handshake_failures(df)
        if hs_fail['detected']:
            threats['tls_handshake_failure'] = hs_fail

        # Incomplete TLS Connections
        incomplete = self._detect_incomplete_connections(df)
        if incomplete['detected']:
            threats['incomplete_tls_connections'] = incomplete
        
        return threats
    
    def _detect_ssl_downgrade(self, df: pd.DataFrame) -> Dict:
        """Detect SSL/TLS downgrade attempts (simplified)"""
        result = {"detected": False, "severity": "info"}
        
        # This is a simplified check - proper detection requires TLS packet parsing
        # Looking for unusual connection patterns
        
        if 'tcp_flags' in df.columns and 'length' in df.columns:
            # Multiple small packets might indicate negotiation issues
            small_packets = df[df['length'] < 100]
            
            if len(small_packets) / len(df) > 0.7:
                result['detected'] = True
                result['severity'] = 'medium'
                result['message'] = "Potential SSL/TLS downgrade or negotiation issues detected"
                result['small_packet_ratio'] = float(len(small_packets) / len(df))
        
        return result
    
    def _detect_certificate_issues(self, df: pd.DataFrame) -> Dict:
        """Detect certificate-related issues (simplified)"""
        result = {"detected": False, "severity": "info"}
        
        # This is a placeholder - proper detection requires TLS packet parsing
        # In practice, you'd check for:
        # - Expired certificates
        # - Self-signed certificates
        # - Certificate chain issues
        # - Hostname mismatches
        
        result['message'] = "Full certificate validation requires TLS packet inspection"
        
        return result
    
    def _detect_https_flood(self, df: pd.DataFrame) -> Dict:
        """Detect HTTPS flood attacks"""
        result = {"detected": False, "severity": "info"}
        
        if 'src_ip' not in df.columns or 'timestamp' not in df.columns:
            return result
        
        time_span = df['timestamp'].max() - df['timestamp'].min()
        if time_span <= 0:
            return result
        
        # Connections per IP
        connections_per_ip = df.groupby('src_ip').size()
        rate_per_ip = connections_per_ip / time_span
        
        # High connection rate threshold
        high_rate_ips = rate_per_ip[rate_per_ip > 50]  # 50 connections/sec
        
        if len(high_rate_ips) > 0:
            result['detected'] = True
            result['severity'] = 'high'
            result['high_rate_ip_count'] = len(high_rate_ips)
            result['message'] = f"HTTPS flood detected: {len(high_rate_ips)} IP(s) with high connection rate"
            result['top_sources'] = {
                str(ip): float(rate) for ip, rate in high_rate_ips.head(10).items()
            }
        
        return result
    
    def _detect_suspicious_sni(self, df: pd.DataFrame) -> Dict:
        """Detect suspicious Server Name Indication patterns"""
        result = {"detected": False, "severity": "info"}
        
        # This requires TLS packet parsing to extract SNI
        # Placeholder for demonstration
        
        result['message'] = "SNI analysis requires TLS packet inspection"
        
        return result

    def _detect_handshake_failures(self, df: pd.DataFrame) -> Dict:
        """Detect TLS handshake failures — RST or FIN during the handshake
        phase (early packets in a flow) indicating cert errors, protocol
        mismatches, or server-side rejections."""
        result = {"detected": False, "severity": "info"}

        if 'tcp_flags' not in df.columns or 'src_ip' not in df.columns:
            return result
        if 'dst_ip' not in df.columns or 'src_port' not in df.columns or 'dst_port' not in df.columns:
            return result

        df_sorted = df.sort_values('timestamp') if 'timestamp' in df.columns else df

        # Group into flows
        df_sorted = df_sorted.copy()
        df_sorted['flow'] = df_sorted.apply(
            lambda r: tuple(sorted([
                (str(r['src_ip']), int(r['src_port'])),
                (str(r['dst_ip']), int(r['dst_port']))
            ])),
            axis=1
        ).astype(str)

        failed_handshakes = 0
        failure_servers = Counter()

        for flow_key, grp in df_sorted.groupby('flow'):
            if len(grp) < 2:
                continue
            # Check first 6 packets in the flow (handshake phase)
            early = grp.head(6)
            has_syn = ((early['tcp_flags'] & 0x02) > 0).any()
            has_rst = ((early['tcp_flags'] & 0x04) > 0).any()
            has_fin = ((early['tcp_flags'] & 0x01) > 0).any()
            # Handshake failure = SYN seen, but RST or FIN within first few packets
            if has_syn and (has_rst or has_fin):
                failed_handshakes += 1
                # The server IP is the one on port 443
                server_row = grp[grp['dst_port'] == 443].head(1)
                if not server_row.empty:
                    failure_servers[server_row.iloc[0]['dst_ip']] += 1

        if failed_handshakes < 3:
            return result

        result['detected'] = True
        result['severity'] = 'high' if failed_handshakes > 20 else 'medium'
        result['failed_handshake_count'] = failed_handshakes
        result['message'] = (
            f"TLS handshake failures: {failed_handshakes} connection(s) terminated "
            "during handshake (RST/FIN after SYN), indicating certificate errors or server rejections"
        )
        result['failure_servers'] = dict(failure_servers.most_common(10))

        return result

    def _detect_incomplete_connections(self, df: pd.DataFrame) -> Dict:
        """Detect incomplete TLS connections — flows with SYN but no data
        exchange (very few packets), indicating connection setup failures."""
        result = {"detected": False, "severity": "info"}

        if 'tcp_flags' not in df.columns or 'src_ip' not in df.columns:
            return result
        if 'dst_ip' not in df.columns or 'src_port' not in df.columns or 'dst_port' not in df.columns:
            return result

        df_c = df.copy()
        df_c['flow'] = df_c.apply(
            lambda r: tuple(sorted([
                (str(r['src_ip']), int(r['src_port'])),
                (str(r['dst_ip']), int(r['dst_port']))
            ])),
            axis=1
        ).astype(str)

        flow_sizes = df_c.groupby('flow').size()
        # Flows with <= 3 packets are likely incomplete (SYN, SYN-ACK, RST/FIN)
        incomplete_flows = flow_sizes[flow_sizes <= 3]
        total_flows = len(flow_sizes)

        if len(incomplete_flows) < 3 or total_flows == 0:
            return result

        incomplete_ratio = len(incomplete_flows) / total_flows

        result['detected'] = True
        result['severity'] = 'high' if incomplete_ratio > 0.3 else 'medium'
        result['incomplete_count'] = int(len(incomplete_flows))
        result['total_flows'] = total_flows
        result['incomplete_ratio'] = float(round(incomplete_ratio, 3))
        result['message'] = (
            f"Incomplete TLS connections: {len(incomplete_flows)} of {total_flows} "
            f"flows ({incomplete_ratio*100:.1f}%) had ≤3 packets, "
            "indicating failed connection setup or immediate termination"
        )

        return result


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='Analyze HTTPS traffic from PCAP file')
    parser.add_argument('--input', '-i', required=True, help='Input PCAP file')
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('--config', '-c', default='config/default.yaml', help='Config file')
    
    args = parser.parse_args()
    
    analyzer = HTTPSAnalyzer(config_path=args.config)
    results = analyzer.analyze(args.input)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
    
    if results.get('threats'):
        print("\n=== CRITICAL HTTPS SECURITY ISSUES ===")
        for threat_name, threat_data in results['threats'].items():
            print(f"\n[{threat_data.get('severity', 'unknown').upper()}] {threat_name.replace('_', ' ').title()}")
            if 'message' in threat_data:
                print(f"  {threat_data['message']}")


if __name__ == '__main__':
    main()
