"""
UDP Protocol Analyzer
Detects UDP-specific critical network issues and provides port-based
application-layer protocol coverage (DNS, NTP, DHCP, QUIC, SSDP, etc.)
"""

import argparse
import pandas as pd
from pathlib import Path
from loguru import logger
import yaml
import json
from typing import Dict

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.parsers.packet_parser import PacketParser
from src.preprocessing.cleaning import DataCleaner

# Well-known UDP port → application-layer protocol mapping
UDP_PORT_MAP = {
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
    69: "TFTP", 123: "NTP", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    161: "SNMP", 162: "SNMP-Trap", 389: "LDAP",
    443: "QUIC/HTTP3", 500: "IKE/VPN", 514: "Syslog",
    1194: "OpenVPN", 1900: "SSDP/UPnP",
    4500: "IKE-NAT", 5353: "mDNS", 5355: "LLMNR",
    9000: "QUIC-Alt", 11211: "Memcached",
}


class UDPAnalyzer:
    """Analyze UDP traffic for critical issues, with port-based
    application-layer protocol identification."""
    
    def __init__(self, config_path: str = "config/default.yaml"):
        """Initialize UDP Analyzer"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.udp_config = self.config['protocols']['udp']
        self.parser = PacketParser(config_path)
        self.cleaner = DataCleaner()
    
    def analyze(self, pcap_file: str, display_filter: str = None, ip_filter: str = None, port_filter: str = None) -> Dict:
        """
        Analyze UDP traffic from PCAP file
        
        Args:
            pcap_file: Path to PCAP file
            display_filter: Optional additional Wireshark display filter
            ip_filter: Optional IP address to filter (source or destination)
            port_filter: Optional comma-separated ports to filter
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Analyzing UDP traffic in {pcap_file}")
        
        try:
            # Build comprehensive filter
            filters = ['udp']
            if display_filter:
                filters.append(f'({display_filter})')
            if ip_filter:
                filters.append(f'(ip.src=={ip_filter} || ip.dst=={ip_filter})')
            if port_filter:
                ports = [p.strip() for p in port_filter.split(',')]
                port_expr = ' || '.join([f'udp.port=={port}' for port in ports])
                filters.append(f'({port_expr})')
            
            proto_filter = ' && '.join(filters)
            logger.debug(f"UDP filter: {proto_filter}")
            
            df = self.parser.parse_pcap(pcap_file, display_filter=proto_filter)
            
            if df.empty:
                logger.warning("No UDP packets found")
                return {"error": "No UDP packets found", "status": "empty"}
            
            df = self.cleaner.clean(df)
            
            results = {
                "total_packets": len(df),
                "statistics": self._calculate_statistics(df),
                "threats": self._detect_threats(df),
                "app_layer_protocols": self._identify_app_layer_protocols(df),
            }
            
            return results
            
        except Exception as e:
            error_msg = f"Error analyzing UDP traffic: {str(e)}"
            logger.error(error_msg)
            return {
                "error": error_msg,
                "status": "error",
                "type": type(e).__name__
            }
    
    def _calculate_statistics(self, df: pd.DataFrame) -> Dict:
        """Calculate UDP statistics"""
        stats = {}
        
        stats['total_udp_packets'] = len(df)
        
        if 'src_ip' in df.columns:
            stats['unique_sources'] = df['src_ip'].nunique()
        
        if 'dst_ip' in df.columns:
            stats['unique_destinations'] = df['dst_ip'].nunique()
        
        if 'dst_port' in df.columns:
            stats['unique_dest_ports'] = df['dst_port'].nunique()
            stats['top_ports'] = df['dst_port'].value_counts().head(10).to_dict()
        
        if 'length' in df.columns:
            stats['total_bytes'] = int(df['length'].sum())
            stats['avg_packet_size'] = float(df['length'].mean())
            stats['min_packet_size'] = int(df['length'].min())
            stats['max_packet_size'] = int(df['length'].max())
            stats['packet_size_variance'] = float(df['length'].var())
        
        return stats
    
    def _detect_threats(self, df: pd.DataFrame) -> Dict:
        """Detect UDP-specific threats"""
        threats = {}
        
        # UDP Flood
        flood = self._detect_udp_flood(df)
        if flood['detected']:
            threats['udp_flood'] = flood
        
        # UDP Amplification
        amplification = self._detect_udp_amplification(df)
        if amplification['detected']:
            threats['udp_amplification'] = amplification
        
        # Port Scanning
        port_scan = self._detect_port_scanning(df)
        if port_scan['detected']:
            threats['port_scanning'] = port_scan
        
        # Fragmentation Attack
        fragmentation = self._detect_fragmentation_attack(df)
        if fragmentation['detected']:
            threats['fragmentation_attack'] = fragmentation
        
        return threats

    def _identify_app_layer_protocols(self, df: pd.DataFrame) -> Dict:
        """Map observed UDP ports to known application-layer protocols."""
        result = {}
        for col in ('dst_port', 'src_port'):
            if col not in df.columns:
                continue
            port_counts = df[col].value_counts()
            for port, count in port_counts.items():
                try:
                    port_int = int(port)
                except (ValueError, TypeError):
                    continue
                proto_name = UDP_PORT_MAP.get(port_int)
                if proto_name:
                    key = f"port_{port_int}_{proto_name.replace('/', '_')}"
                    result[key] = {
                        "port": port_int,
                        "protocol": proto_name,
                        "packet_count": int(count),
                    }
        return result
    
    def _detect_udp_flood(self, df: pd.DataFrame) -> Dict:
        """Detect UDP flood attacks"""
        result = {"detected": False, "severity": "info"}
        
        if 'timestamp' not in df.columns:
            return result
        
        time_span = df['timestamp'].max() - df['timestamp'].min()
        if time_span <= 0:
            return result
        
        packet_rate = len(df) / time_span
        
        if packet_rate > self.udp_config['max_packet_rate']:
            result['detected'] = True
            result['severity'] = 'critical'
            result['packet_rate'] = float(packet_rate)
            result['threshold'] = self.udp_config['max_packet_rate']
            result['message'] = f"UDP flood detected: {packet_rate:.2f} packets/sec (threshold: {self.udp_config['max_packet_rate']})"
            
            # Top targets
            if 'dst_ip' in df.columns:
                top_targets = df['dst_ip'].value_counts().head(5).to_dict()
                result['top_targets'] = top_targets
            
            # Top sources
            if 'src_ip' in df.columns:
                top_sources = df['src_ip'].value_counts().head(5).to_dict()
                result['top_sources'] = top_sources
        
        return result
    
    def _detect_udp_amplification(self, df: pd.DataFrame) -> Dict:
        """Detect UDP amplification attacks"""
        result = {"detected": False, "severity": "info"}
        
        if 'src_port' not in df.columns or 'dst_port' not in df.columns:
            return result
        
        # Common amplification ports
        amplification_ports = {
            53: 'DNS',
            123: 'NTP',
            161: 'SNMP',
            389: 'LDAP',
            1900: 'SSDP',
            5353: 'mDNS',
            11211: 'Memcached'
        }
        
        # Check for traffic from amplification ports
        amp_traffic = df[df['src_port'].isin(amplification_ports.keys())]
        
        if len(amp_traffic) > 100:
            # Check if responses are going to limited destinations (attack victims)
            if 'dst_ip' in df.columns:
                victim_ips = amp_traffic['dst_ip'].value_counts()
                
                # If responses concentrated to few IPs, likely amplification
                if len(victim_ips) < 10 and victim_ips.iloc[0] > 50:
                    result['detected'] = True
                    result['severity'] = 'critical'
                    result['amplification_packet_count'] = len(amp_traffic)
                    result['message'] = f"UDP amplification attack detected: {len(amp_traffic)} amplified responses"
                    
                    # Service being abused
                    service_counts = amp_traffic['src_port'].map(amplification_ports).value_counts()
                    result['abused_services'] = service_counts.to_dict()
                    
                    # Victim IPs
                    result['victim_ips'] = {
                        str(ip): int(count) for ip, count in victim_ips.head(5).items()
                    }
        
        return result
    
    def _detect_port_scanning(self, df: pd.DataFrame) -> Dict:
        """Detect UDP port scanning"""
        result = {"detected": False, "severity": "info"}
        
        if 'src_ip' not in df.columns or 'dst_port' not in df.columns:
            return result
        
        # Group by source IP and count unique destination ports
        port_diversity = df.groupby('src_ip')['dst_port'].nunique()
        
        # Scanning threshold: > 20 unique ports from single IP
        scanners = port_diversity[port_diversity > 20]
        
        if len(scanners) > 0:
            result['detected'] = True
            result['severity'] = 'high'
            result['scanner_count'] = len(scanners)
            result['message'] = f"UDP port scanning detected from {len(scanners)} source(s)"
            result['scanners'] = {
                str(ip): int(count) for ip, count in scanners.head(10).items()
            }
        
        return result
    
    def _detect_fragmentation_attack(self, df: pd.DataFrame) -> Dict:
        """Detect UDP fragmentation attacks"""
        result = {"detected": False, "severity": "info"}
        
        if 'length' not in df.columns:
            return result
        
        # Check packet size variance
        if 'length' in df.columns:
            length_variance = df['length'].var()
            
            # High variance might indicate fragmentation attack
            if length_variance > self.udp_config['max_payload_variance'] * 10000:
                result['detected'] = True
                result['severity'] = 'medium'
                result['packet_size_variance'] = float(length_variance)
                result['message'] = f"High packet size variance detected: potential fragmentation attack"
                
                # Count very small packets (fragments)
                small_packets = df[df['length'] < 100]
                result['small_packet_count'] = len(small_packets)
                result['small_packet_ratio'] = float(len(small_packets) / len(df))
        
        return result


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='Analyze UDP traffic from PCAP file')
    parser.add_argument('--input', '-i', required=True, help='Input PCAP file')
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('--config', '-c', default='config/default.yaml', help='Config file')
    
    args = parser.parse_args()
    
    analyzer = UDPAnalyzer(config_path=args.config)
    results = analyzer.analyze(args.input)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
    
    if results.get('threats'):
        print("\n=== CRITICAL UDP ISSUES ===")
        for threat_name, threat_data in results['threats'].items():
            print(f"\n[{threat_data.get('severity', 'unknown').upper()}] {threat_name.replace('_', ' ').title()}")
            if 'message' in threat_data:
                print(f"  {threat_data['message']}")


if __name__ == '__main__':
    main()
