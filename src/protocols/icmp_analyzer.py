"""
ICMP Protocol Analyzer
Detects ICMP-specific critical network issues
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


class ICMPAnalyzer:
    """Analyze ICMP traffic for critical issues"""
    
    def __init__(self, config_path: str = "config/default.yaml"):
        """Initialize ICMP Analyzer"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.icmp_config = self.config['protocols']['icmp']
        self.parser = PacketParser(config_path)
        self.cleaner = DataCleaner()
    
    def analyze(self, pcap_file: str, display_filter: str = None) -> Dict:
        """Analyze ICMP traffic from PCAP file"""
        logger.info(f"Analyzing ICMP traffic in {pcap_file}")
        
        proto_filter = f'icmp && ({display_filter})' if display_filter else 'icmp'
        df = self.parser.parse_pcap(pcap_file, display_filter=proto_filter)
        
        if df.empty:
            logger.warning("No ICMP packets found")
            return {"error": "No ICMP packets found"}
        
        df = self.cleaner.clean(df)
        
        results = {
            "total_packets": len(df),
            "statistics": self._calculate_statistics(df),
            "threats": self._detect_threats(df)
        }
        
        return results
    
    def _calculate_statistics(self, df: pd.DataFrame) -> Dict:
        """Calculate ICMP statistics"""
        stats = {}
        
        stats['total_icmp_packets'] = len(df)
        
        if 'icmp_type' in df.columns:
            type_counts = df['icmp_type'].value_counts().to_dict()
            stats['icmp_types'] = type_counts
            
            # Common ICMP types
            stats['echo_requests'] = int(df[df['icmp_type'] == 8].shape[0])  # Type 8
            stats['echo_replies'] = int(df[df['icmp_type'] == 0].shape[0])    # Type 0
            stats['dest_unreachable'] = int(df[df['icmp_type'] == 3].shape[0])  # Type 3
            stats['time_exceeded'] = int(df[df['icmp_type'] == 11].shape[0])    # Type 11
        
        if 'src_ip' in df.columns:
            stats['unique_sources'] = df['src_ip'].nunique()
        
        if 'dst_ip' in df.columns:
            stats['unique_destinations'] = df['dst_ip'].nunique()
        
        if 'length' in df.columns:
            stats['avg_packet_size'] = float(df['length'].mean())
            stats['max_packet_size'] = int(df['length'].max())
        
        return stats
    
    def _detect_threats(self, df: pd.DataFrame) -> Dict:
        """Detect ICMP-specific threats"""
        threats = {}
        
        # ICMP Flood
        flood = self._detect_icmp_flood(df)
        if flood['detected']:
            threats['icmp_flood'] = flood
        
        # Ping of Death
        ping_of_death = self._detect_ping_of_death(df)
        if ping_of_death['detected']:
            threats['ping_of_death'] = ping_of_death
        
        # Smurf Attack
        smurf = self._detect_smurf_attack(df)
        if smurf['detected']:
            threats['smurf_attack'] = smurf
        
        # ICMP Tunneling
        tunneling = self._detect_icmp_tunneling(df)
        if tunneling['detected']:
            threats['icmp_tunneling'] = tunneling
        
        # Network Scanning
        scanning = self._detect_network_scanning(df)
        if scanning['detected']:
            threats['network_scanning'] = scanning
        
        return threats
    
    def _detect_icmp_flood(self, df: pd.DataFrame) -> Dict:
        """Detect ICMP flood attacks"""
        result = {"detected": False, "severity": "info"}
        
        if 'timestamp' not in df.columns:
            return result
        
        time_span = df['timestamp'].max() - df['timestamp'].min()
        if time_span <= 0:
            return result
        
        packet_rate = len(df) / time_span
        
        if packet_rate > self.icmp_config['max_packet_rate']:
            result['detected'] = True
            result['severity'] = 'critical'
            result['packet_rate'] = float(packet_rate)
            result['threshold'] = self.icmp_config['max_packet_rate']
            result['message'] = f"ICMP flood detected: {packet_rate:.2f} packets/sec (threshold: {self.icmp_config['max_packet_rate']})"
            
            # Top targets
            if 'dst_ip' in df.columns:
                top_targets = df['dst_ip'].value_counts().head(5).to_dict()
                result['top_targets'] = top_targets
            
            # Top sources
            if 'src_ip' in df.columns:
                top_sources = df['src_ip'].value_counts().head(5).to_dict()
                result['top_sources'] = top_sources
            
            # ICMP type distribution
            if 'icmp_type' in df.columns:
                result['icmp_type_distribution'] = df['icmp_type'].value_counts().to_dict()
        
        return result
    
    def _detect_ping_of_death(self, df: pd.DataFrame) -> Dict:
        """Detect Ping of Death attacks"""
        result = {"detected": False, "severity": "info"}
        
        if 'length' not in df.columns or 'icmp_type' not in df.columns:
            return result
        
        # Ping of Death: ICMP packets larger than allowed
        echo_packets = df[df['icmp_type'] == 8]  # Echo requests
        
        large_pings = echo_packets[echo_packets['length'] > self.icmp_config['max_payload_size']]
        
        if len(large_pings) > 0:
            result['detected'] = True
            result['severity'] = 'high'
            result['large_ping_count'] = len(large_pings)
            result['max_ping_size'] = int(large_pings['length'].max())
            result['message'] = f"Ping of Death detected: {len(large_pings)} oversized ICMP packets"
            
            if 'src_ip' in df.columns:
                result['attacker_ips'] = large_pings['src_ip'].value_counts().head(5).to_dict()
        
        return result
    
    def _detect_smurf_attack(self, df: pd.DataFrame) -> Dict:
        """Detect Smurf attacks (ICMP amplification)"""
        result = {"detected": False, "severity": "info"}
        
        if 'icmp_type' not in df.columns or 'dst_ip' not in df.columns:
            return result
        
        # Smurf: Many echo replies to single destination
        echo_replies = df[df['icmp_type'] == 0]  # Echo replies
        
        if len(echo_replies) < 50:
            return result
        
        # Count replies per destination
        reply_counts = echo_replies['dst_ip'].value_counts()
        
        # If many replies going to single IP, likely smurf victim
        if len(reply_counts) > 0 and reply_counts.iloc[0] > 100:
            result['detected'] = True
            result['severity'] = 'critical'
            result['reply_count'] = int(reply_counts.iloc[0])
            result['victim_ip'] = str(reply_counts.index[0])
            result['message'] = f"Smurf attack detected: {reply_counts.iloc[0]} ICMP replies to {reply_counts.index[0]}"
            
            # Amplification sources
            if 'src_ip' in df.columns:
                victim_traffic = echo_replies[echo_replies['dst_ip'] == reply_counts.index[0]]
                result['amplification_source_count'] = victim_traffic['src_ip'].nunique()
                result['top_amplification_sources'] = victim_traffic['src_ip'].value_counts().head(10).to_dict()
        
        return result
    
    def _detect_icmp_tunneling(self, df: pd.DataFrame) -> Dict:
        """Detect ICMP tunneling / covert channels"""
        result = {"detected": False, "severity": "info"}
        
        if 'length' not in df.columns or 'icmp_type' not in df.columns:
            return result
        
        # ICMP tunneling often uses consistent packet sizes
        echo_packets = df[df['icmp_type'].isin([0, 8])]  # Echo request/reply
        
        if len(echo_packets) < 20:
            return result
        
        # Check for unusual payload sizes or patterns
        # Standard ping is usually 64 bytes total
        unusual_sizes = echo_packets[
            (echo_packets['length'] > 100) & (echo_packets['length'] < 500)
        ]
        
        if len(unusual_sizes) > 20:
            # Check if consistent sizes (tunneling signature)
            size_counts = unusual_sizes['length'].value_counts()
            most_common_size = size_counts.iloc[0] if len(size_counts) > 0 else 0
            
            if most_common_size > 15:  # Many packets of same unusual size
                result['detected'] = True
                result['severity'] = 'high'
                result['suspicious_packet_count'] = len(unusual_sizes)
                result['common_payload_size'] = int(size_counts.index[0])
                result['message'] = f"ICMP tunneling suspected: {len(unusual_sizes)} packets with unusual consistent sizes"
                
                if 'src_ip' in df.columns and 'dst_ip' in df.columns:
                    # Identify tunnel endpoints
                    flows = unusual_sizes.groupby(['src_ip', 'dst_ip']).size().sort_values(ascending=False)
                    if len(flows) > 0:
                        result['suspected_tunnel_endpoints'] = {
                            f"{src}->{dst}": int(count) 
                            for (src, dst), count in flows.head(5).items()
                        }
        
        return result
    
    def _detect_network_scanning(self, df: pd.DataFrame) -> Dict:
        """Detect ICMP-based network scanning"""
        result = {"detected": False, "severity": "info"}
        
        if 'icmp_type' not in df.columns or 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
            return result
        
        # Network scanning: Echo requests to many destinations from single source
        echo_requests = df[df['icmp_type'] == 8]  # Echo requests
        
        if len(echo_requests) < 10:
            return result
        
        # Count unique destinations per source
        dest_per_source = echo_requests.groupby('src_ip')['dst_ip'].nunique()
        
        # Scanning threshold: > 20 unique destinations
        scanners = dest_per_source[dest_per_source > 20]
        
        if len(scanners) > 0:
            result['detected'] = True
            result['severity'] = 'medium'
            result['scanner_count'] = len(scanners)
            result['message'] = f"ICMP network scanning detected from {len(scanners)} source(s)"
            result['scanners'] = {
                str(ip): int(count) for ip, count in scanners.head(10).items()
            }
        
        return result


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='Analyze ICMP traffic from PCAP file')
    parser.add_argument('--input', '-i', required=True, help='Input PCAP file')
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('--config', '-c', default='config/default.yaml', help='Config file')
    
    args = parser.parse_args()
    
    analyzer = ICMPAnalyzer(config_path=args.config)
    results = analyzer.analyze(args.input)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
    
    if results.get('threats'):
        print("\n=== CRITICAL ICMP ISSUES ===")
        for threat_name, threat_data in results['threats'].items():
            print(f"\n[{threat_data.get('severity', 'unknown').upper()}] {threat_name.replace('_', ' ').title()}")
            if 'message' in threat_data:
                print(f"  {threat_data['message']}")


if __name__ == '__main__':
    main()
