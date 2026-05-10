"""
DNS Protocol Analyzer
Detects DNS-specific critical network issues
"""

import argparse
import pandas as pd
from pathlib import Path
from loguru import logger
import yaml
import json
import re
from collections import Counter

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.parsers.packet_parser import PacketParser
from src.preprocessing.cleaning import DataCleaner
from src.core.utils import calculate_entropy


class DNSAnalyzer:
    """Analyze DNS traffic for critical issues"""
    
    def __init__(self, config_path: str = "config/default.yaml"):
        """Initialize DNS Analyzer"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.dns_config = self.config['protocols']['dns']
        self.parser = PacketParser(config_path)
        self.cleaner = DataCleaner()
    
    def analyze(self, pcap_file: str, display_filter: str = None) -> dict:
        """
        Analyze DNS traffic from PCAP file
        
        Args:
            pcap_file: Path to PCAP file
            display_filter: Optional additional Wireshark display filter
            
        Returns:
            Dictionary with analysis results and critical issues
        """
        logger.info(f"Analyzing DNS traffic in {pcap_file}")
        
        # Parse DNS packets
        proto_filter = f'dns && ({display_filter})' if display_filter else 'dns'
        df = self.parser.parse_pcap(pcap_file, display_filter=proto_filter)
        
        if df.empty:
            logger.warning("No DNS packets found")
            return {"error": "No DNS packets found"}
        
        df = self.cleaner.clean(df)
        
        # Run analysis
        results = {
            "total_packets": len(df),
            "statistics": self._calculate_statistics(df),
            "threats": self._detect_threats(df)
        }
        
        return results
    
    def _calculate_statistics(self, df: pd.DataFrame) -> dict:
        """Calculate DNS statistics"""
        stats = {}
        
        if 'dns_query' in df.columns:
            queries = df[df['dns_query'].notna()]
            stats['total_queries'] = len(queries)
            stats['unique_domains'] = queries['dns_query'].nunique()
            
            # Top queried domains
            if len(queries) > 0:
                stats['top_domains'] = queries['dns_query'].value_counts().head(10).to_dict()
        
        if 'dns_response_code' in df.columns:
            responses = df[df['dns_response_code'] >= 0]
            stats['total_responses'] = len(responses)
            
            # NXDOMAIN count
            nxdomain_count = (df['dns_response_code'] == 3).sum()
            stats['nxdomain_count'] = int(nxdomain_count)
            
            if len(responses) > 0:
                stats['nxdomain_rate'] = float(nxdomain_count / len(responses))
        
        if 'src_ip' in df.columns:
            stats['unique_clients'] = df['src_ip'].nunique()
        
        return stats
    
    def _detect_threats(self, df: pd.DataFrame) -> dict:
        """Detect DNS-specific threats"""
        threats = {}
        
        # DNS Tunneling Detection
        tunneling = self._detect_dns_tunneling(df)
        if tunneling['detected']:
            threats['dns_tunneling'] = tunneling
        
        # DGA Detection
        dga = self._detect_dga(df)
        if dga['detected']:
            threats['domain_generation_algorithm'] = dga
        
        # DNS Cache Poisoning
        poisoning = self._detect_cache_poisoning(df)
        if poisoning['detected']:
            threats['cache_poisoning'] = poisoning
        
        # Excessive NXDOMAIN
        nxdomain = self._detect_excessive_nxdomain(df)
        if nxdomain['detected']:
            threats['excessive_nxdomain'] = nxdomain
        
        # DNS Amplification Attack
        amplification = self._detect_dns_amplification(df)
        if amplification['detected']:
            threats['dns_amplification'] = amplification
        
        return threats
    
    def _detect_dns_tunneling(self, df: pd.DataFrame) -> dict:
        """Detect DNS tunneling"""
        result = {"detected": False, "severity": "info"}
        
        if 'dns_query' not in df.columns:
            return result
        
        queries = df[df['dns_query'].notna()].copy()
        if len(queries) < 10:
            return result
        
        # Calculate query characteristics
        queries['query_length'] = queries['dns_query'].str.len()
        queries['subdomain_count'] = queries['dns_query'].str.count(r'\.')
        queries['entropy'] = queries['dns_query'].apply(calculate_entropy)
        
        # Tunneling indicators
        long_queries = queries[queries['query_length'] > 50]
        deep_subdomains = queries[queries['subdomain_count'] > self.dns_config['max_subdomain_depth']]
        high_entropy = queries[queries['entropy'] > 4.0]
        
        suspicious = pd.concat([long_queries, deep_subdomains, high_entropy]).drop_duplicates()
        
        if len(suspicious) > 10 or len(suspicious) / len(queries) > 0.1:
            result['detected'] = True
            result['severity'] = 'critical'
            result['suspicious_query_count'] = len(suspicious)
            result['suspicious_query_rate'] = float(len(suspicious) / len(queries))
            result['message'] = f"DNS tunneling detected: {len(suspicious)} suspicious queries"
            
            # Sample suspicious domains
            result['sample_domains'] = suspicious['dns_query'].head(5).tolist()
        
        return result
    
    def _detect_dga(self, df: pd.DataFrame) -> dict:
        """Detect Domain Generation Algorithm patterns"""
        result = {"detected": False, "severity": "info"}
        
        if 'dns_query' not in df.columns:
            return result
        
        queries = df[df['dns_query'].notna()].copy()
        if len(queries) < 20:
            return result
        
        # DGA characteristics
        queries['entropy'] = queries['dns_query'].apply(
            lambda x: calculate_entropy(str(x).split('.')[0])  # First label only
        )
        queries['has_numbers'] = queries['dns_query'].apply(
            lambda x: bool(re.search(r'\d', str(x).split('.')[0]))
        )
        queries['label_length'] = queries['dns_query'].apply(
            lambda x: len(str(x).split('.')[0])
        )
        
        # DGA patterns: high entropy, numbers, long labels
        dga_candidates = queries[
            (queries['entropy'] > 4.5) &
            (queries['has_numbers']) &
            (queries['label_length'] > 10)
        ]
        
        if len(dga_candidates) > 5:
            result['detected'] = True
            result['severity'] = 'high'
            result['dga_domain_count'] = len(dga_candidates)
            result['message'] = f"DGA pattern detected: {len(dga_candidates)} suspicious domains"
            result['sample_domains'] = dga_candidates['dns_query'].head(5).tolist()
        
        return result
    
    def _detect_cache_poisoning(self, df: pd.DataFrame) -> dict:
        """Detect potential DNS cache poisoning"""
        result = {"detected": False, "severity": "info"}
        
        if 'dns_query' not in df.columns or 'src_ip' not in df.columns:
            return result
        
        # Look for same query from different sources with different responses
        # This is a simplified check
        query_sources = df[df['dns_query'].notna()].groupby('dns_query')['src_ip'].nunique()
        
        # Multiple sources querying same domain rapidly
        suspicious_domains = query_sources[query_sources > 10]
        
        if len(suspicious_domains) > 0:
            result['detected'] = True
            result['severity'] = 'medium'
            result['suspicious_domain_count'] = len(suspicious_domains)
            result['message'] = f"Potential cache poisoning: {len(suspicious_domains)} domains queried from multiple sources"
        
        return result
    
    def _detect_excessive_nxdomain(self, df: pd.DataFrame) -> dict:
        """Detect excessive NXDOMAIN responses"""
        result = {"detected": False, "severity": "info"}
        
        if 'dns_response_code' not in df.columns:
            return result
        
        responses = df[df['dns_response_code'] >= 0]
        if len(responses) < 10:
            return result
        
        nxdomain_count = (responses['dns_response_code'] == 3).sum()
        nxdomain_rate = nxdomain_count / len(responses)
        
        if nxdomain_rate > self.dns_config['max_nxdomain_rate']:
            result['detected'] = True
            result['severity'] = 'medium'
            result['nxdomain_rate'] = float(nxdomain_rate)
            result['nxdomain_count'] = int(nxdomain_count)
            result['message'] = f"Excessive NXDOMAIN rate: {nxdomain_rate:.2%} (threshold: {self.dns_config['max_nxdomain_rate']:.2%})"
            
            # Top failing domains
            if 'dns_query' in df.columns:
                nxdomains = df[df['dns_response_code'] == 3]
                if 'dns_query' in nxdomains.columns:
                    result['top_failing_domains'] = nxdomains['dns_query'].value_counts().head(5).to_dict()
        
        return result
    
    def _detect_dns_amplification(self, df: pd.DataFrame) -> dict:
        """Detect DNS amplification attacks"""
        result = {"detected": False, "severity": "info"}
        
        if 'src_ip' not in df.columns or 'length' not in df.columns:
            return result
        
        # Group by source IP and calculate query rate
        if 'timestamp' in df.columns:
            time_span = df['timestamp'].max() - df['timestamp'].min()
            if time_span > 0:
                query_counts = df.groupby('src_ip').size()
                
                # High query rate from single source
                high_rate_sources = query_counts[query_counts / time_span > self.dns_config['max_query_rate']]
                
                if len(high_rate_sources) > 0:
                    result['detected'] = True
                    result['severity'] = 'high'
                    result['amplification_source_count'] = len(high_rate_sources)
                    result['message'] = f"DNS amplification attack: {len(high_rate_sources)} high-rate source(s)"
                    result['top_sources'] = {
                        str(ip): int(count) for ip, count in high_rate_sources.head(5).items()
                    }
        
        return result


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='Analyze DNS traffic from PCAP file')
    parser.add_argument('--input', '-i', required=True, help='Input PCAP file')
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('--config', '-c', default='config/default.yaml', help='Config file')
    
    args = parser.parse_args()
    
    analyzer = DNSAnalyzer(config_path=args.config)
    results = analyzer.analyze(args.input)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
    
    if results.get('threats'):
        print("\n=== CRITICAL DNS ISSUES ===")
        for threat_name, threat_data in results['threats'].items():
            print(f"\n[{threat_data.get('severity', 'unknown').upper()}] {threat_name.replace('_', ' ').title()}")
            if 'message' in threat_data:
                print(f"  {threat_data['message']}")


if __name__ == '__main__':
    main()
