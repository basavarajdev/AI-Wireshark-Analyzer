"""
HTTP Protocol Analyzer
Detects HTTP-specific critical security issues
"""

import argparse
import pandas as pd
from pathlib import Path
from loguru import logger
import yaml
import json
import re
from typing import Dict

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.parsers.packet_parser import PacketParser
from src.preprocessing.cleaning import DataCleaner


class HTTPAnalyzer:
    """Analyze HTTP traffic for critical security issues"""
    
    def __init__(self, config_path: str = "config/default.yaml"):
        """Initialize HTTP Analyzer"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.http_config = self.config['protocols']['http']
        self.parser = PacketParser(config_path)
        self.cleaner = DataCleaner()
    
    def analyze(self, pcap_file: str, display_filter: str = None) -> Dict:
        """Analyze HTTP traffic from PCAP file"""
        logger.info(f"Analyzing HTTP traffic in {pcap_file}")
        
        proto_filter = f'http && ({display_filter})' if display_filter else 'http'
        df = self.parser.parse_pcap(pcap_file, display_filter=proto_filter)
        
        if df.empty:
            logger.warning("No HTTP packets found")
            return {"error": "No HTTP packets found"}
        
        df = self.cleaner.clean(df)
        
        results = {
            "total_packets": len(df),
            "statistics": self._calculate_statistics(df),
            "threats": self._detect_threats(df)
        }
        
        return results
    
    def _calculate_statistics(self, df: pd.DataFrame) -> Dict:
        """Calculate HTTP statistics"""
        stats = {}
        
        if 'http_method' in df.columns:
            requests = df[df['http_method'].notna()]
            stats['total_requests'] = len(requests)
            stats['methods'] = requests['http_method'].value_counts().to_dict()
        
        if 'http_status' in df.columns:
            responses = df[df['http_status'] > 0]
            stats['total_responses'] = len(responses)
            stats['status_codes'] = responses['http_status'].value_counts().to_dict()
        
        if 'http_uri' in df.columns:
            stats['unique_uris'] = df['http_uri'].nunique()
        
        if 'src_ip' in df.columns:
            stats['unique_clients'] = df['src_ip'].nunique()
        
        return stats
    
    def _detect_threats(self, df: pd.DataFrame) -> Dict:
        """Detect HTTP-specific threats"""
        threats = {}
        
        # SQL Injection
        sql_injection = self._detect_sql_injection(df)
        if sql_injection['detected']:
            threats['sql_injection'] = sql_injection
        
        # XSS Attacks
        xss = self._detect_xss(df)
        if xss['detected']:
            threats['cross_site_scripting'] = xss
        
        # Suspicious User Agents
        sus_agents = self._detect_suspicious_user_agents(df)
        if sus_agents['detected']:
            threats['suspicious_user_agents'] = sus_agents
        
        # High Request Rate (DoS)
        high_rate = self._detect_high_request_rate(df)
        if high_rate['detected']:
            threats['http_flood'] = high_rate
        
        # Directory Traversal
        dir_traversal = self._detect_directory_traversal(df)
        if dir_traversal['detected']:
            threats['directory_traversal'] = dir_traversal
        
        return threats
    
    def _detect_sql_injection(self, df: pd.DataFrame) -> Dict:
        """Detect SQL injection attempts"""
        result = {"detected": False, "severity": "info"}
        
        if 'http_uri' not in df.columns:
            return result
        
        uris = df[df['http_uri'].notna()].copy()
        if len(uris) == 0:
            return result
        
        # SQL injection patterns
        sql_patterns = [
            r"('|(\\'))+",  # Quotes
            r"(union.*select)",
            r"(select.*from)",
            r"(insert.*into)",
            r"(delete.*from)",
            r"(drop.*table)",
            r"(update.*set)",
            r"(exec.*\()",
            r"(or.*1=1)",
            r"(and.*1=1)",
        ]
        
        sql_regex = re.compile('|'.join(sql_patterns), re.IGNORECASE)
        uris['is_sqli'] = uris['http_uri'].str.contains(sql_regex, na=False)
        
        sqli_attempts = uris[uris['is_sqli']]
        
        if len(sqli_attempts) > 0:
            result['detected'] = True
            result['severity'] = 'critical'
            result['sqli_attempt_count'] = len(sqli_attempts)
            result['message'] = f"SQL injection attempts detected: {len(sqli_attempts)} malicious requests"
            result['sample_uris'] = sqli_attempts['http_uri'].head(5).tolist()
            
            if 'src_ip' in df.columns:
                result['attacker_ips'] = sqli_attempts['src_ip'].value_counts().head(5).to_dict()
        
        return result
    
    def _detect_xss(self, df: pd.DataFrame) -> Dict:
        """Detect Cross-Site Scripting (XSS) attempts"""
        result = {"detected": False, "severity": "info"}
        
        if 'http_uri' not in df.columns:
            return result
        
        uris = df[df['http_uri'].notna()].copy()
        if len(uris) == 0:
            return result
        
        # XSS patterns
        xss_patterns = [
            r"<script",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"<iframe",
            r"document\.cookie",
            r"alert\(",
        ]
        
        xss_regex = re.compile('|'.join(xss_patterns), re.IGNORECASE)
        uris['is_xss'] = uris['http_uri'].str.contains(xss_regex, na=False)
        
        xss_attempts = uris[uris['is_xss']]
        
        if len(xss_attempts) > 0:
            result['detected'] = True
            result['severity'] = 'high'
            result['xss_attempt_count'] = len(xss_attempts)
            result['message'] = f"XSS attempts detected: {len(xss_attempts)} malicious requests"
            result['sample_uris'] = xss_attempts['http_uri'].head(5).tolist()
            
            if 'src_ip' in df.columns:
                result['attacker_ips'] = xss_attempts['src_ip'].value_counts().head(5).to_dict()
        
        return result
    
    def _detect_suspicious_user_agents(self, df: pd.DataFrame) -> Dict:
        """Detect suspicious user agents"""
        result = {"detected": False, "severity": "info"}
        
        if 'http_user_agent' not in df.columns:
            return result
        
        agents = df[df['http_user_agent'].notna()].copy()
        if len(agents) == 0:
            return result
        
        suspicious_agents = self.http_config['suspicious_user_agents']
        
        agents['is_suspicious'] = agents['http_user_agent'].str.lower().apply(
            lambda x: any(sus_agent in str(x) for sus_agent in suspicious_agents)
        )
        
        sus_requests = agents[agents['is_suspicious']]
        
        if len(sus_requests) > 0:
            result['detected'] = True
            result['severity'] = 'high'
            result['suspicious_request_count'] = len(sus_requests)
            result['message'] = f"Suspicious user agents detected: {len(sus_requests)} requests from scanning tools"
            result['user_agents'] = sus_requests['http_user_agent'].value_counts().head(10).to_dict()
            
            if 'src_ip' in df.columns:
                result['scanner_ips'] = sus_requests['src_ip'].value_counts().head(5).to_dict()
        
        return result
    
    def _detect_high_request_rate(self, df: pd.DataFrame) -> Dict:
        """Detect HTTP flood / high request rate"""
        result = {"detected": False, "severity": "info"}
        
        if 'src_ip' not in df.columns or 'timestamp' not in df.columns:
            return result
        
        time_span = df['timestamp'].max() - df['timestamp'].min()
        if time_span <= 0:
            return result
        
        # Requests per IP
        requests_per_ip = df.groupby('src_ip').size()
        rate_per_ip = requests_per_ip / time_span
        
        high_rate_ips = rate_per_ip[rate_per_ip > self.http_config['max_request_rate']]
        
        if len(high_rate_ips) > 0:
            result['detected'] = True
            result['severity'] = 'high'
            result['high_rate_ip_count'] = len(high_rate_ips)
            result['message'] = f"HTTP flood detected: {len(high_rate_ips)} IP(s) with high request rate"
            result['top_requesters'] = {
                str(ip): float(rate) for ip, rate in high_rate_ips.head(10).items()
            }
        
        return result
    
    def _detect_directory_traversal(self, df: pd.DataFrame) -> Dict:
        """Detect directory traversal attempts"""
        result = {"detected": False, "severity": "info"}
        
        if 'http_uri' not in df.columns:
            return result
        
        uris = df[df['http_uri'].notna()].copy()
        if len(uris) == 0:
            return result
        
        # Directory traversal patterns
        traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e",
            r"etc/passwd",
            r"windows/system",
        ]
        
        traversal_regex = re.compile('|'.join(traversal_patterns), re.IGNORECASE)
        uris['is_traversal'] = uris['http_uri'].str.contains(traversal_regex, na=False)
        
        traversal_attempts = uris[uris['is_traversal']]
        
        if len(traversal_attempts) > 0:
            result['detected'] = True
            result['severity'] = 'high'
            result['traversal_attempt_count'] = len(traversal_attempts)
            result['message'] = f"Directory traversal attempts detected: {len(traversal_attempts)} malicious requests"
            result['sample_uris'] = traversal_attempts['http_uri'].head(5).tolist()
        
        return result


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='Analyze HTTP traffic from PCAP file')
    parser.add_argument('--input', '-i', required=True, help='Input PCAP file')
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('--config', '-c', default='config/default.yaml', help='Config file')
    
    args = parser.parse_args()
    
    analyzer = HTTPAnalyzer(config_path=args.config)
    results = analyzer.analyze(args.input)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
    
    if results.get('threats'):
        print("\n=== CRITICAL HTTP SECURITY ISSUES ===")
        for threat_name, threat_data in results['threats'].items():
            print(f"\n[{threat_data.get('severity', 'unknown').upper()}] {threat_name.replace('_', ' ').title()}")
            if 'message' in threat_data:
                print(f"  {threat_data['message']}")


if __name__ == '__main__':
    main()
