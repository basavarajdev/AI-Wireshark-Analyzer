"""
TCP Protocol Analyzer
Detects TCP-specific critical network issues and application-layer protocol threats
via port-based filtering (HTTP on 80/8080, HTTPS on 443/8443, SMTP, FTP, etc.)
"""

import argparse
import re
import pandas as pd
import numpy as np
from pathlib import Path
from loguru import logger
import yaml
import json
from typing import Dict, List

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.parsers.packet_parser import PacketParser
from src.preprocessing.cleaning import DataCleaner

# Well-known TCP port → application-layer protocol mapping
TCP_PORT_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS/TCP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS/TLS", 465: "SMTPS", 587: "SMTP-Submission",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt",
}

# HTTP ports for application-layer threat detection
HTTP_PORTS = {80, 8080, 8008, 8888}
# HTTPS/TLS ports
TLS_PORTS = {443, 8443, 9443}


class TCPAnalyzer:
    """Analyze TCP traffic for critical issues, including application-layer
    threats on common ports (HTTP, HTTPS/TLS, etc.)."""
    
    def __init__(self, config_path: str = "config/default.yaml"):
        """Initialize TCP Analyzer"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.tcp_config = self.config['protocols']['tcp']
        self.parser = PacketParser(config_path)
        self.cleaner = DataCleaner()
    
    def analyze(self, pcap_file: str, display_filter: str = None, ip_filter: str = None, port_filter: str = None) -> Dict:
        """
        Analyze TCP traffic from PCAP file
        
        Args:
            pcap_file: Path to PCAP file
            display_filter: Optional additional Wireshark display filter
            ip_filter: Optional IP address to filter (source or destination)
            port_filter: Optional comma-separated ports to filter
            
        Returns:
            Dictionary with analysis results and critical issues
        """
        logger.info(f"Analyzing TCP traffic in {pcap_file}")
        
        try:
            # Build comprehensive filter
            filters = ['tcp']
            if display_filter:
                filters.append(f'({display_filter})')
            if ip_filter:
                filters.append(f'(ip.src=={ip_filter} || ip.dst=={ip_filter})')
            if port_filter:
                ports = [p.strip() for p in port_filter.split(',')]
                port_expr = ' || '.join([f'tcp.port=={port}' for port in ports])
                filters.append(f'({port_expr})')
            
            proto_filter = ' && '.join(filters)
            logger.debug(f"TCP filter: {proto_filter}")
            
            df = self.parser.parse_pcap(pcap_file, display_filter=proto_filter)
            
            if df.empty:
                logger.warning("No TCP packets found")
                return {"error": "No TCP packets found", "status": "empty"}
            
            df = self.cleaner.clean(df)
            
            # Run analysis
            results = {
                "total_packets": len(df),
                "critical_issues": [],
                "statistics": self._calculate_statistics(df),
                "threats": self._detect_threats(df),
                "app_layer_protocols": self._identify_app_layer_protocols(df),
            }
            
            return results
            
        except Exception as e:
            error_msg = f"Error analyzing TCP traffic: {str(e)}"
            logger.error(error_msg)
            return {
                "error": error_msg,
                "status": "error",
                "type": type(e).__name__
            }
    
    def _calculate_statistics(self, df: pd.DataFrame) -> Dict:
        """Calculate TCP statistics"""
        stats = {}
        
        # Flag distribution
        if 'tcp_flags' in df.columns:
            syn_count = ((df['tcp_flags'] & 0x02) > 0).sum()
            ack_count = ((df['tcp_flags'] & 0x10) > 0).sum()
            fin_count = ((df['tcp_flags'] & 0x01) > 0).sum()
            rst_count = ((df['tcp_flags'] & 0x04) > 0).sum()
            push_count = ((df['tcp_flags'] & 0x08) > 0).sum()
            
            stats['syn_packets'] = int(syn_count)
            stats['ack_packets'] = int(ack_count)
            stats['fin_packets'] = int(fin_count)
            stats['rst_packets'] = int(rst_count)
            stats['push_packets'] = int(push_count)

            # SYN-only (no ACK) vs SYN-ACK
            syn_only = ((df['tcp_flags'] & 0x12) == 0x02).sum()
            syn_ack = ((df['tcp_flags'] & 0x12) == 0x12).sum()
            stats['syn_only_packets'] = int(syn_only)
            stats['syn_ack_packets'] = int(syn_ack)
        
        # Connection statistics
        if 'src_ip' in df.columns and 'dst_ip' in df.columns:
            stats['unique_source_ips'] = df['src_ip'].nunique()
            stats['unique_dest_ips'] = df['dst_ip'].nunique()
        
        if 'dst_port' in df.columns:
            stats['unique_dest_ports'] = df['dst_port'].nunique()
            stats['top_ports'] = df['dst_port'].value_counts().head(10).to_dict()
        
        # Packet size statistics
        if 'length' in df.columns:
            stats['avg_packet_size'] = float(df['length'].mean())
            stats['min_packet_size'] = int(df['length'].min())
            stats['max_packet_size'] = int(df['length'].max())

        # Window size statistics
        if 'window_size' in df.columns:
            ws = df['window_size']
            stats['avg_window_size'] = int(ws.mean())
            stats['min_window_size'] = int(ws.min())
            stats['max_window_size'] = int(ws.max())
            zero_win = (ws == 0).sum()
            stats['zero_window_count'] = int(zero_win)
        
        return stats
    
    def _detect_threats(self, df: pd.DataFrame) -> Dict:
        """Detect TCP-specific threats"""
        threats = {}
        
        # SYN Flood Detection
        syn_flood = self._detect_syn_flood(df)
        if syn_flood['detected']:
            threats['syn_flood'] = syn_flood
        
        # RST Storm Detection
        rst_storm = self._detect_rst_storm(df)
        if rst_storm['detected']:
            threats['rst_storm'] = rst_storm
        
        # Port Scanning Detection
        port_scan = self._detect_port_scanning(df)
        if port_scan['detected']:
            threats['port_scanning'] = port_scan
        
        # Retransmission Analysis
        retrans = self._analyze_retransmissions(df)
        if retrans['high_rate']:
            threats['excessive_retransmissions'] = retrans
        
        # Connection Hijacking Detection
        hijack = self._detect_connection_hijacking(df)
        if hijack['detected']:
            threats['connection_hijacking'] = hijack

        # Zero Window Detection
        zero_win = self._detect_zero_window(df)
        if zero_win['detected']:
            threats['zero_window'] = zero_win

        # TCP Reset Analysis (connection resets with context)
        rst_analysis = self._analyze_connection_resets(df)
        if rst_analysis['detected']:
            threats['connection_resets'] = rst_analysis

        # Data Transmission Gaps
        data_gaps = self._detect_data_gaps(df)
        if data_gaps['detected']:
            threats['data_transmission_gaps'] = data_gaps

        # Application-layer threats based on identified ports
        app_threats = self._detect_app_layer_threats(df)
        threats.update(app_threats)
        
        return threats

    # ─────────────────────────────────────────────────────────────────────────
    # Application-layer analysis (port-based; replaces standalone HTTP/HTTPS)
    # ─────────────────────────────────────────────────────────────────────────

    def _identify_app_layer_protocols(self, df: pd.DataFrame) -> Dict:
        """Map observed TCP ports to known application-layer protocols."""
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
                proto_name = TCP_PORT_MAP.get(port_int)
                if proto_name:
                    key = f"port_{port_int}_{proto_name.replace('/', '_')}"
                    result[key] = {
                        "port": port_int,
                        "protocol": proto_name,
                        "packet_count": int(count),
                    }
        return result

    def _detect_app_layer_threats(self, df: pd.DataFrame) -> Dict:
        """Run application-layer threat detection based on port presence."""
        threats = {}

        if 'dst_port' not in df.columns and 'src_port' not in df.columns:
            return threats

        # Determine which ports are present
        all_ports = set()
        for col in ('dst_port', 'src_port'):
            if col in df.columns:
                all_ports.update(df[col].dropna().astype(int).tolist())

        # HTTP threat detection on HTTP ports
        http_present = all_ports & HTTP_PORTS
        if http_present:
            http_df = df[
                df['dst_port'].isin(HTTP_PORTS) | df['src_port'].isin(HTTP_PORTS)
            ] if 'dst_port' in df.columns and 'src_port' in df.columns else df

            for method in (
                self._detect_sql_injection,
                self._detect_xss,
                self._detect_directory_traversal,
                self._detect_suspicious_user_agents,
                self._detect_http_flood,
            ):
                result = method(http_df)
                if result.get('detected'):
                    threats[method.__name__.lstrip('_')] = result

        # TLS/HTTPS threat detection on TLS ports
        tls_present = all_ports & TLS_PORTS
        if tls_present:
            tls_df = df[
                df['dst_port'].isin(TLS_PORTS) | df['src_port'].isin(TLS_PORTS)
            ] if 'dst_port' in df.columns and 'src_port' in df.columns else df

            for method in (
                self._detect_tls_downgrade,
                self._detect_tls_handshake_failures,
                self._detect_https_flood,
            ):
                result = method(tls_df)
                if result.get('detected'):
                    threats[method.__name__.lstrip('_')] = result

        return threats

    # ── HTTP threat detectors ─────────────────────────────────────────────────

    def _detect_sql_injection(self, df: pd.DataFrame) -> Dict:
        """Detect SQL injection patterns in HTTP URIs."""
        result = {"detected": False, "severity": "info"}
        if 'http_uri' not in df.columns:
            return result
        uris = df[df['http_uri'].notna()]
        if uris.empty:
            return result
        sql_re = re.compile(
            r"('|(\\'))+|(union.*select)|(select.*from)|(insert.*into)"
            r"|(delete.*from)|(drop.*table)|(update.*set)|(exec.*\()"
            r"|(or.*1=1)|(and.*1=1)",
            re.IGNORECASE
        )
        hits = uris[uris['http_uri'].str.contains(sql_re, na=False)]
        if not hits.empty:
            result.update({
                "detected": True, "severity": "critical",
                "count": len(hits),
                "message": f"SQL injection attempts: {len(hits)} malicious HTTP requests",
                "sample_uris": hits['http_uri'].head(5).tolist(),
            })
            if 'src_ip' in hits.columns:
                result['attacker_ips'] = hits['src_ip'].value_counts().head(5).to_dict()
        return result

    def _detect_xss(self, df: pd.DataFrame) -> Dict:
        """Detect XSS patterns in HTTP URIs."""
        result = {"detected": False, "severity": "info"}
        if 'http_uri' not in df.columns:
            return result
        uris = df[df['http_uri'].notna()]
        if uris.empty:
            return result
        xss_re = re.compile(
            r"<script|javascript:|onerror=|onload=|<iframe|document\.cookie|alert\(",
            re.IGNORECASE
        )
        hits = uris[uris['http_uri'].str.contains(xss_re, na=False)]
        if not hits.empty:
            result.update({
                "detected": True, "severity": "high",
                "count": len(hits),
                "message": f"XSS attempts: {len(hits)} malicious HTTP requests",
                "sample_uris": hits['http_uri'].head(5).tolist(),
            })
            if 'src_ip' in hits.columns:
                result['attacker_ips'] = hits['src_ip'].value_counts().head(5).to_dict()
        return result

    def _detect_directory_traversal(self, df: pd.DataFrame) -> Dict:
        """Detect directory traversal attempts in HTTP URIs."""
        result = {"detected": False, "severity": "info"}
        if 'http_uri' not in df.columns:
            return result
        uris = df[df['http_uri'].notna()]
        if uris.empty:
            return result
        trav_re = re.compile(
            r"\.\./|\.\.\\|%2e%2e|etc/passwd|windows/system",
            re.IGNORECASE
        )
        hits = uris[uris['http_uri'].str.contains(trav_re, na=False)]
        if not hits.empty:
            result.update({
                "detected": True, "severity": "high",
                "count": len(hits),
                "message": f"Directory traversal attempts: {len(hits)} malicious requests",
                "sample_uris": hits['http_uri'].head(5).tolist(),
            })
        return result

    def _detect_suspicious_user_agents(self, df: pd.DataFrame) -> Dict:
        """Detect scanning tool user agents in HTTP traffic."""
        result = {"detected": False, "severity": "info"}
        if 'http_user_agent' not in df.columns:
            return result
        agents = df[df['http_user_agent'].notna()]
        if agents.empty:
            return result
        suspicious = self.config.get('protocols', {}).get('http', {}).get(
            'suspicious_user_agents', ["sqlmap", "nikto", "nmap", "masscan"]
        )
        hits = agents[agents['http_user_agent'].str.lower().apply(
            lambda x: any(s in str(x) for s in suspicious)
        )]
        if not hits.empty:
            result.update({
                "detected": True, "severity": "high",
                "count": len(hits),
                "message": f"Suspicious user agents: {len(hits)} requests from scanning tools",
                "user_agents": hits['http_user_agent'].value_counts().head(10).to_dict(),
            })
            if 'src_ip' in hits.columns:
                result['scanner_ips'] = hits['src_ip'].value_counts().head(5).to_dict()
        return result

    def _detect_http_flood(self, df: pd.DataFrame) -> Dict:
        """Detect HTTP flood / high request rate."""
        result = {"detected": False, "severity": "info"}
        if 'src_ip' not in df.columns or 'timestamp' not in df.columns:
            return result
        time_span = df['timestamp'].max() - df['timestamp'].min()
        if time_span <= 0:
            return result
        max_rate = self.config.get('protocols', {}).get('http', {}).get('max_request_rate', 50)
        rate_per_ip = df.groupby('src_ip').size() / time_span
        high_rate = rate_per_ip[rate_per_ip > max_rate]
        if not high_rate.empty:
            result.update({
                "detected": True, "severity": "high",
                "count": len(high_rate),
                "message": f"HTTP flood: {len(high_rate)} IP(s) exceed {max_rate} req/s",
                "top_requesters": {str(ip): float(r) for ip, r in high_rate.head(10).items()},
            })
        return result

    # ── TLS/HTTPS threat detectors ────────────────────────────────────────────

    def _detect_tls_downgrade(self, df: pd.DataFrame) -> Dict:
        """Detect potential TLS downgrade / negotiation failures."""
        result = {"detected": False, "severity": "info"}
        if 'length' not in df.columns:
            return result
        small_pkt_ratio = (df['length'] < 100).sum() / max(len(df), 1)
        if small_pkt_ratio > 0.7:
            result.update({
                "detected": True, "severity": "medium",
                "small_packet_ratio": float(round(small_pkt_ratio, 4)),
                "message": "Potential TLS downgrade or negotiation issues (high ratio of small packets on TLS port)",
            })
        return result

    def _detect_tls_handshake_failures(self, df: pd.DataFrame) -> Dict:
        """Detect TLS handshake failures via RST patterns on TLS ports."""
        result = {"detected": False, "severity": "info"}
        if 'tcp_flags' not in df.columns:
            return result
        rst_df = df[(df['tcp_flags'] & 0x04) > 0]
        syn_df = df[(df['tcp_flags'] & 0x12) == 0x02]
        if len(syn_df) == 0:
            return result
        failure_ratio = len(rst_df) / max(len(syn_df), 1)
        if failure_ratio > 0.3 and len(rst_df) >= 5:
            result.update({
                "detected": True, "severity": "medium",
                "rst_count": int(len(rst_df)),
                "syn_count": int(len(syn_df)),
                "failure_ratio": float(round(failure_ratio, 4)),
                "message": f"TLS handshake failures: {len(rst_df)} RSTs for {len(syn_df)} SYNs ({failure_ratio*100:.1f}% failure rate)",
            })
        return result

    def _detect_https_flood(self, df: pd.DataFrame) -> Dict:
        """Detect high connection rate to TLS ports (HTTPS flood)."""
        result = {"detected": False, "severity": "info"}
        if 'src_ip' not in df.columns or 'timestamp' not in df.columns:
            return result
        time_span = df['timestamp'].max() - df['timestamp'].min()
        if time_span <= 0:
            return result
        rate_per_ip = df.groupby('src_ip').size() / time_span
        high_rate = rate_per_ip[rate_per_ip > 50]
        if not high_rate.empty:
            result.update({
                "detected": True, "severity": "high",
                "count": len(high_rate),
                "message": f"HTTPS/TLS flood: {len(high_rate)} IP(s) with >50 conn/s",
                "top_sources": {str(ip): float(r) for ip, r in high_rate.head(10).items()},
            })
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # Core TCP threat detectors
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_syn_flood(self, df: pd.DataFrame) -> Dict:
        """Detect SYN flood attacks"""
        result = {"detected": False, "severity": "info"}
        
        if 'tcp_flags' not in df.columns or 'timestamp' not in df.columns:
            return result
        
        # Count SYN packets
        syn_packets = df[(df['tcp_flags'] & 0x02) > 0]
        
        if len(syn_packets) < 100:
            return result
        
        # Calculate SYN rate
        if 'timestamp' in df.columns:
            time_span = df['timestamp'].max() - df['timestamp'].min()
            if time_span > 0:
                syn_rate = len(syn_packets) / time_span
                
                if syn_rate > self.tcp_config['max_syn_rate']:
                    result['detected'] = True
                    result['severity'] = 'critical'
                    result['syn_rate'] = float(syn_rate)
                    result['threshold'] = self.tcp_config['max_syn_rate']
                    result['message'] = f"SYN flood detected: {syn_rate:.2f} SYN/sec (threshold: {self.tcp_config['max_syn_rate']})"
                    
                    # Identify top targets
                    if 'dst_ip' in df.columns:
                        top_targets = syn_packets['dst_ip'].value_counts().head(5).to_dict()
                        result['top_targets'] = top_targets
        
        return result
    
    def _detect_rst_storm(self, df: pd.DataFrame) -> Dict:
        """Detect RST storms"""
        result = {"detected": False, "severity": "info"}
        
        if 'tcp_flags' not in df.columns:
            return result
        
        # Count RST packets
        rst_packets = df[(df['tcp_flags'] & 0x04) > 0]
        
        if len(rst_packets) < 50:
            return result
        
        # Calculate RST rate
        if 'timestamp' in df.columns:
            time_span = df['timestamp'].max() - df['timestamp'].min()
            if time_span > 0:
                rst_rate = len(rst_packets) / time_span
                
                if rst_rate > self.tcp_config['max_rst_rate']:
                    result['detected'] = True
                    result['severity'] = 'high'
                    result['rst_rate'] = float(rst_rate)
                    result['message'] = f"RST storm detected: {rst_rate:.2f} RST/sec"
                    
                    if 'src_ip' in df.columns:
                        top_sources = rst_packets['src_ip'].value_counts().head(5).to_dict()
                        result['top_sources'] = top_sources
        
        return result
    
    def _detect_port_scanning(self, df: pd.DataFrame) -> Dict:
        """Detect port scanning activity"""
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
            result['message'] = f"Port scanning detected from {len(scanners)} source(s)"
            result['scanners'] = {
                str(ip): int(count) for ip, count in scanners.head(10).items()
            }
            
            # Check for SYN scan pattern
            syn_only = df[(df['tcp_flags'] & 0x02) > 0]
            if len(syn_only) / len(df) > 0.8:
                result['scan_type'] = 'SYN_SCAN'
        
        return result
    
    def _analyze_retransmissions(self, df: pd.DataFrame) -> Dict:
        """Analyze TCP retransmissions"""
        result = {"high_rate": False, "severity": "info"}
        
        if 'seq_num' not in df.columns or 'src_ip' not in df.columns:
            return result
        
        # Group by connection (simplified)
        df['connection'] = df['src_ip'].astype(str) + ':' + df['src_port'].astype(str)
        
        retrans_count = 0
        for conn, group in df.groupby('connection'):
            # Count duplicate sequence numbers
            seq_counts = group['seq_num'].value_counts()
            retrans_count += (seq_counts > 1).sum()
        
        total_packets = len(df)
        retrans_rate = retrans_count / total_packets if total_packets > 0 else 0
        
        result['retransmission_rate'] = float(retrans_rate)
        result['retransmission_count'] = int(retrans_count)
        
        if retrans_rate > self.tcp_config['max_retransmission_rate']:
            result['high_rate'] = True
            result['severity'] = 'medium'
            result['message'] = f"High retransmission rate: {retrans_rate:.2%}"
        
        return result
    
    def _detect_connection_hijacking(self, df: pd.DataFrame) -> Dict:
        """Detect potential TCP connection hijacking"""
        result = {"detected": False, "severity": "info"}
        
        if 'seq_num' not in df.columns or 'ack_num' not in df.columns:
            return result
        
        # Look for sequence number anomalies
        suspicious_count = 0
        
        # Group by connection
        if 'src_ip' in df.columns and 'dst_ip' in df.columns:
            df['flow'] = (df['src_ip'].astype(str) + ':' + df['src_port'].astype(str) + 
                         '-' + df['dst_ip'].astype(str) + ':' + df['dst_port'].astype(str))
            
            for flow, group in df.groupby('flow'):
                if len(group) < 5:
                    continue
                
                # Check for unexpected sequence jumps
                seq_diffs = group['seq_num'].diff().abs()
                large_jumps = (seq_diffs > 100000).sum()
                
                if large_jumps > 2:
                    suspicious_count += 1
        
        if suspicious_count > 0:
            result['detected'] = True
            result['severity'] = 'high'
            result['suspicious_flows'] = suspicious_count
            result['message'] = f"Potential connection hijacking: {suspicious_count} suspicious flow(s)"
        
        return result

    def _detect_zero_window(self, df: pd.DataFrame) -> Dict:
        """Detect TCP zero window conditions indicating receiver buffer exhaustion."""
        result = {"detected": False, "severity": "info"}

        if 'window_size' not in df.columns:
            return result

        zero_win_df = df[df['window_size'] == 0]
        if len(zero_win_df) < 3:
            return result

        zero_ratio = len(zero_win_df) / len(df)
        result['detected'] = True
        result['severity'] = 'high' if zero_ratio > 0.05 else 'medium'
        result['zero_window_count'] = int(len(zero_win_df))
        result['zero_window_ratio'] = float(round(zero_ratio, 4))
        result['message'] = (
            f"TCP zero window detected: {len(zero_win_df)} packets ({zero_ratio*100:.2f}%) "
            "with window size 0, indicating receiver buffer exhaustion"
        )

        # Identify affected endpoints
        if 'src_ip' in zero_win_df.columns:
            result['affected_sources'] = zero_win_df['src_ip'].value_counts().head(5).to_dict()
        if 'dst_ip' in zero_win_df.columns:
            result['affected_destinations'] = zero_win_df['dst_ip'].value_counts().head(5).to_dict()

        return result

    def _analyze_connection_resets(self, df: pd.DataFrame) -> Dict:
        """Analyze TCP RST packets with connection context — incomplete handshakes,
        abrupt terminations, and reset patterns."""
        result = {"detected": False, "severity": "info"}

        if 'tcp_flags' not in df.columns:
            return result

        rst_df = df[(df['tcp_flags'] & 0x04) > 0]
        if len(rst_df) < 5:
            return result

        total = len(df)
        rst_ratio = len(rst_df) / total

        # RSTs after SYN (connection refused / failed handshakes)
        rst_after_syn = 0
        if 'src_ip' in df.columns and 'dst_ip' in df.columns and 'dst_port' in df.columns:
            syn_df = df[(df['tcp_flags'] & 0x12) == 0x02]  # SYN only
            for _, syn in syn_df.iterrows():
                # Look for RST from destination back to source on same port
                matching_rst = rst_df[
                    (rst_df['src_ip'] == syn['dst_ip']) &
                    (rst_df['dst_ip'] == syn['src_ip']) &
                    (rst_df['src_port'] == syn['dst_port'])
                ]
                if len(matching_rst) > 0:
                    rst_after_syn += 1
                if rst_after_syn > 200:
                    break  # cap iteration

        # RSTs by port — reveals which services are refusing connections
        rst_by_port = {}
        if 'src_port' in rst_df.columns:
            rst_by_port = rst_df['src_port'].value_counts().head(10).to_dict()

        result['detected'] = True
        result['severity'] = 'high' if rst_ratio > 0.1 else 'medium'
        result['rst_count'] = int(len(rst_df))
        result['rst_ratio'] = float(round(rst_ratio, 4))
        result['connection_refused'] = int(rst_after_syn)
        result['rst_by_port'] = rst_by_port
        result['message'] = (
            f"TCP connection resets: {len(rst_df)} RST packets ({rst_ratio*100:.1f}% of traffic), "
            f"{rst_after_syn} connection refused (RST after SYN)"
        )

        if 'src_ip' in rst_df.columns:
            result['top_rst_sources'] = rst_df['src_ip'].value_counts().head(5).to_dict()

        return result

    def _detect_data_gaps(self, df: pd.DataFrame) -> Dict:
        """Detect gaps in TCP data transmission — periods of silence within
        established flows that indicate connection stalls or breaks."""
        result = {"detected": False, "severity": "info"}

        if 'timestamp' not in df.columns or 'src_ip' not in df.columns:
            return result

        # Build bidirectional flow keys
        if 'dst_ip' not in df.columns or 'src_port' not in df.columns or 'dst_port' not in df.columns:
            return result

        df_sorted = df.sort_values('timestamp')
        df_sorted['flow'] = df_sorted.apply(
            lambda r: tuple(sorted([
                (str(r['src_ip']), int(r['src_port'])),
                (str(r['dst_ip']), int(r['dst_port']))
            ])),
            axis=1
        ).astype(str)

        gap_threshold = 5.0  # seconds — silence > 5s within a flow is a gap
        stalled_flows = []

        for flow_key, grp in df_sorted.groupby('flow'):
            if len(grp) < 4:
                continue
            timestamps = grp['timestamp'].values
            diffs = np.diff(timestamps)
            large_gaps = diffs[diffs > gap_threshold]
            if len(large_gaps) > 0:
                stalled_flows.append({
                    'flow': flow_key,
                    'gap_count': int(len(large_gaps)),
                    'max_gap_sec': float(round(large_gaps.max(), 2)),
                    'avg_gap_sec': float(round(large_gaps.mean(), 2)),
                })

        if not stalled_flows:
            return result

        result['detected'] = True
        result['severity'] = 'medium'
        result['stalled_flow_count'] = len(stalled_flows)
        result['total_gaps'] = sum(f['gap_count'] for f in stalled_flows)
        worst = max(stalled_flows, key=lambda f: f['max_gap_sec'])
        result['worst_gap_sec'] = worst['max_gap_sec']
        result['message'] = (
            f"Data transmission gaps: {len(stalled_flows)} flow(s) with silence > {gap_threshold}s, "
            f"worst gap {worst['max_gap_sec']:.1f}s"
        )
        result['stalled_flows'] = stalled_flows[:10]

        return result


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='Analyze TCP traffic from PCAP file')
    parser.add_argument('--input', '-i', required=True, help='Input PCAP file')
    parser.add_argument('--output', '-o', help='Output JSON file (default: print to console)')
    parser.add_argument('--html-report', '-r', help='Generate HTML report file')
    parser.add_argument('--config', '-c', default='config/default.yaml', help='Config file')
    
    args = parser.parse_args()
    
    # Run analysis
    analyzer = TCPAnalyzer(config_path=args.config)
    results = analyzer.analyze(args.input)
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
    
    # Generate HTML report if requested
    if args.html_report:
        try:
            from src.reports.html_generator import HTMLReportGenerator
            generator = HTMLReportGenerator()
            report_path = generator.generate_report(
                results=results,
                pcap_file=args.input,
                output_file=args.html_report,
                protocol="TCP"
            )
            print(f"\n📄 HTML Report generated: {report_path}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
    
    # Print critical issues
    if results.get('threats'):
        print("\n=== CRITICAL ISSUES DETECTED ===")
        for threat_name, threat_data in results['threats'].items():
            print(f"\n[{threat_data.get('severity', 'unknown').upper()}] {threat_name.replace('_', ' ').title()}")
            if 'message' in threat_data:
                print(f"  {threat_data['message']}")


if __name__ == '__main__':
    main()
