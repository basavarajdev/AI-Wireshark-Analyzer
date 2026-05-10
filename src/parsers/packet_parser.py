"""
Packet Parser Module
Extracts features from PCAP files using PyShark
"""

import pyshark
import pandas as pd
import numpy as np
from typing import List, Dict, Optional, Union
from pathlib import Path
from datetime import datetime
from loguru import logger
import yaml


class PacketParser:
    """Parse PCAP files and extract network features"""
    
    def __init__(self, config_path: str = "config/default.yaml"):
        """
        Initialize PacketParser
        
        Args:
            config_path: Path to configuration file
        """
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.features = self.config['features']['packet_features']
        self.max_packets = self.config['features']['max_packets']
        
    def parse_pcap(self, pcap_file: str, display_filter: Optional[str] = None) -> pd.DataFrame:
        """
        Parse PCAP file and extract features
        
        Args:
            pcap_file: Path to PCAP file
            display_filter: Wireshark display filter (e.g., 'tcp', 'http')
            
        Returns:
            DataFrame with extracted features
        """
        logger.info(f"Parsing PCAP file: {pcap_file}")
        
        if not Path(pcap_file).exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        packets_data = []
        
        try:
            # Open PCAP file
            capture = pyshark.FileCapture(
                pcap_file,
                display_filter=display_filter,
                use_json=True,
                include_raw=True
            )
            
            packet_count = 0
            for packet in capture:
                try:
                    packet_features = self._extract_packet_features(packet)
                    if packet_features:
                        packets_data.append(packet_features)
                        packet_count += 1
                        
                        if self.max_packets > 0 and packet_count >= self.max_packets:
                            logger.info(f"Reached max packets limit: {self.max_packets}")
                            break
                            
                except Exception as e:
                    logger.warning(f"Error parsing packet {packet_count}: {e}")
                    continue
            
            capture.close()
            logger.info(f"Parsed {len(packets_data)} packets successfully")
            
        except Exception as e:
            logger.error(f"Error reading PCAP file: {e}")
            raise
        
        if not packets_data:
            logger.warning("No packets extracted from PCAP file")
            return pd.DataFrame()
        
        df = pd.DataFrame(packets_data)
        return df
    
    def _extract_packet_features(self, packet) -> Optional[Dict]:
        """
        Extract features from a single packet
        
        Args:
            packet: PyShark packet object
            
        Returns:
            Dictionary of packet features
        """
        features = {}
        
        try:
            # Basic packet info
            features['timestamp'] = float(packet.sniff_timestamp)
            features['length'] = int(packet.length)
            
            # Protocol
            if hasattr(packet, 'highest_layer'):
                features['protocol'] = packet.highest_layer
            else:
                features['protocol'] = 'UNKNOWN'
            
            # IP layer
            if hasattr(packet, 'ip'):
                features['src_ip'] = packet.ip.src
                features['dst_ip'] = packet.ip.dst
                features['ttl'] = int(packet.ip.ttl) if hasattr(packet.ip, 'ttl') else 0
                features['ip_version'] = int(packet.ip.version) if hasattr(packet.ip, 'version') else 4
            else:
                features['src_ip'] = None
                features['dst_ip'] = None
                features['ttl'] = 0
                features['ip_version'] = 0
            
            # TCP layer
            if hasattr(packet, 'tcp'):
                features['src_port'] = int(packet.tcp.srcport)
                features['dst_port'] = int(packet.tcp.dstport)
                features['tcp_flags'] = self._parse_tcp_flags(packet.tcp)
                features['window_size'] = int(packet.tcp.window_size) if hasattr(packet.tcp, 'window_size') else 0
                features['seq_num'] = int(packet.tcp.seq) if hasattr(packet.tcp, 'seq') else 0
                features['ack_num'] = int(packet.tcp.ack) if hasattr(packet.tcp, 'ack') else 0
                features['transport'] = 'TCP'
            
            # UDP layer
            elif hasattr(packet, 'udp'):
                features['src_port'] = int(packet.udp.srcport)
                features['dst_port'] = int(packet.udp.dstport)
                features['tcp_flags'] = 0
                features['window_size'] = 0
                features['seq_num'] = 0
                features['ack_num'] = 0
                features['transport'] = 'UDP'
            
            else:
                features['src_port'] = 0
                features['dst_port'] = 0
                features['tcp_flags'] = 0
                features['window_size'] = 0
                features['seq_num'] = 0
                features['ack_num'] = 0
                features['transport'] = 'OTHER'
            
            # ICMP layer
            if hasattr(packet, 'icmp'):
                features['icmp_type'] = int(packet.icmp.type) if hasattr(packet.icmp, 'type') else 0
                features['icmp_code'] = int(packet.icmp.code) if hasattr(packet.icmp, 'code') else 0
            else:
                features['icmp_type'] = -1
                features['icmp_code'] = -1
            
            # DNS layer
            if hasattr(packet, 'dns'):
                features['dns_query'] = packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else None
                features['dns_response_code'] = int(packet.dns.flags_rcode) if hasattr(packet.dns, 'flags_rcode') else 0
            else:
                features['dns_query'] = None
                features['dns_response_code'] = -1
            
            # HTTP layer
            if hasattr(packet, 'http'):
                features['http_method'] = packet.http.request_method if hasattr(packet.http, 'request_method') else None
                features['http_uri'] = packet.http.request_uri if hasattr(packet.http, 'request_uri') else None
                features['http_user_agent'] = packet.http.user_agent if hasattr(packet.http, 'user_agent') else None
                features['http_status'] = int(packet.http.response_code) if hasattr(packet.http, 'response_code') else 0
            else:
                features['http_method'] = None
                features['http_uri'] = None
                features['http_user_agent'] = None
                features['http_status'] = 0
            
            return features
            
        except Exception as e:
            logger.debug(f"Feature extraction error: {e}")
            return None
    
    def _parse_tcp_flags(self, tcp_layer) -> int:
        """
        Parse TCP flags into integer
        
        Args:
            tcp_layer: PyShark TCP layer
            
        Returns:
            Integer representation of TCP flags
        """
        flags = 0
        
        try:
            if hasattr(tcp_layer, 'flags_syn') and tcp_layer.flags_syn == '1':
                flags |= 0x02
            if hasattr(tcp_layer, 'flags_ack') and tcp_layer.flags_ack == '1':
                flags |= 0x10
            if hasattr(tcp_layer, 'flags_fin') and tcp_layer.flags_fin == '1':
                flags |= 0x01
            if hasattr(tcp_layer, 'flags_rst') and tcp_layer.flags_rst == '1':
                flags |= 0x04
            if hasattr(tcp_layer, 'flags_push') and tcp_layer.flags_push == '1':
                flags |= 0x08
            if hasattr(tcp_layer, 'flags_urg') and tcp_layer.flags_urg == '1':
                flags |= 0x20
        except Exception as e:
            logger.debug(f"TCP flag parsing error: {e}")
        
        return flags
    
    def extract_flow_features(self, df: pd.DataFrame, window: int = 60) -> pd.DataFrame:
        """
        Aggregate packets into flow-level features
        
        Args:
            df: DataFrame with packet-level features
            window: Time window in seconds
            
        Returns:
            DataFrame with flow-level features
        """
        if df.empty:
            return pd.DataFrame()
        
        logger.info(f"Extracting flow features with {window}s window")
        
        # Create flow identifier
        df['flow_id'] = (
            df['src_ip'].astype(str) + ':' + df['src_port'].astype(str) + '-' +
            df['dst_ip'].astype(str) + ':' + df['dst_port'].astype(str) + '-' +
            df['protocol'].astype(str)
        )
        
        # Time-based grouping
        df['time_window'] = (df['timestamp'] // window).astype(int)
        
        # Aggregate by flow and time window
        flow_features = df.groupby(['flow_id', 'time_window']).agg({
            'length': ['sum', 'mean', 'std', 'min', 'max', 'count'],
            'tcp_flags': lambda x: x.mode()[0] if len(x) > 0 else 0,
            'window_size': 'mean',
            'ttl': 'mean',
            'protocol': 'first',
            'src_ip': 'first',
            'dst_ip': 'first',
            'src_port': 'first',
            'dst_port': 'first',
            'timestamp': ['min', 'max']
        }).reset_index()
        
        # Flatten column names
        flow_features.columns = ['_'.join(col).strip('_') for col in flow_features.columns.values]
        
        # Calculate duration
        flow_features['duration'] = flow_features['timestamp_max'] - flow_features['timestamp_min']
        
        # Packets per second
        flow_features['packets_per_sec'] = flow_features['length_count'] / (flow_features['duration'] + 1e-6)
        
        logger.info(f"Extracted {len(flow_features)} flows")
        
        return flow_features
