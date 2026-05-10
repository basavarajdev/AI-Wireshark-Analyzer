"""
Feature Engineering Module
Transform raw packet data into ML-ready features
"""

import pandas as pd
import numpy as np
from loguru import logger
from typing import List, Dict
from src.core.utils import ip_to_int, calculate_entropy, is_private_ip, get_time_of_day


class FeatureEngineer:
    """Engineer features from packet data for ML models"""
    
    def __init__(self):
        """Initialize FeatureEngineer"""
        pass
    
    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create ML-ready features from packet data
        
        Args:
            df: Cleaned packet DataFrame
            
        Returns:
            DataFrame with engineered features
        """
        logger.info(f"Engineering features for {len(df)} packets")
        
        df_features = df.copy()
        
        # IP-based features
        df_features = self._add_ip_features(df_features)
        
        # Port-based features
        df_features = self._add_port_features(df_features)
        
        # Protocol features
        df_features = self._add_protocol_features(df_features)
        
        # Statistical features
        df_features = self._add_statistical_features(df_features)
        
        # Time-based features
        df_features = self._add_time_features(df_features)
        
        # DNS-specific features
        if 'dns_query' in df_features.columns:
            df_features = self._add_dns_features(df_features)
        
        # HTTP-specific features
        if 'http_uri' in df_features.columns:
            df_features = self._add_http_features(df_features)
        
        logger.info(f"Engineered {len(df_features.columns)} features")
        
        return df_features
    
    def _add_ip_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add IP-based features"""
        
        if 'src_ip' in df.columns:
            df['src_ip_int'] = df['src_ip'].apply(ip_to_int)
            df['src_ip_is_private'] = df['src_ip'].apply(is_private_ip).astype(int)
        
        if 'dst_ip' in df.columns:
            df['dst_ip_int'] = df['dst_ip'].apply(ip_to_int)
            df['dst_ip_is_private'] = df['dst_ip'].apply(is_private_ip).astype(int)
        
        # IP diversity (within groups)
        if 'src_ip' in df.columns and 'dst_ip' in df.columns:
            df['is_same_subnet'] = (
                (df['src_ip_int'] >> 24) == (df['dst_ip_int'] >> 24)
            ).astype(int)
        
        return df
    
    def _add_port_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add port-based features"""
        
        if 'src_port' in df.columns:
            df['src_port_is_privileged'] = (df['src_port'] < 1024).astype(int)
            df['src_port_is_ephemeral'] = (df['src_port'] >= 49152).astype(int)
        
        if 'dst_port' in df.columns:
            df['dst_port_is_privileged'] = (df['dst_port'] < 1024).astype(int)
            df['dst_port_is_ephemeral'] = (df['dst_port'] >= 49152).astype(int)
        
        # Well-known service ports
        if 'dst_port' in df.columns:
            df['is_http'] = df['dst_port'].isin([80, 8080]).astype(int)
            df['is_https'] = (df['dst_port'] == 443).astype(int)
            df['is_dns'] = (df['dst_port'] == 53).astype(int)
            df['is_ssh'] = (df['dst_port'] == 22).astype(int)
            df['is_ftp'] = df['dst_port'].isin([20, 21]).astype(int)
        
        return df
    
    def _add_protocol_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add protocol-based features"""
        
        if 'protocol' in df.columns:
            # One-hot encode common protocols
            df['is_tcp'] = (df['transport'] == 'TCP').astype(int) if 'transport' in df.columns else 0
            df['is_udp'] = (df['transport'] == 'UDP').astype(int) if 'transport' in df.columns else 0
            df['is_icmp'] = (df['protocol'] == 'ICMP').astype(int)
        
        # TCP flags breakdown
        if 'tcp_flags' in df.columns:
            df['tcp_flag_syn'] = ((df['tcp_flags'] & 0x02) > 0).astype(int)
            df['tcp_flag_ack'] = ((df['tcp_flags'] & 0x10) > 0).astype(int)
            df['tcp_flag_fin'] = ((df['tcp_flags'] & 0x01) > 0).astype(int)
            df['tcp_flag_rst'] = ((df['tcp_flags'] & 0x04) > 0).astype(int)
            df['tcp_flag_psh'] = ((df['tcp_flags'] & 0x08) > 0).astype(int)
            df['tcp_flag_urg'] = ((df['tcp_flags'] & 0x20) > 0).astype(int)
        
        return df
    
    def _add_statistical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add statistical features"""
        
        if 'length' in df.columns:
            # Length categories
            df['is_small_packet'] = (df['length'] < 100).astype(int)
            df['is_medium_packet'] = ((df['length'] >= 100) & (df['length'] < 1000)).astype(int)
            df['is_large_packet'] = (df['length'] >= 1000).astype(int)
        
        if 'ttl' in df.columns:
            # TTL categories (common OS values)
            df['ttl_category'] = pd.cut(
                df['ttl'],
                bins=[0, 32, 64, 128, 256],
                labels=[0, 1, 2, 3]
            ).astype(float).fillna(0)
        
        return df
    
    def _add_time_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add time-based features"""
        
        if 'timestamp' in df.columns:
            # Time of day
            df['time_of_day'] = df['timestamp'].apply(get_time_of_day)
            df['is_business_hours'] = df['time_of_day'].isin(['morning', 'afternoon']).astype(int)
            
            # Time deltas (if sorted)
            df['time_delta'] = df['timestamp'].diff().fillna(0)
            df['time_delta'] = df['time_delta'].clip(lower=0, upper=60)  # Cap at 60 seconds
        
        return df
    
    def _add_dns_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add DNS-specific features"""
        
        if 'dns_query' in df.columns:
            # Query length
            df['dns_query_length'] = df['dns_query'].apply(
                lambda x: len(str(x)) if pd.notna(x) else 0
            )
            
            # Subdomain count
            df['dns_subdomain_count'] = df['dns_query'].apply(
                lambda x: str(x).count('.') if pd.notna(x) else 0
            )
            
            # Query entropy (detect DGA)
            df['dns_query_entropy'] = df['dns_query'].apply(
                lambda x: calculate_entropy(str(x)) if pd.notna(x) else 0
            )
            
            # Contains numbers
            df['dns_has_numbers'] = df['dns_query'].apply(
                lambda x: int(any(c.isdigit() for c in str(x))) if pd.notna(x) else 0
            )
        
        if 'dns_response_code' in df.columns:
            df['is_dns_nxdomain'] = (df['dns_response_code'] == 3).astype(int)
        
        return df
    
    def _add_http_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add HTTP-specific features"""
        
        if 'http_uri' in df.columns:
            # URI length
            df['http_uri_length'] = df['http_uri'].apply(
                lambda x: len(str(x)) if pd.notna(x) else 0
            )
            
            # Contains query parameters
            df['http_has_params'] = df['http_uri'].apply(
                lambda x: int('?' in str(x)) if pd.notna(x) else 0
            )
            
            # URI entropy
            df['http_uri_entropy'] = df['http_uri'].apply(
                lambda x: calculate_entropy(str(x)) if pd.notna(x) else 0
            )
        
        if 'http_method' in df.columns:
            # Common methods
            df['is_http_get'] = (df['http_method'] == 'GET').astype(int)
            df['is_http_post'] = (df['http_method'] == 'POST').astype(int)
        
        if 'http_user_agent' in df.columns:
            # Suspicious user agents
            suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan', 'python', 'curl']
            df['http_suspicious_agent'] = df['http_user_agent'].apply(
                lambda x: int(any(agent in str(x).lower() for agent in suspicious_agents)) 
                if pd.notna(x) else 0
            )
        
        return df
    
    def get_ml_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Get only ML-ready numeric features
        
        Args:
            df: DataFrame with all features
            
        Returns:
            DataFrame with only numeric ML features
        """
        # Select only numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        
        # Exclude identifiers
        exclude_cols = ['src_ip_int', 'dst_ip_int', 'seq_num', 'ack_num']
        numeric_cols = [col for col in numeric_cols if col not in exclude_cols]
        
        df_ml = df[numeric_cols].copy()
        
        # Handle inf and NaN
        df_ml = df_ml.replace([np.inf, -np.inf], np.nan)
        df_ml = df_ml.fillna(0)
        
        logger.info(f"Selected {len(df_ml.columns)} ML features")
        
        return df_ml
