"""
Data Cleaning Module
Clean and validate packet data
"""

import pandas as pd
import numpy as np
from loguru import logger
from typing import Optional, List


class DataCleaner:
    """Clean and validate network packet data"""
    
    def __init__(self):
        """Initialize DataCleaner"""
        pass
    
    def clean(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean packet data
        
        Args:
            df: Raw packet DataFrame
            
        Returns:
            Cleaned DataFrame
        """
        logger.info(f"Cleaning data: {len(df)} rows")
        
        df_clean = df.copy()
        
        # Remove duplicates
        df_clean = self._remove_duplicates(df_clean)
        
        # Handle missing values
        df_clean = self._handle_missing_values(df_clean)
        
        # Remove invalid packets
        df_clean = self._remove_invalid_packets(df_clean)
        
        # Fix data types
        df_clean = self._fix_data_types(df_clean)
        
        logger.info(f"Cleaned data: {len(df_clean)} rows ({len(df) - len(df_clean)} removed)")
        
        return df_clean
    
    def _remove_duplicates(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove duplicate packets"""
        initial_count = len(df)
        
        # Remove exact duplicates
        df = df.drop_duplicates()
        
        duplicates_removed = initial_count - len(df)
        if duplicates_removed > 0:
            logger.debug(f"Removed {duplicates_removed} duplicate packets")
        
        return df
    
    def _handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle missing values in packet data"""
        
        # Fill missing ports with 0
        if 'src_port' in df.columns:
            df['src_port'] = df['src_port'].fillna(0)
        if 'dst_port' in df.columns:
            df['dst_port'] = df['dst_port'].fillna(0)
        
        # Fill missing IPs with placeholder
        if 'src_ip' in df.columns:
            df['src_ip'] = df['src_ip'].fillna('0.0.0.0')
        if 'dst_ip' in df.columns:
            df['dst_ip'] = df['dst_ip'].fillna('0.0.0.0')
        
        # Fill missing protocol
        if 'protocol' in df.columns:
            df['protocol'] = df['protocol'].fillna('UNKNOWN')
        
        # Fill missing numeric values with 0
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].fillna(0)
        
        return df
    
    def _remove_invalid_packets(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove packets with invalid data"""
        initial_count = len(df)
        
        # Remove packets with invalid length
        if 'length' in df.columns:
            df = df[df['length'] > 0]
            df = df[df['length'] < 65536]  # Max IP packet size
        
        # Remove packets with invalid timestamp
        if 'timestamp' in df.columns:
            df = df[df['timestamp'] > 0]
        
        # Remove packets with invalid TTL
        if 'ttl' in df.columns:
            df = df[(df['ttl'] >= 0) & (df['ttl'] <= 255)]
        
        # Remove packets with invalid ports
        if 'src_port' in df.columns:
            df = df[(df['src_port'] >= 0) & (df['src_port'] <= 65535)]
        if 'dst_port' in df.columns:
            df = df[(df['dst_port'] >= 0) & (df['dst_port'] <= 65535)]
        
        invalid_removed = initial_count - len(df)
        if invalid_removed > 0:
            logger.debug(f"Removed {invalid_removed} invalid packets")
        
        return df
    
    def _fix_data_types(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fix data types for consistency"""
        
        # Integer columns
        int_cols = ['length', 'src_port', 'dst_port', 'tcp_flags', 
                    'window_size', 'ttl', 'seq_num', 'ack_num']
        for col in int_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
        
        # Float columns
        float_cols = ['timestamp']
        for col in float_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(float)
        
        # String columns
        str_cols = ['protocol', 'src_ip', 'dst_ip', 'transport']
        for col in str_cols:
            if col in df.columns:
                df[col] = df[col].astype(str)
        
        return df
    
    def validate_pcap_data(self, df: pd.DataFrame) -> bool:
        """
        Validate that DataFrame contains required packet data
        
        Args:
            df: Packet DataFrame
            
        Returns:
            True if valid, False otherwise
        """
        required_cols = ['timestamp', 'length', 'protocol']
        
        for col in required_cols:
            if col not in df.columns:
                logger.error(f"Missing required column: {col}")
                return False
        
        if len(df) == 0:
            logger.error("DataFrame is empty")
            return False
        
        logger.info("Data validation passed")
        return True
    
    def filter_by_protocol(self, df: pd.DataFrame, protocols: List[str]) -> pd.DataFrame:
        """
        Filter packets by protocol
        
        Args:
            df: Packet DataFrame
            protocols: List of protocols to keep
            
        Returns:
            Filtered DataFrame
        """
        if 'protocol' not in df.columns:
            logger.warning("Protocol column not found")
            return df
        
        df_filtered = df[df['protocol'].isin(protocols)]
        logger.info(f"Filtered to {len(df_filtered)} packets with protocols: {protocols}")
        
        return df_filtered
    
    def filter_by_time_range(self, df: pd.DataFrame, start_time: float, end_time: float) -> pd.DataFrame:
        """
        Filter packets by time range
        
        Args:
            df: Packet DataFrame
            start_time: Start timestamp
            end_time: End timestamp
            
        Returns:
            Filtered DataFrame
        """
        if 'timestamp' not in df.columns:
            logger.warning("Timestamp column not found")
            return df
        
        df_filtered = df[(df['timestamp'] >= start_time) & (df['timestamp'] <= end_time)]
        logger.info(f"Filtered to {len(df_filtered)} packets in time range")
        
        return df_filtered
