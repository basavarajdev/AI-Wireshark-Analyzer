"""Core utility functions"""

import yaml
import os
import sys
from pathlib import Path
from loguru import logger
from typing import Dict, Any
import numpy as np
import pandas as pd


def setup_logging(config_path: str = "config/default.yaml"):
    """
    Setup logging configuration
    
    Args:
        config_path: Path to configuration file
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        log_config = config.get('logging', {})
        log_level = log_config.get('level', 'INFO')
        log_format = log_config.get('format', '[{time:YYYY-MM-DD HH:mm:ss}] {level} | {message}')
        log_file = log_config.get('file', 'logs/ai_wireshark.log')
        
        # Create logs directory
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        
        # Remove default logger
        logger.remove()
        
        # Add console logger
        logger.add(
            sys.stderr,
            format=log_format,
            level=log_level,
            colorize=True
        )
        
        # Add file logger
        logger.add(
            log_file,
            format=log_format,
            level=log_level,
            rotation=log_config.get('rotation', '10 MB'),
            retention=log_config.get('retention', '30 days'),
            compression="zip"
        )
        
        logger.info("Logging initialized")
        
    except Exception as e:
        print(f"Error setting up logging: {e}")


def load_config(config_path: str = "config/default.yaml") -> Dict[str, Any]:
    """
    Load configuration from YAML file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(f"Configuration loaded from {config_path}")
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise


def create_directories(config: Dict[str, Any]):
    """
    Create necessary directories
    
    Args:
        config: Configuration dictionary
    """
    paths = config.get('paths', {})
    
    for path_type, path in paths.items():
        Path(path).mkdir(parents=True, exist_ok=True)
        logger.debug(f"Created directory: {path}")


def ip_to_int(ip: str) -> int:
    """
    Convert IP address to integer
    
    Args:
        ip: IP address string
        
    Returns:
        Integer representation
    """
    if pd.isna(ip) or ip is None:
        return 0
    
    try:
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
               (int(parts[2]) << 8) + int(parts[3])
    except:
        return 0


def normalize_features(df: pd.DataFrame, columns: list = None) -> pd.DataFrame:
    """
    Normalize numerical features to [0, 1] range
    
    Args:
        df: Input DataFrame
        columns: Columns to normalize (None = all numeric)
        
    Returns:
        DataFrame with normalized features
    """
    df_norm = df.copy()
    
    if columns is None:
        columns = df.select_dtypes(include=[np.number]).columns
    
    for col in columns:
        if col in df.columns:
            min_val = df[col].min()
            max_val = df[col].max()
            
            if max_val > min_val:
                df_norm[col] = (df[col] - min_val) / (max_val - min_val)
            else:
                df_norm[col] = 0
    
    return df_norm


def detect_protocol_from_port(port: int) -> str:
    """
    Detect common protocol from port number
    
    Args:
        port: Port number
        
    Returns:
        Protocol name
    """
    common_ports = {
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        23: 'TELNET',
        25: 'SMTP',
        53: 'DNS',
        67: 'DHCP',
        68: 'DHCP',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3389: 'RDP',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        8080: 'HTTP-ALT',
        27017: 'MongoDB'
    }
    
    return common_ports.get(port, 'UNKNOWN')


def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of string
    
    Args:
        data: Input string
        
    Returns:
        Entropy value
    """
    if not data:
        return 0.0
    
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * np.log2(p_x)
    
    return entropy


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is private
    
    Args:
        ip: IP address string
        
    Returns:
        True if private, False otherwise
    """
    if pd.isna(ip) or ip is None:
        return False
    
    try:
        parts = [int(x) for x in ip.split('.')]
        
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        
        # 127.0.0.0/8
        if parts[0] == 127:
            return True
        
        return False
    except:
        return False


def get_time_of_day(timestamp: float) -> str:
    """
    Get time of day category
    
    Args:
        timestamp: Unix timestamp
        
    Returns:
        Time category (morning, afternoon, evening, night)
    """
    from datetime import datetime
    
    hour = datetime.fromtimestamp(timestamp).hour
    
    if 6 <= hour < 12:
        return 'morning'
    elif 12 <= hour < 18:
        return 'afternoon'
    elif 18 <= hour < 22:
        return 'evening'
    else:
        return 'night'
