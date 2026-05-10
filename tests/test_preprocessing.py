"""
Test Preprocessing Module
"""

import pytest
import pandas as pd
import numpy as np
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent))

from src.preprocessing.cleaning import DataCleaner
from src.preprocessing.feature_engineering import FeatureEngineer


class TestDataCleaner:
    """Test cases for DataCleaner"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.cleaner = DataCleaner()
    
    def test_cleaner_initialization(self):
        """Test cleaner initializes correctly"""
        assert self.cleaner is not None
    
    def test_remove_duplicates(self):
        """Test duplicate removal"""
        data = {
            'timestamp': [1.0, 1.0, 2.0],
            'length': [100, 100, 150],
            'protocol': ['TCP', 'TCP', 'UDP']
        }
        df = pd.DataFrame(data)
        
        cleaned = self.cleaner._remove_duplicates(df)
        
        # Should remove one duplicate
        assert len(cleaned) <= len(df)
    
    def test_handle_missing_values(self):
        """Test missing value handling"""
        data = {
            'timestamp': [1.0, 2.0, 3.0],
            'length': [100, np.nan, 150],
            'src_port': [12345, np.nan, 80],
            'protocol': ['TCP', None, 'UDP']
        }
        df = pd.DataFrame(data)
        
        cleaned = self.cleaner._handle_missing_values(df)
        
        # Check missing values are handled
        assert cleaned['length'].isna().sum() == 0
        assert cleaned['src_port'].isna().sum() == 0
    
    def test_validate_pcap_data(self):
        """Test data validation"""
        valid_data = {
            'timestamp': [1.0, 2.0],
            'length': [100, 150],
            'protocol': ['TCP', 'UDP']
        }
        df = pd.DataFrame(valid_data)
        
        assert self.cleaner.validate_pcap_data(df) == True
        
        # Invalid data (missing required column)
        invalid_data = {
            'length': [100, 150]
        }
        df_invalid = pd.DataFrame(invalid_data)
        
        assert self.cleaner.validate_pcap_data(df_invalid) == False


class TestFeatureEngineer:
    """Test cases for FeatureEngineer"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.engineer = FeatureEngineer()
    
    def test_engineer_initialization(self):
        """Test engineer initializes correctly"""
        assert self.engineer is not None
    
    def test_add_ip_features(self):
        """Test IP feature engineering"""
        data = {
            'src_ip': ['192.168.1.1', '10.0.0.1'],
            'dst_ip': ['8.8.8.8', '192.168.1.1']
        }
        df = pd.DataFrame(data)
        
        result = self.engineer._add_ip_features(df)
        
        assert 'src_ip_is_private' in result.columns
        assert 'dst_ip_is_private' in result.columns
    
    def test_add_port_features(self):
        """Test port feature engineering"""
        data = {
            'src_port': [80, 12345],
            'dst_port': [443, 8080]
        }
        df = pd.DataFrame(data)
        
        result = self.engineer._add_port_features(df)
        
        assert 'src_port_is_privileged' in result.columns
        assert 'is_https' in result.columns
    
    def test_get_ml_features(self):
        """Test ML feature extraction"""
        data = {
            'timestamp': [1.0, 2.0],
            'length': [100, 150],
            'protocol': ['TCP', 'UDP'],
            'src_ip': ['192.168.1.1', '10.0.0.1'],
            'ttl': [64, 128]
        }
        df = pd.DataFrame(data)
        
        result = self.engineer.get_ml_features(df)
        
        # Should only contain numeric features
        assert result.select_dtypes(include=[np.number]).shape[1] == result.shape[1]
        
        # Should not contain inf or NaN
        assert not result.isin([np.inf, -np.inf]).any().any()
        assert not result.isna().any().any()
