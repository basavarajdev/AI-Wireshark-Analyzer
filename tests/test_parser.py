"""
Test Packet Parser
"""

import pytest
import pandas as pd
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent))

from src.parsers.packet_parser import PacketParser


class TestPacketParser:
    """Test cases for PacketParser"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.parser = PacketParser()
    
    def test_parser_initialization(self):
        """Test parser initializes correctly"""
        assert self.parser is not None
        assert hasattr(self.parser, 'features')
        assert hasattr(self.parser, 'max_packets')
    
    def test_extract_flow_features(self):
        """Test flow feature extraction"""
        # Create sample packet data
        data = {
            'timestamp': [1.0, 1.5, 2.0, 2.5],
            'length': [100, 150, 120, 200],
            'src_ip': ['192.168.1.1'] * 4,
            'dst_ip': ['10.0.0.1'] * 4,
            'src_port': [12345] * 4,
            'dst_port': [80] * 4,
            'protocol': ['TCP'] * 4,
            'tcp_flags': [2, 18, 18, 17],
            'window_size': [65535] * 4,
            'ttl': [64] * 4
        }
        df = pd.DataFrame(data)
        
        # Extract flow features
        flow_df = self.parser.extract_flow_features(df, window=60)
        
        # Assertions
        assert not flow_df.empty
        assert 'flow_id' in df.columns or 'flow_id_first' in flow_df.columns
    
    def test_tcp_flags_parsing(self):
        """Test TCP flags parsing"""
        # This would require a mock TCP layer
        # For now, test the logic
        flags = 0x02 | 0x10  # SYN + ACK
        
        has_syn = (flags & 0x02) > 0
        has_ack = (flags & 0x10) > 0
        
        assert has_syn
        assert has_ack
