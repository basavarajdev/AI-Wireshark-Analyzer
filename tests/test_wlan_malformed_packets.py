#!/usr/bin/env python3
"""
Test WLAN analyzer's validation of status codes and reason codes.
Ensures malformed packets with invalid codes are properly excluded from analysis.
"""

import pytest
import pandas as pd
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.protocols.wlan_analyzer import (
    WLANAnalyzer, is_valid_status_code, is_valid_reason_code,
    MAX_VALID_STATUS_CODE, MAX_VALID_REASON_CODE
)


class TestStatusCodeValidation:
    """Test IEEE 802.11-2020 status code validation."""

    def test_max_valid_status_code_is_93(self):
        """Verify max valid status code is 93 per IEEE 802.11-2020."""
        assert MAX_VALID_STATUS_CODE == 93

    def test_valid_status_code_zero(self):
        """Status code 0 (Success) is valid."""
        assert is_valid_status_code(0) is True

    def test_valid_status_code_1(self):
        """Status code 1 (Unspecified failure) is valid."""
        assert is_valid_status_code(1) is True

    def test_valid_status_code_93(self):
        """Status code 93 (max) is valid."""
        assert is_valid_status_code(93) is True

    def test_valid_status_code_in_range(self):
        """All codes 0-93 should be valid."""
        for code in [0, 1, 15, 30, 53, 72, 93]:
            assert is_valid_status_code(code) is True, f"Code {code} should be valid"

    def test_invalid_status_code_negative(self):
        """Negative status codes are invalid."""
        assert is_valid_status_code(-1) is False

    def test_invalid_status_code_94(self):
        """Status code 94 (beyond max) is invalid."""
        assert is_valid_status_code(94) is False

    def test_invalid_status_code_above_max(self):
        """Status codes above max are invalid."""
        invalid_codes = [100, 257, 1000, 57773, 53551, 47096, 64009]
        for code in invalid_codes:
            assert is_valid_status_code(code) is False, f"Code {code} should be invalid"

    def test_observed_invalid_status_codes_from_malformed_packets(self):
        """Test the specific invalid status codes from the user's report."""
        observed_codes = [57773, 53551, 47096, 30, 64009]
        # Note: 30 is actually valid (REFUSED_TEMPORARILY), so only others should be invalid
        for code in [57773, 53551, 47096, 64009]:
            assert is_valid_status_code(code) is False, f"Malformed code {code} should be invalid"
        # But 30 should be valid
        assert is_valid_status_code(30) is True, "Code 30 is valid per IEEE 802.11-2020"


class TestReasonCodeValidation:
    """Test IEEE 802.11-2020 reason code validation."""

    def test_max_valid_reason_code_is_50(self):
        """Verify max valid reason code is 50 per IEEE 802.11-2020."""
        assert MAX_VALID_REASON_CODE == 50

    def test_valid_reason_code_zero(self):
        """Reason code 0 (reserved) is technically valid."""
        assert is_valid_reason_code(0) is True

    def test_valid_reason_code_3(self):
        """Reason code 3 (STA leaving BSS) is valid."""
        assert is_valid_reason_code(3) is True

    def test_valid_reason_code_50(self):
        """Reason code 50 (max, SAE password unavailable) is valid."""
        assert is_valid_reason_code(50) is True

    def test_valid_reason_code_in_range(self):
        """All codes 0-50 should be valid."""
        for code in [0, 1, 3, 14, 15, 22, 47, 50]:
            assert is_valid_reason_code(code) is True, f"Code {code} should be valid"

    def test_invalid_reason_code_negative(self):
        """Negative reason codes are invalid."""
        assert is_valid_reason_code(-1) is False

    def test_invalid_reason_code_51(self):
        """Reason code 51 (beyond max) is invalid."""
        assert is_valid_reason_code(51) is False

    def test_invalid_reason_code_above_max(self):
        """Reason codes above max are invalid."""
        invalid_codes = [51, 100, 256, 1000, 10452, 22675, 11098, 55295]
        for code in invalid_codes:
            assert is_valid_reason_code(code) is False, f"Code {code} should be invalid"

    def test_observed_invalid_reason_codes_from_malformed_packets(self):
        """Test the specific invalid reason codes from the user's report."""
        observed_codes = [10452, 22675, 11098, 55295]
        for code in observed_codes:
            assert is_valid_reason_code(code) is False, f"Malformed code {code} should be invalid"


class TestMalformedPacketExclusion:
    """Test that malformed packets are properly excluded from analysis."""

    def test_wlan_analyzer_initializes_malformed_packet_counters(self):
        """Verify the analyzer tracks malformed packets."""
        analyzer = WLANAnalyzer()
        
        # Create a minimal test DataFrame with an invalid status code
        df = pd.DataFrame([
            {
                'timestamp': 0.0,
                'length': 100,
                'type_subtype': '0x0001',  # Association Response
                'sa': '00:11:22:33:44:55',
                'da': 'aa:bb:cc:dd:ee:ff',
                'ta': None,
                'ra': None,
                'bssid': '00:11:22:33:44:55',
                'seq': 1,
                'duration': 0,
                'retry': 0,
                'protected': 0,
                'pwrmgt': 0,
                'signal_dbm': -60,
                'noise_dbm': -90,
                'channel': 6,
                'frequency': 2437,
                'data_rate': 54.0,
                'phy': '802.11g',
                'ssid': 'TestSSID',
                'status_code': 57773,  # MALFORMED - beyond max (93)
                'reason_code': 0,
                'rsn_version': 0,
                'eapol_msg_nr': 0,
                'auth_seq': 0,
                'auth_alg': 0,
                'akm_type': 0,
                'capabilities': 0,
                'category_code': 0,
                'ba_buffer_size': 0,
                'action_code': 0,
                'ccmp_pn': 0,
            },
        ])
        
        # Run failure detection
        result = analyzer._detect_connection_failures(df)
        
        # Verify the malformed packet was excluded
        assert 'malformed_packets' in result
        assert result['malformed_packets']['status_code_invalid'] == 1
        assert result['malformed_packets']['reason_code_invalid'] == 0
        # And the failure should NOT be in the detected failures
        assert not result.get('failure_details', []), "Malformed packet should not be in failure_details"

    def test_wlan_analyzer_excludes_invalid_reason_codes(self):
        """Verify invalid reason codes are excluded from deauthentication analysis."""
        analyzer = WLANAnalyzer()
        
        # Create a test DataFrame with invalid reason codes
        df = pd.DataFrame([
            {
                'timestamp': 0.0,
                'length': 100,
                'type_subtype': '0x000c',  # Deauthentication
                'sa': '00:11:22:33:44:55',
                'da': 'aa:bb:cc:dd:ee:ff',
                'ta': None,
                'ra': None,
                'bssid': '00:11:22:33:44:55',
                'seq': 1,
                'duration': 0,
                'retry': 0,
                'protected': 0,
                'pwrmgt': 0,
                'signal_dbm': -60,
                'noise_dbm': -90,
                'channel': 6,
                'frequency': 2437,
                'data_rate': 54.0,
                'phy': '802.11g',
                'ssid': 'TestSSID',
                'status_code': 0,
                'reason_code': 10452,  # MALFORMED - beyond max (50)
                'rsn_version': 0,
                'eapol_msg_nr': 0,
                'auth_seq': 0,
                'auth_alg': 0,
                'akm_type': 0,
                'capabilities': 0,
                'category_code': 0,
                'ba_buffer_size': 0,
                'action_code': 0,
                'ccmp_pn': 0,
            },
        ])
        
        result = analyzer._detect_connection_failures(df)
        
        assert 'malformed_packets' in result
        assert result['malformed_packets']['reason_code_invalid'] == 1
        assert not result.get('failure_details', []), "Malformed packet should not be in failure_details"

    def test_wlan_analyzer_includes_valid_codes(self):
        """Verify valid codes are still included in analysis."""
        analyzer = WLANAnalyzer()
        
        # Create a test DataFrame with valid status code (wrong PSK)
        df = pd.DataFrame([
            {
                'timestamp': 0.0,
                'length': 100,
                'type_subtype': '0x0001',  # Association Response
                'sa': '00:11:22:33:44:55',
                'da': 'aa:bb:cc:dd:ee:ff',
                'ta': None,
                'ra': None,
                'bssid': '00:11:22:33:44:55',
                'seq': 1,
                'duration': 0,
                'retry': 0,
                'protected': 0,
                'pwrmgt': 0,
                'signal_dbm': -60,
                'noise_dbm': -90,
                'channel': 6,
                'frequency': 2437,
                'data_rate': 54.0,
                'phy': '802.11g',
                'ssid': 'TestSSID',
                'status_code': 15,  # Valid - Wrong credentials
                'reason_code': 0,
                'rsn_version': 0,
                'eapol_msg_nr': 0,
                'auth_seq': 0,
                'auth_alg': 0,
                'akm_type': 0,
                'capabilities': 0,
                'category_code': 0,
                'ba_buffer_size': 0,
                'action_code': 0,
                'ccmp_pn': 0,
            },
        ])
        
        result = analyzer._detect_connection_failures(df)
        
        # Verify no malformed packets were excluded
        assert result['malformed_packets']['status_code_invalid'] == 0
        # And the valid failure should be detected
        assert result.get('detected') is True
        assert len(result.get('failure_details', [])) == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
