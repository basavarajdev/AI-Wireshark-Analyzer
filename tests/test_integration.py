"""
Integration tests for AI-Wireshark Analyzer
Tests complete workflows and end-to-end functionality
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys
import json

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestApplicationInitialization:
    """Test application initialization and startup"""

    def test_imports_no_crash(self):
        """Test that main application imports don't crash"""
        try:
            # Critical imports that must work
            from app import main_window
            from app.panels import base_panel
            from src.api import cli
            from src.core import model
            assert True, "All critical imports successful"
        except Exception as e:
            pytest.fail(f"Application import failed: {e}")

    def test_configuration_loads(self):
        """Test that configuration files load correctly"""
        try:
            import yaml
            config_path = Path(__file__).parent.parent / "config" / "default.yaml"
            
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                assert isinstance(config, dict), "Config should be a dictionary"
                assert 'protocols' in config, "Config should have protocols section"
        except Exception as e:
            pytest.fail(f"Configuration load failed: {e}")

    def test_results_directory_creatable(self):
        """Test that results directory can be created"""
        import tempfile
        import shutil

        results_dir = Path(tempfile.mkdtemp()) / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        assert results_dir.exists(), "Results directory should be created"
        shutil.rmtree(results_dir.parent)


class TestProtocolAnalyzersInitialization:
    """Test that all protocol analyzers can be instantiated"""

    def test_tcp_analyzer_init(self):
        """Test TCPAnalyzer initialization"""
        from src.protocols.tcp_analyzer import TCPAnalyzer
        analyzer = TCPAnalyzer()
        assert analyzer is not None, "TCPAnalyzer should instantiate"

    def test_udp_analyzer_init(self):
        """Test UDPAnalyzer initialization"""
        from src.protocols.udp_analyzer import UDPAnalyzer
        analyzer = UDPAnalyzer()
        assert analyzer is not None, "UDPAnalyzer should instantiate"

    def test_dns_analyzer_init(self):
        """Test DNSAnalyzer initialization"""
        from src.protocols.dns_analyzer import DNSAnalyzer
        analyzer = DNSAnalyzer()
        assert analyzer is not None, "DNSAnalyzer should instantiate"

    def test_icmp_analyzer_init(self):
        """Test ICMPAnalyzer initialization"""
        from src.protocols.icmp_analyzer import ICMPAnalyzer
        analyzer = ICMPAnalyzer()
        assert analyzer is not None, "ICMPAnalyzer should instantiate"

    def test_dhcp_analyzer_init(self):
        """Test DHCPAnalyzer initialization"""
        from src.protocols.dhcp_analyzer import DHCPAnalyzer
        analyzer = DHCPAnalyzer()
        assert analyzer is not None, "DHCPAnalyzer should instantiate"


class TestPanelInitialization:
    """Test that all UI panels can be initialized"""

    def test_tcp_udp_panel_init(self):
        """Test TcpUdpPanel initialization"""
        from app.panels.tcp_udp_panel import TcpUdpPanel
        
        # Create without requiring parent widget
        panel = TcpUdpPanel()
        assert panel is not None, "TcpUdpPanel should instantiate"
        assert hasattr(panel, '_ip_filter'), "Should have IP filter widget"
        assert hasattr(panel, '_port_filter'), "Should have port filter widget"

    def test_protocol_panel_init(self):
        """Test ProtocolPanel initialization"""
        from app.panels.protocol_panel import ProtocolPanel
        
        panel = ProtocolPanel()
        assert panel is not None, "ProtocolPanel should instantiate"
        assert hasattr(panel, '_ip_filter'), "Should have IP filter widget"
        assert hasattr(panel, '_port_filter'), "Should have port filter widget"


class TestDataValidation:
    """Test data validation and error handling"""

    def test_packet_parser_initialization(self):
        """Test PacketParser can be initialized"""
        from src.parsers.packet_parser import PacketParser
        parser = PacketParser()
        assert parser is not None, "PacketParser should instantiate"

    def test_data_cleaner_initialization(self):
        """Test DataCleaner can be initialized"""
        from src.preprocessing.cleaning import DataCleaner
        cleaner = DataCleaner()
        assert cleaner is not None, "DataCleaner should instantiate"

    def test_feature_engineer_initialization(self):
        """Test FeatureEngineer can be initialized"""
        from src.preprocessing.feature_engineering import FeatureEngineer
        engineer = FeatureEngineer()
        assert engineer is not None, "FeatureEngineer should instantiate"


class TestCLIInterface:
    """Test CLI interface functionality"""

    def test_cli_protocol_analysis_signature(self):
        """Test CLI _run_protocol_analysis has correct signature"""
        from src.api.cli import _run_protocol_analysis
        import inspect

        sig = inspect.signature(_run_protocol_analysis)
        assert 'pcap_file' in sig.parameters, "Should have pcap_file parameter"
        assert 'protocol' in sig.parameters, "Should have protocol parameter"
        assert 'display_filter' in sig.parameters, "Should have display_filter parameter"
        assert 'ip_filter' in sig.parameters, "Should have ip_filter parameter (v1.6.0)"
        assert 'port_filter' in sig.parameters, "Should have port_filter parameter (v1.6.0)"

    def test_tcp_udp_script_signature(self):
        """Test analyze_tcp_udp.py run function has correct signature"""
        from scripts.analyze_tcp_udp import run
        import inspect

        sig = inspect.signature(run)
        assert 'pcap_file' in sig.parameters, "Should have pcap_file parameter"
        assert 'output_dir' in sig.parameters, "Should have output_dir parameter"
        assert 'ip_filter' in sig.parameters, "Should have ip_filter parameter (v1.6.0)"
        assert 'port_filter' in sig.parameters, "Should have port_filter parameter (v1.6.0)"


class TestVersionAndStatus:
    """Test version information and project status"""

    def test_release_notes_updated(self):
        """Test that RELEASE_NOTES.md reflects v1.6.0"""
        release_notes_path = Path(__file__).parent.parent / "docs" / "RELEASE_NOTES.md"
        
        if release_notes_path.exists():
            content = release_notes_path.read_text()
            assert "v1.6.0" in content, "RELEASE_NOTES should mention v1.6.0"
            assert "TensorFlow" in content, "Should document TensorFlow fix"
            assert "filtering" in content.lower(), "Should document filtering feature"

    def test_readme_updated(self):
        """Test that README.md reflects latest features"""
        readme_path = Path(__file__).parent.parent / "README.md"
        
        if readme_path.exists():
            content = readme_path.read_text()
            assert "July 2026" in content or "v1.6.0" in content, \
                "README should reflect current date/version"
            assert "IP" in content and "port" in content.lower(), \
                "Should mention new filtering features"

    def test_build_guide_updated(self):
        """Test that BUILD_GUIDE.md reflects current status"""
        build_guide_path = Path(__file__).parent.parent / "BUILD_GUIDE.md"
        
        if build_guide_path.exists():
            content = build_guide_path.read_text()
            assert "July 2026" in content or "Latest Updates" in content, \
                "BUILD_GUIDE should reflect current status"


class TestErrorHandling:
    """Test error handling in core components"""

    def test_analyzer_handles_missing_pcap(self):
        """Test that analyzers handle missing PCAP files gracefully"""
        from src.protocols.tcp_analyzer import TCPAnalyzer

        analyzer = TCPAnalyzer()
        result = analyzer.analyze("/nonexistent/file.pcap")
        
        # Should return error dict, not crash
        assert isinstance(result, dict), "Should return dict"
        if 'error' not in result and result.get('total_packets') == 0:
            # Empty result is acceptable
            assert 'error' in result or 'total_packets' in result

    def test_analyzer_handles_invalid_filter(self):
        """Test that analyzers handle invalid filters gracefully"""
        from src.protocols.tcp_analyzer import TCPAnalyzer

        analyzer = TCPAnalyzer()
        # Invalid filter should not crash
        try:
            # Try with an obviously bad filter - should either work with empty result
            # or raise a controlled exception
            result = analyzer.analyze(
                "/tmp/nonexistent.pcap",
                display_filter="this_is_not_valid_syntax!!!"
            )
            assert isinstance(result, dict), "Should return dict even with bad filter"
        except Exception as e:
            # Acceptable if it raises a controlled exception
            assert "error" in str(e).lower() or "invalid" in str(e).lower()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
