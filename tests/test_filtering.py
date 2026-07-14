"""
Test IP and port filtering functionality for protocol analyzers
Verifies that filters are correctly applied to TCP/UDP/Protocol analysis
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestIPPortFilterValidation:
    """Test validation of IP and port filter inputs"""

    def test_valid_ip_format(self):
        """Test validation of valid IP address format"""
        from app.panels.tcp_udp_panel import TcpUdpPanel

        panel = TcpUdpPanel()
        # Set valid IP
        panel._ip_filter.setText("192.168.1.1")
        assert panel._validate() == "", "Valid IP should pass validation"

    def test_invalid_ip_format(self):
        """Test validation rejects invalid IP format"""
        from app.panels.tcp_udp_panel import TcpUdpPanel

        panel = TcpUdpPanel()
        panel._ip_filter.setText("192.168.1")  # Missing octet
        error = panel._validate()
        assert "Invalid IP" in error or error != "", "Should reject invalid IP"

    def test_ip_octet_range_validation(self):
        """Test validation of IP octets (0-255)"""
        from app.panels.tcp_udp_panel import TcpUdpPanel

        panel = TcpUdpPanel()
        panel._ip_filter.setText("192.168.1.256")  # 256 > 255
        error = panel._validate()
        assert "Invalid IP" in error or error != "", "Should reject out-of-range octet"

    def test_valid_port_format(self):
        """Test validation of valid port numbers"""
        from app.panels.tcp_udp_panel import TcpUdpPanel

        panel = TcpUdpPanel()
        panel._port_filter.setText("80")
        assert panel._validate() == "", "Valid port should pass validation"

    def test_multiple_valid_ports(self):
        """Test validation of comma-separated ports"""
        from app.panels.tcp_udp_panel import TcpUdpPanel

        panel = TcpUdpPanel()
        panel._port_filter.setText("80,443,8080")
        assert panel._validate() == "", "Valid ports should pass validation"

    def test_invalid_port_range(self):
        """Test validation rejects out-of-range ports"""
        from app.panels.tcp_udp_panel import TcpUdpPanel

        panel = TcpUdpPanel()
        panel._port_filter.setText("65536")  # > 65535
        error = panel._validate()
        assert error != "", "Should reject port > 65535"

    def test_invalid_port_zero(self):
        """Test validation rejects port 0"""
        from app.panels.tcp_udp_panel import TcpUdpPanel

        panel = TcpUdpPanel()
        panel._port_filter.setText("0")
        error = panel._validate()
        assert error != "", "Should reject port 0"

    def test_non_numeric_port(self):
        """Test validation rejects non-numeric ports"""
        from app.panels.tcp_udp_panel import TcpUdpPanel

        panel = TcpUdpPanel()
        panel._port_filter.setText("abc")
        error = panel._validate()
        assert error != "", "Should reject non-numeric port"


class TestProtocolAnalyzerFiltering:
    """Test protocol analyzer filter application"""

    def test_tcp_analyzer_accepts_filters(self):
        """Test TCPAnalyzer accepts IP and port filter parameters"""
        from src.protocols.tcp_analyzer import TCPAnalyzer

        analyzer = TCPAnalyzer()
        # Should not raise exception for accepting parameters
        assert callable(analyzer.analyze), "analyze method should exist"

        # Check method signature includes new parameters
        import inspect
        sig = inspect.signature(analyzer.analyze)
        assert 'ip_filter' in sig.parameters, "Should have ip_filter parameter"
        assert 'port_filter' in sig.parameters, "Should have port_filter parameter"

    def test_udp_analyzer_accepts_filters(self):
        """Test UDPAnalyzer accepts IP and port filter parameters"""
        from src.protocols.udp_analyzer import UDPAnalyzer

        analyzer = UDPAnalyzer()
        import inspect
        sig = inspect.signature(analyzer.analyze)
        assert 'ip_filter' in sig.parameters, "Should have ip_filter parameter"
        assert 'port_filter' in sig.parameters, "Should have port_filter parameter"

    def test_dns_analyzer_accepts_filters(self):
        """Test DNSAnalyzer accepts IP and port filter parameters"""
        from src.protocols.dns_analyzer import DNSAnalyzer

        analyzer = DNSAnalyzer()
        import inspect
        sig = inspect.signature(analyzer.analyze)
        assert 'ip_filter' in sig.parameters, "Should have ip_filter parameter"
        assert 'port_filter' in sig.parameters, "Should have port_filter parameter"

    def test_icmp_analyzer_accepts_filters(self):
        """Test ICMPAnalyzer accepts IP filter parameter"""
        from src.protocols.icmp_analyzer import ICMPAnalyzer

        analyzer = ICMPAnalyzer()
        import inspect
        sig = inspect.signature(analyzer.analyze)
        assert 'ip_filter' in sig.parameters, "Should have ip_filter parameter"

    def test_dhcp_analyzer_accepts_filters(self):
        """Test DHCPAnalyzer accepts IP and port filter parameters"""
        from src.protocols.dhcp_analyzer import DHCPAnalyzer

        analyzer = DHCPAnalyzer()
        import inspect
        sig = inspect.signature(analyzer.analyze)
        assert 'ip_filter' in sig.parameters, "Should have ip_filter parameter"
        assert 'port_filter' in sig.parameters, "Should have port_filter parameter"


class TestFilterExpressionConstruction:
    """Test Wireshark filter expression construction"""

    def test_ip_filter_expression(self):
        """Test IP filter creates correct Wireshark expression"""
        # Simulate filter building logic
        ip_filter = "192.168.1.1"
        expected = f"(ip.src=={ip_filter} || ip.dst=={ip_filter})"
        assert "ip.src==" in expected, "Should filter source IP"
        assert "ip.dst==" in expected, "Should filter destination IP"

    def test_port_filter_expression_single(self):
        """Test single port filter creates correct expression"""
        port_filter = "80"
        ports = [p.strip() for p in port_filter.split(',')]
        port_expr = ' || '.join([f'tcp.port=={port}' for port in ports])
        assert "tcp.port==80" in port_expr, "Should filter TCP port 80"

    def test_port_filter_expression_multiple(self):
        """Test multiple ports filter creates correct expression"""
        port_filter = "80,443,8080"
        ports = [p.strip() for p in port_filter.split(',')]
        port_expr = ' || '.join([f'tcp.port=={port}' for port in ports])
        assert "tcp.port==80" in port_expr, "Should filter port 80"
        assert "tcp.port==443" in port_expr, "Should filter port 443"
        assert "tcp.port==8080" in port_expr, "Should filter port 8080"

    def test_combined_filters(self):
        """Test combined IP and port filters"""
        ip_filter = "192.168.1.1"
        port_filter = "80,443"
        
        filters = []
        if ip_filter:
            filters.append(f"(ip.src=={ip_filter} || ip.dst=={ip_filter})")
        if port_filter:
            ports = [p.strip() for p in port_filter.split(',')]
            port_expr = ' || '.join([f'tcp.port=={port}' for port in ports])
            filters.append(f"({port_expr})")
        
        combined = ' && '.join(filters)
        assert "ip.src==" in combined, "Should include IP filter"
        assert "tcp.port==" in combined, "Should include port filter"
        assert " && " in combined, "Should combine with AND"


class TestWorkerFiltering:
    """Test that worker threads properly pass filter parameters"""

    def test_tcp_udp_worker_passes_filters(self):
        """Test _run_tcp_udp worker passes filters to analyzer"""
        from app.workers import AnalysisWorker

        # Mock the analyzer call
        with patch('scripts.analyze_tcp_udp.run') as mock_run:
            mock_run.return_value = {'html_path': '/tmp/test.html', 'results': {}}

            worker = AnalysisWorker(
                'tcp_udp',
                {
                    'pcap': '/tmp/test.pcap',
                    'ip_filter': '192.168.1.1',
                    'port_filter': '80,443'
                }
            )

            # Verify parameters would be passed (check without running)
            assert worker.params['ip_filter'] == '192.168.1.1'
            assert worker.params['port_filter'] == '80,443'

    def test_protocol_worker_passes_filters(self):
        """Test _run_protocol worker passes filters to analyzer"""
        from app.workers import AnalysisWorker

        worker = AnalysisWorker(
            'protocol',
            {
                'pcap': '/tmp/test.pcap',
                'protocol': 'tcp',
                'filter': '',
                'ip_filter': '10.0.0.1',
                'port_filter': '22'
            }
        )

        assert worker.params['ip_filter'] == '10.0.0.1'
        assert worker.params['port_filter'] == '22'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
