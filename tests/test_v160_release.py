"""
Smoke tests for v1.6.0 release verification
Quick validation that all major components are working
"""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestV160Features:
    """Test v1.6.0 specific features"""

    def test_tensorflow_cuda_fix_applied(self):
        """Verify TensorFlow CUDA segfault fix is in place"""
        model_path = Path(__file__).parent.parent / "src" / "core" / "model.py"
        content = model_path.read_text()

        assert "CUDA_VISIBLE_DEVICES" in content, "Should disable CUDA"
        assert "TF_CPP_MIN_LOG_LEVEL" in content, "Should suppress TF logs"
        assert "tf.config.set_visible_devices" in content, "Should disable GPU"

    def test_tcp_udp_filters_implemented(self):
        """Verify TCP/UDP filtering is implemented"""
        tcp_udp_path = Path(__file__).parent.parent / "app" / "panels" / "tcp_udp_panel.py"
        content = tcp_udp_path.read_text()

        assert "_ip_filter" in content, "Should have IP filter widget"
        assert "_port_filter" in content, "Should have port filter widget"
        assert "ip_filter" in content, "Should handle IP filter param"
        assert "port_filter" in content, "Should handle port filter param"

    def test_protocol_panel_filters_implemented(self):
        """Verify Protocol panel filtering is implemented"""
        protocol_path = Path(__file__).parent.parent / "app" / "panels" / "protocol_panel.py"
        content = protocol_path.read_text()

        assert "_ip_filter" in content, "Should have IP filter widget"
        assert "_port_filter" in content, "Should have port filter widget"
        assert "ip_filter" in content, "Should handle IP filter param"
        assert "port_filter" in content, "Should handle port filter param"

    def test_analyzer_filter_methods_updated(self):
        """Verify protocol analyzers have filter parameters"""
        analyzers = [
            "tcp_analyzer.py",
            "udp_analyzer.py",
            "http_analyzer.py",
            "https_analyzer.py",
            "dns_analyzer.py",
            "icmp_analyzer.py",
            "dhcp_analyzer.py"
        ]

        for analyzer_file in analyzers:
            analyzer_path = Path(__file__).parent.parent / "src" / "protocols" / analyzer_file
            if analyzer_path.exists():
                content = analyzer_path.read_text()
                assert "ip_filter" in content, f"{analyzer_file} should support ip_filter"
                assert "port_filter" in content, f"{analyzer_file} should support port_filter"

    def test_documentation_updated(self):
        """Verify documentation reflects v1.6.0"""
        docs_to_check = [
            "RELEASE_NOTES.md",
            "README.md",
            "BUILD_GUIDE.md"
        ]

        for doc in docs_to_check:
            doc_path = Path(__file__).parent.parent / doc
            if doc_path.exists():
                content = doc_path.read_text()
                # Should mention v1.6.0 or July 2026
                assert "v1.6" in content or "July 2026" in content, \
                    f"{doc} should mention v1.6.0"


class TestReleaseReadiness:
    """Test that the release is ready for building"""

    def test_requirements_file_exists(self):
        """Verify requirements.txt exists"""
        req_path = Path(__file__).parent.parent / "requirements.txt"
        assert req_path.exists(), "requirements.txt should exist"

    def test_build_spec_exists(self):
        """Verify PyInstaller spec file exists"""
        spec_path = Path(__file__).parent.parent / "installer" / "ai_wireshark.spec"
        assert spec_path.exists(), "PyInstaller spec file should exist"

    def test_setup_py_exists(self):
        """Verify setup.py exists for packaging"""
        setup_path = Path(__file__).parent.parent / "setup.py"
        assert setup_path.exists(), "setup.py should exist"

    def test_no_obvious_syntax_errors(self):
        """Test that critical Python files have no syntax errors"""
        import ast

        critical_files = [
            "app/main.py",
            "src/core/model.py",
            "src/api/cli.py",
            "src/protocols/tcp_analyzer.py",
        ]

        for file_path in critical_files:
            full_path = Path(__file__).parent.parent / file_path
            if full_path.exists():
                try:
                    with open(full_path, 'r') as f:
                        ast.parse(f.read())
                except SyntaxError as e:
                    pytest.fail(f"Syntax error in {file_path}: {e}")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
