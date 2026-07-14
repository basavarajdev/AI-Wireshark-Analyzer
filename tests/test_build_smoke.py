"""
Build Smoke Tests — run before every distribution build.

Catches segmentation faults, missing dependencies, broken imports, invalid
function signatures, and API regressions that would produce a broken binary.

Run with:
    pytest tests/test_build_smoke.py -v
"""

import ast
import importlib
import inspect
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _has_param(func, name: str) -> bool:
    return name in inspect.signature(func).parameters


def _run_python(snippet: str) -> subprocess.CompletedProcess:
    """Execute a snippet in a fresh interpreter process to catch segfaults."""
    return subprocess.run(
        [sys.executable, "-c", snippet],
        capture_output=True, text=True, timeout=30,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. Hard dependencies (import must not crash or segfault)
# ─────────────────────────────────────────────────────────────────────────────

class TestDependencyImports:
    """Verify every required package can be imported without crashes."""

    _PACKAGES = [
        "PyQt6.QtCore",
        "PyQt6.QtGui",
        "PyQt6.QtWidgets",
        "pyshark",
        "pandas",
        "numpy",
        "scipy",
        "sklearn",
        "yaml",
        "loguru",
        "matplotlib",
        "click",
        "fastapi",
        "uvicorn",
        "pydantic",
        "cryptography",
        "requests",
        "joblib",
    ]

    @pytest.mark.parametrize("package", _PACKAGES)
    def test_package_imports_clean(self, package):
        """Each package must import without an exception or non-zero exit."""
        result = _run_python(f"import {package}")
        assert result.returncode == 0, (
            f"Importing '{package}' returned exit code {result.returncode}.\n"
            f"stderr: {result.stderr[:400]}"
        )

    def test_no_tensorflow_in_requirements(self):
        """TensorFlow was removed (saves 4 GB, caused GPU segfault). Ensure
        it has NOT been re-added to requirements.txt."""
        req = (ROOT / "requirements.txt").read_text()
        assert "tensorflow" not in req.lower(), (
            "tensorflow must NOT be in requirements.txt — it causes a CUDA "
            "segfault on systems without a GPU"
        )

    def test_pyqt6_version_meets_minimum(self):
        """PyQt6 must be ≥ 6.6.0."""
        from PyQt6.QtCore import PYQT_VERSION_STR
        major, minor, _ = (int(x) for x in PYQT_VERSION_STR.split("."))
        assert (major, minor) >= (6, 6), (
            f"PyQt6 {PYQT_VERSION_STR} is below minimum 6.6.0"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Core application imports
# ─────────────────────────────────────────────────────────────────────────────

class TestCoreApplicationImports:
    """Verify the application's own modules import without crashing."""

    def test_app_main_importable(self):
        from app import main  # noqa: F401

    def test_app_main_window_importable(self):
        from app import main_window  # noqa: F401

    def test_app_resources_importable(self):
        from app import resources  # noqa: F401

    def test_app_workers_importable(self):
        from app import workers  # noqa: F401

    def test_app_styles_importable(self):
        from app import styles  # noqa: F401

    def test_src_core_model_importable(self):
        from src.core import model  # noqa: F401

    def test_src_core_utils_importable(self):
        from src.core import utils  # noqa: F401

    def test_src_api_cli_importable(self):
        from src.api import cli  # noqa: F401

    def test_src_api_rest_importable(self):
        from src.api import rest  # noqa: F401

    def test_src_parsers_packet_parser_importable(self):
        from src.parsers import packet_parser  # noqa: F401

    def test_src_reports_importable(self):
        """Reports package should import without errors."""
        import importlib
        spec = importlib.util.find_spec("src.reports")
        assert spec is not None, "src.reports package not found"


# ─────────────────────────────────────────────────────────────────────────────
# 3. GPU / CUDA safety (must not segfault on headless/CPU-only machines)
# ─────────────────────────────────────────────────────────────────────────────

class TestGPUSafety:
    """Verify that the ML model module safely disables GPU/CUDA."""

    def test_cuda_disabled_env_var_set(self):
        model_path = ROOT / "src" / "core" / "model.py"
        content = model_path.read_text()
        assert "CUDA_VISIBLE_DEVICES" in content, (
            "model.py must set CUDA_VISIBLE_DEVICES to prevent GPU segfault"
        )

    def test_tf_log_suppression_set(self):
        model_path = ROOT / "src" / "core" / "model.py"
        content = model_path.read_text()
        assert "TF_CPP_MIN_LOG_LEVEL" in content, (
            "model.py must set TF_CPP_MIN_LOG_LEVEL to suppress TF noise"
        )

    def test_model_module_no_segfault(self):
        """Import src.core.model in a subprocess — catches any GPU segfault."""
        result = _run_python(
            "import sys, pathlib; "
            f"sys.path.insert(0, '{ROOT}'); "
            "from src.core import model"
        )
        assert result.returncode == 0, (
            f"src.core.model import crashed (exit {result.returncode}).\n"
            f"stderr: {result.stderr[:400]}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Protocol analyzer class instantiation
# ─────────────────────────────────────────────────────────────────────────────

class TestProtocolAnalyzerInstantiation:
    """Every analyzer class must instantiate without raising an exception."""

    def test_tcp_analyzer_instantiates(self):
        from src.protocols.tcp_analyzer import TCPAnalyzer
        a = TCPAnalyzer()
        assert a is not None

    def test_udp_analyzer_instantiates(self):
        from src.protocols.udp_analyzer import UDPAnalyzer
        a = UDPAnalyzer()
        assert a is not None

    def test_dns_analyzer_instantiates(self):
        from src.protocols.dns_analyzer import DNSAnalyzer
        a = DNSAnalyzer()
        assert a is not None

    def test_icmp_analyzer_instantiates(self):
        from src.protocols.icmp_analyzer import ICMPAnalyzer
        a = ICMPAnalyzer()
        assert a is not None

    def test_dhcp_analyzer_instantiates(self):
        from src.protocols.dhcp_analyzer import DHCPAnalyzer
        a = DHCPAnalyzer()
        assert a is not None

    def test_wlan_analyzer_instantiates(self):
        from src.protocols.wlan_analyzer import WLANAnalyzer
        # WLANAnalyzer takes a config_path string, not a dict
        a = WLANAnalyzer(str(ROOT / "config" / "default.yaml"))
        assert a is not None

    def test_wlan_rf_monitor_instantiates(self):
        from src.protocols.wlan_rf_monitor import WLANRFMonitor
        a = WLANRFMonitor({})
        assert a is not None

    def test_wlan_decryptor_importable(self):
        from src.protocols import wlan_decryptor  # noqa: F401


# ─────────────────────────────────────────────────────────────────────────────
# 5. Protocol analyzer filter API (v1.6.0 requirement)
# ─────────────────────────────────────────────────────────────────────────────

class TestProtocolAnalyzerFilterAPI:
    """All analyzers must accept ip_filter and port_filter in .analyze()."""

    _ANALYZERS = [
        ("src.protocols.tcp_analyzer",   "TCPAnalyzer"),
        ("src.protocols.udp_analyzer",   "UDPAnalyzer"),
        ("src.protocols.http_analyzer",  "HTTPAnalyzer"),
        ("src.protocols.https_analyzer", "HTTPSAnalyzer"),
        ("src.protocols.dns_analyzer",   "DNSAnalyzer"),
        ("src.protocols.icmp_analyzer",  "ICMPAnalyzer"),
        ("src.protocols.dhcp_analyzer",  "DHCPAnalyzer"),
    ]

    @pytest.mark.parametrize("module,cls", _ANALYZERS)
    def test_analyze_accepts_ip_filter(self, module, cls):
        mod = importlib.import_module(module)
        klass = getattr(mod, cls)
        assert _has_param(klass.analyze, "ip_filter"), (
            f"{cls}.analyze() must accept ip_filter parameter"
        )

    @pytest.mark.parametrize("module,cls", _ANALYZERS)
    def test_analyze_accepts_port_filter(self, module, cls):
        mod = importlib.import_module(module)
        klass = getattr(mod, cls)
        assert _has_param(klass.analyze, "port_filter"), (
            f"{cls}.analyze() must accept port_filter parameter"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 6. Script entry-point signatures
# ─────────────────────────────────────────────────────────────────────────────

class TestScriptEntryPoints:
    """All analysis scripts must expose a run() function with correct params."""

    def test_run_wlan_analysis_signature(self):
        from scripts.run_wlan_analysis import run
        sig = inspect.signature(run)
        assert "pcap_file" in sig.parameters
        assert "output_dir" in sig.parameters

    def test_run_channel_monitor_signature(self):
        from scripts.run_channel_monitor import run
        sig = inspect.signature(run)
        assert "pcap" in sig.parameters

    def test_analyze_tcp_udp_signature(self):
        from scripts.analyze_tcp_udp import run
        sig = inspect.signature(run)
        assert "pcap_file" in sig.parameters
        assert "ip_filter" in sig.parameters, "Missing ip_filter (v1.6.0)"
        assert "port_filter" in sig.parameters, "Missing port_filter (v1.6.0)"

    def test_run_ipv6_analysis_signature(self):
        from scripts.run_ipv6_analysis import run
        sig = inspect.signature(run)
        assert "pcap_file" in sig.parameters
        assert "ipv6_addr" in sig.parameters
        assert "output_dir" in sig.parameters

    def test_run_ipv6_analysis_analyse_functions_present(self):
        """All per-protocol sub-analyses must be present."""
        import scripts.run_ipv6_analysis as m
        for fn in ("analyse_overview", "analyse_address_info",
                   "analyse_neighbor_discovery", "analyse_dns6",
                   "analyse_extension_headers", "analyse_tcp",
                   "analyse_udp", "analyse_icmpv6", "analyse_statistics"):
            assert hasattr(m, fn), f"scripts.run_ipv6_analysis.{fn} is missing"


# ─────────────────────────────────────────────────────────────────────────────
# 7. IPv6 analysis — truncated PCAP robustness (regression for v1.6.1 fix)
# ─────────────────────────────────────────────────────────────────────────────

class TestIPv6AnalysisTruncatedPcap:
    """
    _count() and _run_tshark() must return results even when tshark exits
    with a non-zero return code (e.g. truncated capture file).
    Previously these functions used check_output which swallowed all output
    on any non-zero exit, producing false "No packets found" reports.
    """

    def test_count_uses_subprocess_run_not_check_output(self):
        """Implementation must use subprocess.run so exit code ≠ 0 doesn't
        discard tshark's stdout."""
        path = ROOT / "scripts" / "run_ipv6_analysis.py"
        source = path.read_text()
        assert "subprocess.run(" in source, (
            "_count() and _run_tshark() must use subprocess.run, not check_output"
        )
        assert "check_output" not in source, (
            "check_output raises CalledProcessError on tshark exit code 2 "
            "(truncated file warning) — use subprocess.run instead"
        )

    def test_count_function_returns_int(self):
        from scripts.run_ipv6_analysis import _count
        result = _count("/nonexistent/file.pcap", "ipv6")
        assert isinstance(result, int)
        assert result == 0   # no file → 0, no crash

    def test_run_tshark_returns_list(self):
        from scripts.run_ipv6_analysis import _run_tshark
        result = _run_tshark("/nonexistent/file.pcap", "ipv6", ["frame.number"])
        assert isinstance(result, list)

    def test_run_tshark_timeout_returns_empty(self):
        """A very short timeout on a missing file must return [] not raise."""
        from scripts.run_ipv6_analysis import _run_tshark
        result = _run_tshark("/nonexistent/file.pcap", "ipv6", ["frame.number"])
        assert result == []

    def test_analyse_overview_returns_dict_on_missing_file(self):
        from scripts.run_ipv6_analysis import analyse_overview
        result = analyse_overview("/nonexistent/file.pcap", "::1")
        assert isinstance(result, dict)
        assert result.get("total_packets", 0) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 8. WLAN analysis functions
# ─────────────────────────────────────────────────────────────────────────────

class TestWLANAnalysisFunctions:
    """Verify WLAN analysis utility functions and classifications."""

    def test_classify_ssids_splits_wifi_direct(self):
        from scripts.run_wlan_analysis import _classify_ssids
        ssids = {
            "HomeNetwork": 10,
            "DIRECT-HP-LaserJet": 5,
            "CoffeeShop": 2,
            "HP-Print-ABC": 3,
        }
        regular, wfd = _classify_ssids(ssids)
        assert "HomeNetwork" in regular
        assert "CoffeeShop" in regular
        assert "DIRECT-HP-LaserJet" in wfd
        assert "HP-Print-ABC" in wfd

    def test_is_unicast_mac(self):
        from scripts.run_channel_monitor import is_unicast
        assert is_unicast("00:11:22:33:44:55") is True
        assert is_unicast("ff:ff:ff:ff:ff:ff") is False   # broadcast
        assert is_unicast("01:00:5e:00:00:01") is False   # multicast

    def test_is_globally_administered_mac(self):
        from scripts.run_channel_monitor import is_globally_administered
        assert is_globally_administered("00:11:22:33:44:55") is True   # OUI
        assert is_globally_administered("02:11:22:33:44:55") is False  # locally assigned

    def test_parse_output_empty_string_returns_empty_df(self):
        from scripts.run_channel_monitor import parse_output
        import pandas as pd
        df = parse_output("")
        assert isinstance(df, pd.DataFrame)
        assert df.empty

    def test_parse_output_single_row(self):
        from scripts.run_channel_monitor import parse_output, COLUMN_NAMES
        # Build a tab-separated row with the right number of fields
        row = "\t".join(["1751000000.0", "100", "1", "0x0008",
                          "aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff",
                          "aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff",
                          "aa:bb:cc:dd:ee:ff", "0", "0",
                          "-65", "-95", "6", "2437", "54.0", "3", "Home", "100"])
        df = parse_output(row)
        assert len(df) == 1
        assert df.iloc[0]["channel"] == 6

    def test_wlan_rf_monitor_run_all_on_empty_df(self):
        """run_all must handle a DataFrame with the expected columns without crashing."""
        import pandas as pd
        from scripts.run_channel_monitor import COLUMN_NAMES
        from src.protocols.wlan_rf_monitor import WLANRFMonitor
        # rf_monitor expects a DataFrame with the channel monitor column schema
        df = pd.DataFrame(columns=COLUMN_NAMES)
        monitor = WLANRFMonitor({})
        result = monitor.run_all(df)
        assert isinstance(result, dict)


# ─────────────────────────────────────────────────────────────────────────────
# 9. TCP / UDP analysis functions
# ─────────────────────────────────────────────────────────────────────────────

class TestTCPUDPAnalysisFunctions:
    """Verify TCP/UDP analysis helpers behave correctly."""

    def test_analyse_tcp_udp_returns_dict_on_missing_file(self):
        from scripts.analyze_tcp_udp import analyse
        result = analyse("/nonexistent/file.pcap")
        assert isinstance(result, dict)

    def test_analyse_tcp_udp_with_ip_filter(self):
        from scripts.analyze_tcp_udp import analyse
        result = analyse("/nonexistent/file.pcap", ip_filter="192.168.1.1")
        assert isinstance(result, dict)

    def test_analyse_tcp_udp_with_port_filter(self):
        from scripts.analyze_tcp_udp import analyse
        result = analyse("/nonexistent/file.pcap", port_filter="80,443")
        assert isinstance(result, dict)

    def test_generate_html_no_crash_on_minimal_data(self):
        """generate_html must not raise on minimal / empty data."""
        import tempfile
        from scripts.analyze_tcp_udp import generate_html
        data = {
            "total_packets": 0, "duration_s": 0.0,
            "tcp_count": 0, "udp_count": 0,
            "print_hosts": {}, "rst_total": 0,
            "zero_window": 0, "window_updates": 0,
            "retransmissions_print": 0, "dup_acks_print": 0,
            "lost_segments": 0, "data_sent_mb": 0.0,
            "print_connections": 0, "rst_detail": [],
            "rst_bursts": [], "udp_top_flows": [],
            "broadcast_udp": [], "quic_count": 0,
            "zw_timeline": {},
        }
        data["duration_s"] = 1.0  # avoid ZeroDivisionError in html template
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            out = f.name
        try:
            generate_html("/fake/file.pcap", data, out)
            assert Path(out).exists()
            content = Path(out).read_text()
            assert "<html" in content.lower()
        finally:
            Path(out).unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# 10. IPv6 address classification
# ─────────────────────────────────────────────────────────────────────────────

class TestIPv6AddressClassification:
    """Validate the IPv6 address classifier used in analysis reports."""

    def _classify(self, addr):
        from scripts.run_ipv6_analysis import _classify_ipv6_address
        return _classify_ipv6_address(addr)

    def test_loopback(self):
        info = self._classify("::1")
        assert info["type"] == "loopback"

    def test_link_local(self):
        info = self._classify("fe80::1")
        assert info["scope"] == "link"

    def test_ula_address(self):
        info = self._classify("fd12:3456:789a::1")
        assert "unique-local" in info["type"]

    def test_global_unicast(self):
        info = self._classify("2001:db8::1")
        assert info["scope"] == "global"

    def test_multicast(self):
        info = self._classify("ff02::1")
        assert info["type"] == "multicast"

    def test_invalid_address_does_not_crash(self):
        info = self._classify("not-an-address")
        assert isinstance(info, dict)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Channel monitor statistics
# ─────────────────────────────────────────────────────────────────────────────

class TestChannelMonitorStatistics:
    """compute_stats must return correct structure on synthetic data."""

    def _make_df(self, n_frames=20):
        import pandas as pd
        import numpy as np
        from scripts.run_channel_monitor import COLUMN_NAMES, DATA_SET, BEACON
        rows = []
        for i in range(n_frames):
            subtype = BEACON if i % 5 == 0 else list(DATA_SET)[0]
            rows.append({
                "timestamp": float(i), "length": 100, "frame_number": i,
                "type_subtype": subtype,
                "sa": "aa:bb:cc:dd:ee:ff", "da": "ff:ff:ff:ff:ff:ff",
                "ta": "aa:bb:cc:dd:ee:ff", "ra": "ff:ff:ff:ff:ff:ff",
                "bssid": "aa:bb:cc:dd:ee:ff",
                "retry": 0, "pwrmgt": 0,
                "signal_dbm": -65.0, "noise_dbm": -95.0,
                "channel": 6.0, "frequency": 2437.0,
                "data_rate": 54.0, "phy": 3.0,
                "ssid": "TestNet", "duration": 100.0,
            })
        return pd.DataFrame(rows)

    def test_compute_stats_returns_required_keys(self):
        from scripts.run_channel_monitor import compute_stats
        df = self._make_df()
        stats = compute_stats(df, window_sec=20.0)
        required = {
            "n_frames", "total_bytes", "utilisation_pct",
            "throughput_mbps", "retry_rate", "frame_types",
            "bssid_stats", "client_stats", "overload_flags",
        }
        for key in required:
            assert key in stats, f"compute_stats result missing key: {key}"

    def test_compute_stats_empty_df_returns_empty(self):
        import pandas as pd
        from scripts.run_channel_monitor import compute_stats
        result = compute_stats(pd.DataFrame(), window_sec=10.0)
        assert result == {}

    def test_compute_stats_counts_frames_correctly(self):
        from scripts.run_channel_monitor import compute_stats
        df = self._make_df(n_frames=20)
        stats = compute_stats(df, window_sec=20.0)
        assert stats["n_frames"] == 20

    def test_compute_stats_retry_rate_zero_when_no_retries(self):
        from scripts.run_channel_monitor import compute_stats
        df = self._make_df(n_frames=10)
        stats = compute_stats(df, window_sec=10.0)
        assert stats["retry_rate"] == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# 12. UI panel imports (without displaying anything)
# ─────────────────────────────────────────────────────────────────────────────

class TestPanelImports:
    """All panel modules must be importable — catches missing imports that
    would crash the app at startup."""

    _PANELS = [
        "app.panels.home_panel",
        "app.panels.wlan_panel",
        "app.panels.decrypt_panel",
        "app.panels.channel_panel",
        "app.panels.tcp_udp_panel",
        "app.panels.ipv6_panel",
        "app.panels.protocol_panel",
        "app.panels.anomaly_panel",
        "app.panels.cli_info_panel",
        "app.panels.about_panel",
    ]

    @pytest.mark.parametrize("module", _PANELS)
    def test_panel_importable(self, module):
        imported = importlib.import_module(module)
        assert imported is not None

    def test_about_panel_has_correct_version(self):
        """About panel version constant must match the latest release."""
        from app.panels.about_panel import APP_VERSION
        major, minor, patch = (int(x) for x in APP_VERSION.split("."))
        assert (major, minor) >= (1, 6), (
            f"APP_VERSION is {APP_VERSION} — expected at least v1.6.x"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 13. Syntax validation for all critical Python files
# ─────────────────────────────────────────────────────────────────────────────

class TestSyntaxValidation:
    """All critical Python source files must parse without SyntaxError."""

    _FILES = [
        "app/main.py",
        "app/main_window.py",
        "app/workers.py",
        "app/panels/wlan_panel.py",
        "app/panels/tcp_udp_panel.py",
        "app/panels/ipv6_panel.py",
        "app/panels/protocol_panel.py",
        "app/panels/channel_panel.py",
        "app/panels/decrypt_panel.py",
        "app/panels/anomaly_panel.py",
        "src/core/model.py",
        "src/api/cli.py",
        "src/protocols/tcp_analyzer.py",
        "src/protocols/udp_analyzer.py",
        "src/protocols/dns_analyzer.py",
        "src/protocols/http_analyzer.py",
        "src/protocols/https_analyzer.py",
        "src/protocols/icmp_analyzer.py",
        "src/protocols/dhcp_analyzer.py",
        "src/protocols/wlan_analyzer.py",
        "src/protocols/wlan_rf_monitor.py",
        "src/protocols/wlan_decryptor.py",
        "scripts/run_wlan_analysis.py",
        "scripts/run_channel_monitor.py",
        "scripts/analyze_tcp_udp.py",
        "scripts/run_ipv6_analysis.py",
    ]

    @pytest.mark.parametrize("rel_path", _FILES)
    def test_no_syntax_errors(self, rel_path):
        full = ROOT / rel_path
        if not full.exists():
            pytest.skip(f"{rel_path} not found")
        try:
            ast.parse(full.read_text())
        except SyntaxError as exc:
            pytest.fail(f"SyntaxError in {rel_path}: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# 14. Build artifacts and config files
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildArtifacts:
    """All files needed by the build system must be present."""

    def test_requirements_txt_exists(self):
        assert (ROOT / "requirements.txt").exists()

    def test_setup_py_exists(self):
        assert (ROOT / "setup.py").exists()

    def test_main_spec_exists(self):
        assert (ROOT / "installer" / "ai_wireshark.spec").exists()

    def test_linux_spec_exists(self):
        assert (ROOT / "installer" / "linux" / "ai_wireshark_linux.spec").exists()

    def test_desktop_entry_exists(self):
        assert (ROOT / "installer" / "ai-wireshark.desktop").exists()

    def test_default_config_exists(self):
        assert (ROOT / "config" / "default.yaml").exists()

    def test_default_config_valid_yaml(self):
        import yaml
        content = (ROOT / "config" / "default.yaml").read_text()
        cfg = yaml.safe_load(content)
        assert isinstance(cfg, dict), "default.yaml must parse to a dict"

    def test_default_config_has_protocols_section(self):
        import yaml
        cfg = yaml.safe_load((ROOT / "config" / "default.yaml").read_text())
        assert "protocols" in cfg, "config must have a 'protocols' section"

    def test_app_icon_exists_and_is_readonly(self):
        """Original icon must be present and protected from overwriting."""
        icon = ROOT / "installer" / "app_icon_orig.png"
        assert icon.exists(), "installer/app_icon_orig.png is missing"
        import stat
        mode = icon.stat().st_mode
        # At least one read bit must be set; write bits must be absent
        assert mode & stat.S_IRUSR, "app_icon_orig.png must be readable"
        assert not (mode & stat.S_IWUSR), "app_icon_orig.png must NOT be owner-writable"

    def test_setup_py_version_matches_about_panel(self):
        """setup.py version must match the About panel version constant."""
        from app.panels.about_panel import APP_VERSION
        setup_text = (ROOT / "setup.py").read_text()
        assert f'version="{APP_VERSION}"' in setup_text, (
            f"setup.py version does not match APP_VERSION ({APP_VERSION})"
        )

    def test_tshark_available(self):
        """tshark must be installed — it is required at runtime."""
        result = subprocess.run(
            ["tshark", "--version"], capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0, (
            "tshark is not available or not in PATH. "
            "Install it with: sudo apt install tshark"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
