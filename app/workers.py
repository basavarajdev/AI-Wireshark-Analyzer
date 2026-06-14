"""Background workers for running analysis tasks without blocking the UI."""

import json
import traceback
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = str(PROJECT_ROOT / "results")


class AnalysisWorker(QThread):
    """Generic worker that runs analysis tasks in background via direct imports."""

    progress = pyqtSignal(str)       # Status message
    finished = pyqtSignal(dict)      # Results dict
    error = pyqtSignal(str)          # Error message

    def __init__(self, task: str, params: dict, parent=None):
        super().__init__(parent)
        self.task = task
        self.params = params

    def run(self):
        try:
            if self.task == "wlan":
                self._run_wlan()
            elif self.task == "tcp_udp":
                self._run_tcp_udp()
            elif self.task == "ipv6":
                self._run_ipv6()
            elif self.task == "channel_monitor":
                self._run_channel_monitor()
            elif self.task == "protocol":
                self._run_protocol()
            elif self.task == "anomaly":
                self._run_anomaly()
            elif self.task == "decrypt":
                self._run_decrypt()
            elif self.task == "client_map":
                self._run_client_map()
            elif self.task == "combined_report":
                self._run_combined_report()
            else:
                self.error.emit(f"Unknown task: {self.task}")
        except Exception as e:
            self.error.emit(f"{type(e).__name__}: {e}\n{traceback.format_exc()}")

    def _run_wlan(self):
        """Run WLAN analysis via direct import."""
        pcap = self.params["pcap"]
        mac = self.params.get("mac", "") or None

        self.progress.emit("Starting WLAN analysis...")
        from scripts.run_wlan_analysis import run as wlan_run
        out = wlan_run(pcap, mac_filter=mac, output_dir=RESULTS_DIR)

        if out.get('error'):
            self.error.emit(out['error'])
            return

        self.progress.emit("Analysis complete. Loading results...")
        output = {"stdout": "", "stderr": ""}
        if out.get('json_path') and Path(out['json_path']).exists():
            output["json_data"] = json.loads(Path(out['json_path']).read_text())
        if out.get('html_path'):
            output["html_path"] = out['html_path']
        self.finished.emit(output)

    def _run_tcp_udp(self):
        """Run TCP/UDP analysis via direct import."""
        pcap = self.params["pcap"]
        out_html = self.params.get("output", "") or None

        self.progress.emit("Starting TCP/UDP analysis...")
        from scripts.analyze_tcp_udp import run as tcp_run
        out = tcp_run(pcap, output_html=out_html, output_dir=RESULTS_DIR)

        self.progress.emit("Analysis complete.")
        output = {"stdout": "", "stderr": ""}
        if out.get('html_path') and Path(out['html_path']).exists():
            output["html_path"] = out['html_path']
        output["json_data"] = out.get('results', {})
        self.finished.emit(output)

    def _run_ipv6(self):
        """Run IPv6 analysis via direct import."""
        pcap = self.params["pcap"]
        ipv6_addr = self.params["ipv6_address"]

        self.progress.emit(f"Starting IPv6 analysis for {ipv6_addr}...")
        from scripts.run_ipv6_analysis import run as ipv6_run
        out = ipv6_run(pcap, ipv6_addr, output_dir=RESULTS_DIR)

        if out.get('error'):
            self.error.emit(out['error'])
            return

        self.progress.emit("Analysis complete.")
        output = {"stdout": "", "stderr": ""}
        if out.get('json_path') and Path(out['json_path']).exists():
            output["json_data"] = json.loads(Path(out['json_path']).read_text())
        if out.get('html_path'):
            output["html_path"] = out['html_path']
        self.finished.emit(output)

    def _run_channel_monitor(self):
        """Run channel monitor via direct import."""
        pcap = self.params["pcap"]
        channel = self.params.get("channel")
        bssid = self.params.get("bssid", "") or None
        mac = self.params.get("mac", "") or None
        station = self.params.get("station", "") or None
        interval = self.params.get("interval", 10)
        out_prefix = self.params.get("output", "") or None

        self.progress.emit(f"Running channel monitor (interval={interval}s)...")
        from scripts.run_channel_monitor import run as ch_run
        out = ch_run(
            pcap=pcap, channel=channel, bssid=bssid, mac=mac,
            station=station, interval=float(interval),
            out_prefix=out_prefix, output_dir=RESULTS_DIR,
        )

        if out.get('error'):
            self.error.emit(out['error'])
            return

        self.progress.emit("Analysis complete.")
        output = {"stdout": "", "stderr": ""}
        if out.get('json_path') and Path(out['json_path']).exists():
            output["json_data"] = json.loads(Path(out['json_path']).read_text())
        if out.get('html_path'):
            output["html_path"] = out['html_path']
        self.finished.emit(output)

    def _run_protocol(self):
        """Run protocol-specific analysis via direct import."""
        pcap = self.params["pcap"]
        protocol = self.params.get("protocol", "tcp")
        display_filter = self.params.get("filter", "")
        html_output = self.params.get("html_output", "") or None

        self.progress.emit(f"Starting {protocol.upper()} protocol analysis...")

        from src.api.cli import _run_protocol_analysis
        results = _run_protocol_analysis(pcap, protocol, display_filter or None)

        self.progress.emit("Analysis complete.")
        output = {"stdout": "", "stderr": "", "json_data": results}

        if html_output:
            try:
                from src.reports.html_generator import HTMLReportGenerator
                generator = HTMLReportGenerator()
                generator.generate_report(
                    results={'total_packets': results.get('total_packets', 0),
                             'protocol_analysis': {protocol: results}},
                    pcap_file=pcap,
                    output_file=html_output,
                    protocol=protocol.upper(),
                )
                output["html_path"] = html_output
            except Exception as e:
                pass

        self.finished.emit(output)

    def _run_anomaly(self):
        """Run anomaly detection via direct import."""
        pcap = self.params["pcap"]
        model_type = self.params.get("model_type", "isolation_forest")

        self.progress.emit(f"Running anomaly detection ({model_type})...")

        from src.parsers.packet_parser import PacketParser
        from src.preprocessing.cleaning import DataCleaner
        from src.preprocessing.feature_engineering import FeatureEngineer
        from src.core.model import IsolationForestModel, AutoencoderModel

        parser = PacketParser()
        df = parser.parse_pcap(pcap)
        cleaner = DataCleaner()
        df = cleaner.clean(df)
        engineer = FeatureEngineer()
        df_features = engineer.engineer_features(df)
        X = engineer.get_ml_features(df_features)

        if model_type == 'isolation_forest':
            detector = IsolationForestModel()
            model_path = PROJECT_ROOT / "models" / "isolation_forest.pkl"
            if model_path.exists():
                detector.load(str(model_path))
            else:
                detector.train(X)
        else:
            detector = AutoencoderModel()
            model_path = PROJECT_ROOT / "models" / "autoencoder.h5"
            if model_path.exists():
                detector.load(str(model_path))
            else:
                detector.train(X)

        predictions = detector.predict(X)
        scores = detector.score_samples(X)
        anomaly_count = int((predictions == -1).sum())

        results = {
            "file": pcap,
            "model": model_type,
            "total_packets": len(predictions),
            "anomalies_detected": anomaly_count,
            "anomaly_rate": anomaly_count / max(len(predictions), 1),
            "score_statistics": {
                "min": float(scores.min()),
                "max": float(scores.max()),
                "mean": float(scores.mean()),
                "std": float(scores.std()),
            },
        }
        output = {"stdout": "", "stderr": "", "json_data": results}
        self.finished.emit(output)

    def _run_decrypt(self):
        """Run WPA/WPA2/WPA3 decryption via direct import."""
        pcap = self.params["pcap"]
        key_type = self.params.get("key_type", "wpa-pwd")
        password = self.params.get("password", "")
        ssid = self.params.get("ssid", "") or ""
        mac = self.params.get("mac", "") or None
        save_pcap = self.params.get("save_decrypted_pcap", False)

        self.progress.emit("Starting WPA decryption...")

        from src.protocols.wlan_decryptor import run as decrypt_run
        out = decrypt_run(
            pcap_file=pcap,
            key_type=key_type,
            password=password,
            ssid=ssid,
            mac_filter=mac,
            output_dir=RESULTS_DIR,
            save_decrypted_pcap=save_pcap,
        )

        if out.get("error"):
            self.error.emit(out["error"])
            return

        self.progress.emit("Decryption complete. Loading results...")
        output = {"stdout": "", "stderr": ""}
        if out.get("json_path") and Path(out["json_path"]).exists():
            output["json_data"] = json.loads(Path(out["json_path"]).read_text())
        if out.get("html_path"):
            output["html_path"] = out["html_path"]
        self.finished.emit(output)

    def _run_client_map(self):
        """Build client/network map report from per-channel JSON data."""
        input_json = self.params["input_json"]

        self.progress.emit("Building client/network map report...")
        from scripts.build_client_map_report import run as map_run
        out = map_run(input_json, output_dir=RESULTS_DIR)

        if out.get('error'):
            self.error.emit(out['error'])
            return

        self.progress.emit("Client map report complete.")
        output = {"stdout": "", "stderr": ""}
        if out.get('html_path'):
            output["html_path"] = out['html_path']
        self.finished.emit(output)

    def _run_combined_report(self):
        """Build combined comprehensive network report."""
        client_map_json = self.params["client_map_json"]
        channel_jsons_dir = self.params.get("channel_jsons_dir") or None

        self.progress.emit("Building combined network report...")
        from scripts.build_combined_report import run as combined_run
        out = combined_run(
            client_map_json, channel_jsons_dir=channel_jsons_dir,
            output_dir=RESULTS_DIR,
        )

        if out.get('error'):
            self.error.emit(out['error'])
            return

        self.progress.emit("Combined report complete.")
        output = {"stdout": "", "stderr": ""}
        if out.get('html_path'):
            output["html_path"] = out['html_path']
        self.finished.emit(output)
