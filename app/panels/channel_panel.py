"""Channel Monitor & Network Map panel."""

from PyQt6.QtWidgets import (
    QVBoxLayout, QGroupBox, QHBoxLayout, QLabel,
    QDoubleSpinBox, QLineEdit, QPushButton, QFileDialog, QFrame, QComboBox
)

from app.panels.base_panel import BaseAnalysisPanel
from app.widgets.inputs import FileSelector, MacAddressInput
from app.workers import AnalysisWorker


class ChannelPanel(BaseAnalysisPanel):
    TITLE = "Channel Monitor & Network Map"
    SUBTITLE = "Channel utilisation, retry pressure, per-BSSID/client stats, station spotlight, client/network map reports"
    TASK_NAME = "channel_monitor"
    INPUT_GUIDE = "Use the top section for live channel diagnostics from a capture. Use the report-builder section when you already have per-channel JSON survey outputs and want a client map or combined dashboard without rerunning the monitor."

    def _build_option_card(self, title: str, description: str):
        card = QFrame()
        card.setObjectName("optionCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 14, 14, 14)
        card_layout.setSpacing(4)

        title_label = QLabel(title)
        title_label.setObjectName("optionTitle")
        card_layout.addWidget(title_label)

        desc_label = QLabel(description)
        desc_label.setObjectName("fieldHelp")
        desc_label.setWordWrap(True)
        card_layout.addWidget(desc_label)
        return card

    def _build_inputs(self, layout: QVBoxLayout):
        group = QGroupBox("1. Channel Monitor Inputs")
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(12)

        group_note = QLabel(
            "Run the channel monitor on a capture when you need RF utilization, retry pressure, client density, BSSID visibility, and optional station spotlight analysis."
        )
        group_note.setObjectName("fieldHelp")
        group_note.setWordWrap(True)
        group_layout.addWidget(group_note)

        self._file_selector = FileSelector(label="PCAP File:")
        group_layout.addWidget(self._file_selector)

        options_group = QGroupBox("Capture Analysis Options")
        options_layout = QVBoxLayout(options_group)
        options_layout.setSpacing(12)

        ch_label = QLabel("Channel")
        ch_label.setObjectName("fieldLabel")
        options_layout.addWidget(ch_label)

        self._channel_combo = QComboBox()
        self._channel_combo.addItem("All Channels (2.4/5/6 GHz)", None)

        self._channel_combo.addItem("-- 2.4 GHz --", None)
        for ch in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]:
            self._channel_combo.addItem(f"Channel {ch} (2.4 GHz)", ch)

        self._channel_combo.addItem("-- 5 GHz --", None)
        for ch in [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]:
            self._channel_combo.addItem(f"Channel {ch} (5 GHz)", ch)

        self._channel_combo.setCurrentIndex(0)
        self._channel_combo.setToolTip("Select All Channels or a specific channel from 2.4 GHz, 5 GHz, or 6 GHz bands.")
        options_layout.addWidget(self._channel_combo)

        int_help = QLabel(
            "All Channels scans every detected channel in the capture. "
            "Selectable channels: 2.4 GHz (1-14) and 5 GHz (36-165). "
            "Reference list for all bands: 2.4 GHz (1-14), 5 GHz (36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165), "
            "6 GHz (1,5,9,...,233)."
        )
        int_help.setObjectName("fieldHelp")
        int_help.setWordWrap(True)
        options_layout.addWidget(int_help)

        int_label = QLabel("Interval (seconds)")
        int_label.setObjectName("fieldLabel")
        options_layout.addWidget(int_label)

        self._interval_spin = QDoubleSpinBox()
        self._interval_spin.setRange(1.0, 300.0)
        self._interval_spin.setValue(10.0)
        self._interval_spin.setSingleStep(5.0)
        options_layout.addWidget(self._interval_spin)

        interval_help = QLabel("Controls the time window used for utilization, throughput, and retry trend calculations.")
        interval_help.setObjectName("fieldHelp")
        interval_help.setWordWrap(True)
        options_layout.addWidget(interval_help)

        group_layout.addWidget(options_group)

        filters_group = QGroupBox("Scope Filters")
        filters_layout = QVBoxLayout(filters_group)
        filters_layout.setSpacing(12)

        bssid_label = QLabel("BSSID")
        bssid_label.setObjectName("fieldLabel")
        filters_layout.addWidget(bssid_label)

        bssid_help = QLabel("Optional. Restrict the analysis to a single access point when multiple BSSIDs are present.")
        bssid_help.setObjectName("fieldHelp")
        bssid_help.setWordWrap(True)
        filters_layout.addWidget(bssid_help)

        self._bssid_edit = QLineEdit()
        self._bssid_edit.setPlaceholderText("Filter to AP BSSID (optional), e.g. 00:04:EA:38:70:E0")
        self._bssid_edit.setMaxLength(17)
        filters_layout.addWidget(self._bssid_edit)

        self._mac_input = MacAddressInput(
            label="Client MAC:",
            placeholder="Filter to client MAC (optional)",
            description="Optional. Focus the report on one station while keeping the rest of the capture available for background context."
        )
        filters_layout.addWidget(self._mac_input)

        station_label = QLabel("Station Spotlight")
        station_label.setObjectName("fieldLabel")
        filters_layout.addWidget(station_label)

        station_help = QLabel("Optional. Enter a station MAC to generate a deeper per-device roaming, throughput, and retry profile.")
        station_help.setObjectName("fieldHelp")
        station_help.setWordWrap(True)
        filters_layout.addWidget(station_help)

        self._station_edit = QLineEdit()
        self._station_edit.setPlaceholderText("Station MAC for spotlight profile (optional), e.g. F8:ED:FC:FE:F0:06")
        self._station_edit.setMaxLength(17)
        filters_layout.addWidget(self._station_edit)

        out_label = QLabel("Output Prefix")
        out_label.setObjectName("fieldLabel")
        filters_layout.addWidget(out_label)

        out_help = QLabel("Optional. Leave blank to auto-name the JSON and HTML outputs under the results directory.")
        out_help.setObjectName("fieldHelp")
        out_help.setWordWrap(True)
        filters_layout.addWidget(out_help)

        self._output_edit = QLineEdit()
        self._output_edit.setPlaceholderText("Output path prefix (optional), e.g. results/ch6_monitor")
        filters_layout.addWidget(self._output_edit)

        group_layout.addWidget(filters_group)

        layout.addWidget(group)

        map_group = QGroupBox("2. Network Map / Combined Report Builder")
        map_layout = QVBoxLayout(map_group)
        map_layout.setSpacing(10)

        map_desc = QLabel(
            "Build client/network map or combined report from per-channel JSON data. "
            "Select a directory containing channel survey JSON files."
        )
        map_desc.setWordWrap(True)
        map_desc.setObjectName("fieldHelp")
        map_layout.addWidget(map_desc)

        map_layout.addWidget(
            self._build_option_card(
                "Build Client Map",
                "Use this when you want device clustering, SSID-to-client visibility, and cross-channel station relationships from survey JSON files."
            )
        )
        map_layout.addWidget(
            self._build_option_card(
                "Build Combined Report",
                "Use this when you need both RF health metrics and the client map fused into one executive dashboard."
            )
        )

        dir_label = QLabel("Survey Data Directory")
        dir_label.setObjectName("fieldLabel")
        map_layout.addWidget(dir_label)

        dir_help = QLabel("Select the folder that contains client_network_map.json and channel monitor JSON output files.")
        dir_help.setObjectName("fieldHelp")
        dir_help.setWordWrap(True)
        map_layout.addWidget(dir_help)

        dir_row = QHBoxLayout()
        dir_row.setSpacing(8)

        self._map_dir_edit = QLineEdit()
        self._map_dir_edit.setPlaceholderText("Directory with client_network_map.json and/or channel monitor JSONs")
        dir_row.addWidget(self._map_dir_edit, 1)

        self._btn_browse_dir = QPushButton("Browse...")
        self._btn_browse_dir.clicked.connect(self._browse_map_dir)
        dir_row.addWidget(self._btn_browse_dir)
        map_layout.addLayout(dir_row)

        action_note = QLabel(
            "Use Client Map for topology and device relationships. Use Combined Report for a management-friendly dashboard that merges RF health and client-map findings."
        )
        action_note.setObjectName("fieldHelp")
        action_note.setWordWrap(True)
        map_layout.addWidget(action_note)

        btn_row = QVBoxLayout()
        btn_row.setSpacing(10)

        self._btn_client_map = QPushButton("Build Client Map")
        self._btn_client_map.setObjectName("btnSuccess")
        self._btn_client_map.setFixedHeight(36)
        self._btn_client_map.clicked.connect(self._on_build_client_map)
        btn_row.addWidget(self._btn_client_map)

        self._btn_combined = QPushButton("Build Combined Report")
        self._btn_combined.setObjectName("btnSuccess")
        self._btn_combined.setFixedHeight(36)
        self._btn_combined.clicked.connect(self._on_build_combined_report)
        btn_row.addWidget(self._btn_combined)
        map_layout.addLayout(btn_row)

        layout.addWidget(map_group)

    def _validate(self) -> str:
        if not self._file_selector.get_path():
            return "Please select a PCAP file"
        return ""

    def _get_params(self) -> dict:
        channel = self._channel_combo.currentData()
        return {
            "pcap": self._file_selector.get_path(),
            "channel": channel,
            "bssid": self._bssid_edit.text().strip(),
            "mac": self._mac_input.get_mac(),
            "station": self._station_edit.text().strip(),
            "interval": self._interval_spin.value(),
            "output": self._output_edit.text().strip(),
        }

    # ── Network Map helpers ────────────────────────────────────────────────

    def _browse_map_dir(self):
        """Open directory picker for network map data."""
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Channel Data Directory", ""
        )
        if dir_path:
            self._map_dir_edit.setText(dir_path)

    def _get_map_json_path(self) -> str:
        """Find client_network_map.json in the selected directory."""
        import os
        dir_path = self._map_dir_edit.text().strip()
        if not dir_path:
            return ""
        json_path = os.path.join(dir_path, "client_network_map.json")
        if os.path.isfile(json_path):
            return json_path
        # Also check if user selected a JSON file directly
        if dir_path.endswith(".json") and os.path.isfile(dir_path):
            return dir_path
        return ""

    def _on_build_client_map(self):
        """Run client map report builder."""
        json_path = self._get_map_json_path()
        if not json_path:
            self._status_label.setText("⚠ No client_network_map.json found in selected directory")
            self._status_label.setStyleSheet("color: #ec6a7a;")
            return

        self._btn_client_map.setEnabled(False)
        self._btn_combined.setEnabled(False)
        self._progress.setVisible(True)
        self._status_label.setText("Building client map...")
        self._status_label.setStyleSheet("color: #78d1d2;")
        self._log.clear()
        self._log.setVisible(True)
        self._results.clear()

        params = {"input_json": json_path}
        self._worker = AnalysisWorker("client_map", params)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_map_finished)
        self._worker.error.connect(self._on_map_error)
        self._worker.start()

    def _on_build_combined_report(self):
        """Run combined report builder."""
        json_path = self._get_map_json_path()
        dir_path = self._map_dir_edit.text().strip()
        if not json_path:
            self._status_label.setText("⚠ No client_network_map.json found in selected directory")
            self._status_label.setStyleSheet("color: #ec6a7a;")
            return

        self._btn_client_map.setEnabled(False)
        self._btn_combined.setEnabled(False)
        self._progress.setVisible(True)
        self._status_label.setText("Building combined report...")
        self._status_label.setStyleSheet("color: #78d1d2;")
        self._log.clear()
        self._log.setVisible(True)
        self._results.clear()

        params = {
            "client_map_json": json_path,
            "channel_jsons_dir": dir_path if dir_path != json_path else None,
        }
        self._worker = AnalysisWorker("combined_report", params)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_map_finished)
        self._worker.error.connect(self._on_map_error)
        self._worker.start()

    def _on_map_finished(self, result: dict):
        """Handle completion of map/combined report."""
        self._btn_client_map.setEnabled(True)
        self._btn_combined.setEnabled(True)
        self._progress.setVisible(False)
        self._status_label.setText("✓ Report generated")
        self._status_label.setStyleSheet("color: #7fd5a0;")

        html_path = result.get("html_path")
        self._results.show_results(
            json_data=result.get("json_data"),
            html_path=html_path,
            title="Network Map Report"
        )

    def _on_map_error(self, msg: str):
        """Handle error from map/combined report."""
        self._btn_client_map.setEnabled(True)
        self._btn_combined.setEnabled(True)
        self._progress.setVisible(False)
        self._status_label.setText("✗ Report generation failed")
        self._status_label.setStyleSheet("color: #ec6a7a;")
        self._log.append(f"ERROR: {msg}")
        self._log.setVisible(True)
