"""Channel Monitor & Network Map panel — two tabs: Single Channel Monitor and Multi-Channel Survey."""

from PyQt6.QtWidgets import (
    QVBoxLayout, QGroupBox, QHBoxLayout, QLabel,
    QSpinBox, QLineEdit, QPushButton, QFileDialog, QFrame, QComboBox,
    QTabWidget, QWidget, QListWidget, QListWidgetItem, QAbstractItemView,
)

from app.panels.base_panel import BaseAnalysisPanel
from app.widgets.inputs import FileSelector, MacAddressInput
from app.workers import AnalysisWorker



class ChannelPanel(BaseAnalysisPanel):
    TITLE = "Channel Monitor & Network Map"
    SUBTITLE = (
        "Single channel: full RF diagnostics from one capture. "
        "Multi-channel: compare traffic across several channel captures side by side."
    )
    TASK_NAME = "channel_monitor"
    INPUT_GUIDE = (
        "Tab 1 — Single Channel Monitor: run deep traffic analysis on one capture. "
        "The channel is auto-detected if not specified. "
        "Tab 2 — Multi-Channel Survey: add multiple captures (one per channel) and get a "
        "cross-channel comparison report covering every traffic parameter."
    )

    # ── helpers ──────────────────────────────────────────────────────────────

    def _make_spin_multiples_of_60(self) -> QSpinBox:
        spin = QSpinBox()
        spin.setRange(60, 3600)
        spin.setSingleStep(60)
        spin.setValue(60)
        spin.setToolTip(
            "Rolling window used for trend calculations. Must be a multiple of 60 seconds."
        )
        return spin

    # ── two-tab layout ────────────────────────────────────────────────────────

    def _build_inputs(self, layout: QVBoxLayout):
        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_single_channel_tab(), "Single Channel Monitor")
        self._tabs.addTab(self._build_multi_channel_tab(), "Multi-Channel Survey")
        layout.addWidget(self._tabs)

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 0 — Single Channel Monitor
    # ══════════════════════════════════════════════════════════════════════════

    def _build_single_channel_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        desc = QLabel(
            "Run full channel diagnostics on a single capture: RF utilisation, retry "
            "pressure, per-BSSID/client stats, station spotlight and overload indicators. "
            "If no channel is selected the dominant channel is auto-detected from the capture."
        )
        desc.setObjectName("fieldHelp")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # ── Capture file ──────────────────────────────────────────────────
        cap_group = QGroupBox("Capture File")
        cap_layout = QVBoxLayout(cap_group)
        cap_layout.setSpacing(10)
        self._file_selector = FileSelector(label="PCAP / pcapng:")
        cap_layout.addWidget(self._file_selector)
        layout.addWidget(cap_group)

        # ── Channel & interval ────────────────────────────────────────────
        opts_group = QGroupBox("Channel & Interval")
        opts_layout = QVBoxLayout(opts_group)
        opts_layout.setSpacing(10)

        ch_label = QLabel("Channel")
        ch_label.setObjectName("fieldLabel")
        opts_layout.addWidget(ch_label)

        self._channel_combo = QComboBox()
        self._channel_combo.addItem("Auto-detect from capture", None)
        self._channel_combo.addItem("── 2.4 GHz ──", None)
        for ch in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]:
            self._channel_combo.addItem(f"Channel {ch}  (2.4 GHz)", ch)
        self._channel_combo.addItem("── 5 GHz ──", None)
        for ch in [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108,
                   112, 116, 120, 124, 128, 132, 136, 140, 144, 149,
                   153, 157, 161, 165]:
            self._channel_combo.addItem(f"Channel {ch}  (5 GHz)", ch)
        self._channel_combo.addItem("── 6 GHz ──", None)
        for ch in [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49,
                   53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93]:
            self._channel_combo.addItem(f"Channel {ch}  (6 GHz)", ch)
        self._channel_combo.setCurrentIndex(0)
        opts_layout.addWidget(self._channel_combo)

        ch_help = QLabel(
            "Leave on Auto-detect to let the tool identify the dominant channel from "
            "wlan_radio.channel metadata in the capture. Choose a specific channel only when "
            "you want to restrict analysis to that channel."
        )
        ch_help.setObjectName("fieldHelp")
        ch_help.setWordWrap(True)
        opts_layout.addWidget(ch_help)

        int_label = QLabel("Interval (seconds)")
        int_label.setObjectName("fieldLabel")
        opts_layout.addWidget(int_label)

        self._interval_spin = self._make_spin_multiples_of_60()
        opts_layout.addWidget(self._interval_spin)

        int_help = QLabel(
            "Time window for trend calculations (utilisation, throughput, retry rate). "
            "Must be a multiple of 60 s."
        )
        int_help.setObjectName("fieldHelp")
        int_help.setWordWrap(True)
        opts_layout.addWidget(int_help)

        layout.addWidget(opts_group)

        # ── Scope filters ─────────────────────────────────────────────────
        filt_group = QGroupBox("Scope Filters  (all optional)")
        filt_layout = QVBoxLayout(filt_group)
        filt_layout.setSpacing(10)

        bssid_label = QLabel("BSSID")
        bssid_label.setObjectName("fieldLabel")
        filt_layout.addWidget(bssid_label)

        bssid_help = QLabel(
            "Restrict the analysis to a single access point when multiple BSSIDs are present."
        )
        bssid_help.setObjectName("fieldHelp")
        bssid_help.setWordWrap(True)
        filt_layout.addWidget(bssid_help)

        self._bssid_edit = QLineEdit()
        self._bssid_edit.setPlaceholderText(
            "Filter to AP BSSID (optional), e.g. 00:04:EA:38:70:E0"
        )
        self._bssid_edit.setMaxLength(17)
        filt_layout.addWidget(self._bssid_edit)

        self._mac_input = MacAddressInput(
            label="Client MAC:",
            placeholder="Filter to client MAC (optional)",
            description=(
                "Focus the report on one station while keeping the rest of the "
                "capture available for background context."
            ),
        )
        filt_layout.addWidget(self._mac_input)

        station_label = QLabel("Station Spotlight")
        station_label.setObjectName("fieldLabel")
        filt_layout.addWidget(station_label)

        station_help = QLabel(
            "Enter a station MAC to generate a deeper per-device roaming, "
            "throughput, and retry profile alongside the full channel report."
        )
        station_help.setObjectName("fieldHelp")
        station_help.setWordWrap(True)
        filt_layout.addWidget(station_help)

        self._station_edit = QLineEdit()
        self._station_edit.setPlaceholderText(
            "Station MAC for spotlight profile (optional), e.g. F8:ED:FC:FE:F0:06"
        )
        self._station_edit.setMaxLength(17)
        filt_layout.addWidget(self._station_edit)

        out_label = QLabel("Output Prefix")
        out_label.setObjectName("fieldLabel")
        filt_layout.addWidget(out_label)

        out_help = QLabel(
            "Leave blank to auto-name JSON and HTML outputs under the results directory."
        )
        out_help.setObjectName("fieldHelp")
        out_help.setWordWrap(True)
        filt_layout.addWidget(out_help)

        self._output_edit = QLineEdit()
        self._output_edit.setPlaceholderText(
            "Output path prefix (optional), e.g. results/ch6_monitor"
        )
        filt_layout.addWidget(self._output_edit)

        layout.addWidget(filt_group)
        layout.addStretch()
        return tab

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 1 — Multi-Channel Survey
    # ══════════════════════════════════════════════════════════════════════════

    def _build_multi_channel_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        desc = QLabel(
            "Add one capture file per channel. Each file is analysed independently; the "
            "dominant channel is auto-detected from each capture. The survey report then "
            "compares every traffic parameter across all channels and highlights "
            "multi-band APs and roaming clients."
        )
        desc.setObjectName("fieldHelp")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # ── Capture files list ────────────────────────────────────────────
        files_group = QGroupBox("Capture Files  (one per channel)")
        files_layout = QVBoxLayout(files_group)
        files_layout.setSpacing(8)

        self._multi_file_list = QListWidget()
        self._multi_file_list.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection
        )
        self._multi_file_list.setMinimumHeight(130)
        self._multi_file_list.setToolTip("Each entry is one capture file for one channel.")
        files_layout.addWidget(self._multi_file_list)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        btn_add_files = QPushButton("Add Files…")
        btn_add_files.clicked.connect(self._multi_add_files)
        btn_row.addWidget(btn_add_files)

        btn_add_dir = QPushButton("Add from Directory…")
        btn_add_dir.clicked.connect(self._multi_add_dir)
        btn_row.addWidget(btn_add_dir)

        btn_remove = QPushButton("Remove Selected")
        btn_remove.clicked.connect(self._multi_remove_selected)
        btn_row.addWidget(btn_remove)

        btn_clear = QPushButton("Clear All")
        btn_clear.clicked.connect(self._multi_file_list.clear)
        btn_row.addWidget(btn_clear)

        btn_row.addStretch()
        files_layout.addLayout(btn_row)

        note = QLabel(
            "Tip: use \"Add from Directory\" to load every .pcap / .pcapng "
            "found in a folder at once."
        )
        note.setObjectName("fieldHelp")
        note.setWordWrap(True)
        files_layout.addWidget(note)

        layout.addWidget(files_group)

        # ── Survey options ────────────────────────────────────────────────
        opts_group = QGroupBox("Survey Options")
        opts_layout = QVBoxLayout(opts_group)
        opts_layout.setSpacing(10)

        int_label = QLabel("Interval (seconds)")
        int_label.setObjectName("fieldLabel")
        opts_layout.addWidget(int_label)

        self._multi_interval_spin = self._make_spin_multiples_of_60()
        opts_layout.addWidget(self._multi_interval_spin)

        int_help = QLabel(
            "Rolling window for per-channel trend analysis. Must be a multiple of 60 s. "
            "Use 60 for short captures, 120–300 for longer ones."
        )
        int_help.setObjectName("fieldHelp")
        int_help.setWordWrap(True)
        opts_layout.addWidget(int_help)

        out_label = QLabel("Output Directory")
        out_label.setObjectName("fieldLabel")
        opts_layout.addWidget(out_label)

        out_row = QHBoxLayout()
        out_row.setSpacing(8)

        self._multi_output_edit = QLineEdit()
        self._multi_output_edit.setPlaceholderText(
            "Output directory (optional, defaults to results/)"
        )
        out_row.addWidget(self._multi_output_edit, 1)

        btn_browse_out = QPushButton("Browse…")
        btn_browse_out.clicked.connect(self._multi_browse_out)
        out_row.addWidget(btn_browse_out)

        opts_layout.addLayout(out_row)
        layout.addWidget(opts_group)

        # ── Info card ─────────────────────────────────────────────────────
        info_frame = QFrame()
        info_frame.setObjectName("optionCard")
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(14, 12, 14, 12)
        info_layout.setSpacing(4)

        info_title = QLabel("What the survey report includes")
        info_title.setObjectName("optionTitle")
        info_layout.addWidget(info_title)

        info_body = QLabel(
            "• Cross-channel comparison table: utilisation, retry rate, throughput, "
            "frame rate, BSSID count, client count, avg signal, overload flags\n"
            "• Side-by-side bar charts for every key metric\n"
            "• Multi-band AP detection: APs broadcasting on more than one channel\n"
            "• Roaming client detection: stations appearing on multiple channels\n"
            "• Per-channel detail sections with links to individual reports"
        )
        info_body.setObjectName("fieldHelp")
        info_body.setWordWrap(True)
        info_layout.addWidget(info_body)

        layout.addWidget(info_frame)
        layout.addStretch()
        return tab

    # ── Multi-channel file helpers ────────────────────────────────────────

    def _multi_add_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select Capture Files", "",
            "Capture files (*.pcap *.pcapng *.cap);;All files (*)"
        )
        existing = {
            self._multi_file_list.item(i).text()
            for i in range(self._multi_file_list.count())
        }
        for f in files:
            if f not in existing:
                self._multi_file_list.addItem(QListWidgetItem(f))

    def _multi_add_dir(self):
        from pathlib import Path
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Directory Containing Captures", ""
        )
        if not dir_path:
            return
        existing = {
            self._multi_file_list.item(i).text()
            for i in range(self._multi_file_list.count())
        }
        found = sorted(
            str(p) for ext in ("*.pcap", "*.pcapng", "*.cap")
            for p in Path(dir_path).glob(ext)
        )
        for f in found:
            if f not in existing:
                self._multi_file_list.addItem(QListWidgetItem(f))

    def _multi_remove_selected(self):
        for item in self._multi_file_list.selectedItems():
            self._multi_file_list.takeItem(self._multi_file_list.row(item))

    def _multi_browse_out(self):
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Output Directory", ""
        )
        if dir_path:
            self._multi_output_edit.setText(dir_path)

    # ── validation & params ───────────────────────────────────────────────

    def _validate(self) -> str:
        if self._tabs.currentIndex() == 0:
            if not self._file_selector.get_path():
                return "Please select a PCAP file"
            if self._interval_spin.value() % 60 != 0:
                return "Interval must be a multiple of 60 seconds"
        else:
            count = self._multi_file_list.count()
            if count == 0:
                return "Please add at least one capture file"
            if count < 2:
                return (
                    "At least 2 capture files are required for a multi-channel comparison. "
                    "For a single capture, use the Single Channel Monitor tab."
                )
            if self._multi_interval_spin.value() % 60 != 0:
                return "Interval must be a multiple of 60 seconds"
        return ""

    def _get_params(self) -> dict:
        if self._tabs.currentIndex() == 0:
            return {
                "pcap": self._file_selector.get_path(),
                "channel": self._channel_combo.currentData(),
                "bssid": self._bssid_edit.text().strip() or None,
                "mac": self._mac_input.get_mac() or None,
                "station": self._station_edit.text().strip() or None,
                "interval": float(self._interval_spin.value()),
                "output": self._output_edit.text().strip() or None,
            }
        else:
            return {
                "pcap_files": [
                    self._multi_file_list.item(i).text()
                    for i in range(self._multi_file_list.count())
                ],
                "interval": float(self._multi_interval_spin.value()),
                "output_dir": self._multi_output_edit.text().strip() or None,
            }

    # ── run dispatch ──────────────────────────────────────────────────────

    def _on_run(self):
        error = self._validate()
        if error:
            self._log.clear()
            self._log.append(f"⚠ ERROR: {error}")
            self._log.setVisible(True)
            return

        params = self._get_params()
        tab = self._tabs.currentIndex()
        task = "channel_monitor" if tab == 0 else "multichannel_survey"

        self._btn_run.setEnabled(False)
        self._progress.setVisible(True)
        self._status_label.setText(
            "Running single channel monitor…"
            if tab == 0
            else f"Running multi-channel survey on {len(params.get('pcap_files', []))} captures…"
        )
        self._status_label.setVisible(True)
        self._log.clear()
        self._log.setVisible(True)
        self._results.clear()

        self._worker = AnalysisWorker(task, params)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_finished(self, result: dict):
        self._btn_run.setEnabled(True)
        self._progress.setVisible(False)
        self._status_label.setVisible(False)

        if result.get("stdout"):
            self._log.append(result["stdout"][:2000])

        title = (
            "Single Channel Monitor Results"
            if self._tabs.currentIndex() == 0
            else "Multi-Channel Survey Results"
        )
        self._results.show_results(
            json_data=result.get("json_data"),
            html_path=result.get("html_path"),
            title=title,
        )

    def _on_error(self, msg: str):
        self._btn_run.setEnabled(True)
        self._progress.setVisible(False)
        self._status_label.setVisible(False)
        self._log.append(f"ERROR: {msg}")
        self._log.setVisible(True)

    def _on_build_client_map(self):
        pass

    def _on_build_combined_report(self):
        pass

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

