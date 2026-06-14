"""TCP/UDP Application Diagnostics panel."""

from PyQt6.QtWidgets import QVBoxLayout, QGroupBox, QLabel, QLineEdit, QGridLayout, QFrame

from app.panels.base_panel import BaseAnalysisPanel
from app.widgets.inputs import FileSelector


class TcpUdpPanel(BaseAnalysisPanel):
    TITLE = "TCP/UDP Application Diagnostics"
    SUBTITLE = "Zero-window stalls, retransmissions, RST events, UDP flows, QUIC detection"
    TASK_NAME = "tcp_udp"
    INPUT_GUIDE = "Use this panel for application slowdowns, print failures, and unstable sessions. Pick a capture and optionally override the HTML output path if you want to control where the report is saved."

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
        group = QGroupBox("1. Capture Source")
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(12)

        capture_note = QLabel(
            "Use this analysis for application-level failures such as printer stalls, retransmission-heavy transfers, reset bursts, and noisy UDP sessions."
        )
        capture_note.setObjectName("fieldHelp")
        capture_note.setWordWrap(True)
        group_layout.addWidget(capture_note)

        self._file_selector = FileSelector(label="PCAP File:")
        group_layout.addWidget(self._file_selector)

        coverage_group = QGroupBox("Included Diagnostics")
        coverage_layout = QGridLayout(coverage_group)
        coverage_layout.setHorizontalSpacing(12)
        coverage_layout.setVerticalSpacing(12)
        coverage_layout.addWidget(self._build_option_card("TCP health", "Zero-window events, retransmissions, duplicate ACKs, and reset storms."), 0, 0)
        coverage_layout.addWidget(self._build_option_card("UDP visibility", "Top flows, floods, multicast traffic, and QUIC-heavy sessions."), 0, 1)
        coverage_layout.addWidget(self._build_option_card("Best use case", "Printer failures, file transfer stalls, and application slowness."), 1, 0, 1, 2)
        group_layout.addWidget(coverage_group)

        out_group = QGroupBox("2. Report Output")
        out_group_layout = QVBoxLayout(out_group)
        out_group_layout.setSpacing(12)

        out_label = QLabel("Output HTML")
        out_label.setObjectName("fieldLabel")
        out_group_layout.addWidget(out_label)

        out_help = QLabel("Optional. Leave blank to save the report automatically under results/ using the capture name.")
        out_help.setObjectName("fieldHelp")
        out_help.setWordWrap(True)
        out_group_layout.addWidget(out_help)

        self._output_edit = QLineEdit()
        self._output_edit.setPlaceholderText("Leave blank for auto-generated path in results/")
        out_group_layout.addWidget(self._output_edit)
        layout.addWidget(group)
        layout.addWidget(out_group)

    def _validate(self) -> str:
        if not self._file_selector.get_path():
            return "Please select a PCAP file"
        return ""

    def _get_params(self) -> dict:
        return {
            "pcap": self._file_selector.get_path(),
            "output": self._output_edit.text().strip(),
        }
