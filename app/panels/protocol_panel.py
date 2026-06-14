"""Protocol Analyzers panel — TCP, UDP, DNS, HTTP, HTTPS, ICMP, DHCP."""

from PyQt6.QtWidgets import QVBoxLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit

from app.panels.base_panel import BaseAnalysisPanel
from app.widgets.inputs import FileSelector, ProtocolSelector, FilterInput


class ProtocolPanel(BaseAnalysisPanel):
    TITLE = "Protocol Analyzers"
    SUBTITLE = "Security threat detection — SYN floods, DNS tunneling, SQL injection, port scans, DHCP attacks"
    TASK_NAME = "protocol"
    INPUT_GUIDE = "Use this panel when you want a focused protocol deep-dive. Start with a capture, choose one protocol or all protocols, and optionally apply a Wireshark display filter for targeted evidence."

    def _build_inputs(self, layout: QVBoxLayout):
        group = QGroupBox("Capture Scope")
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(12)

        self._file_selector = FileSelector(label="PCAP File:")
        group_layout.addWidget(self._file_selector)

        self._protocol_selector = ProtocolSelector(label="Protocol:")
        group_layout.addWidget(self._protocol_selector)

        self._filter_input = FilterInput(
            label="Filter:",
            placeholder='Wireshark display filter (optional), e.g. ip.addr==192.168.1.1'
        )
        group_layout.addWidget(self._filter_input)

        # HTML output path
        out_row = QHBoxLayout()
        out_label = QLabel("HTML Out:")
        out_label.setObjectName("fieldLabel")
        out_label.setFixedWidth(80)
        out_row.addWidget(out_label)

        self._html_output = QLineEdit()
        self._html_output.setPlaceholderText("Path for HTML report (optional), e.g. results/tcp_report.html")
        out_row.addWidget(self._html_output, 1)
        group_layout.addLayout(out_row)

        layout.addWidget(group)

    def _validate(self) -> str:
        if not self._file_selector.get_path():
            return "Please select a PCAP file"
        return ""

    def _get_params(self) -> dict:
        return {
            "pcap": self._file_selector.get_path(),
            "protocol": self._protocol_selector.get_protocol(),
            "filter": self._filter_input.get_filter(),
            "html_output": self._html_output.text().strip(),
        }
