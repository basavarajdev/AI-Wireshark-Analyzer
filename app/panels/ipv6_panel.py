"""IPv6 Traffic Analysis panel."""

from PyQt6.QtWidgets import QVBoxLayout, QGroupBox

from app.panels.base_panel import BaseAnalysisPanel
from app.widgets.inputs import FileSelector, IPv6Input


class IPv6Panel(BaseAnalysisPanel):
    TITLE = "IPv6 Traffic Analysis"
    SUBTITLE = "Per-address IPv6 diagnostics — TCP connections, UDP flows, ICMPv6/NDP, SNMP, retransmissions"
    TASK_NAME = "ipv6"
    INPUT_GUIDE = "Select the capture and enter the exact IPv6 address you want to inspect. This panel focuses the report on one node so transport, ICMPv6, NDP, and SNMP behavior stays readable."

    def _build_inputs(self, layout: QVBoxLayout):
        group = QGroupBox("Capture Scope")
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(12)

        self._file_selector = FileSelector(label="PCAP File:")
        group_layout.addWidget(self._file_selector)

        self._ipv6_input = IPv6Input(
            label="IPv6 Addr:",
            placeholder="Target IPv6 address, e.g. 2408:8a04:e001:0:faed:fcff:fefe:10c1"
        )
        group_layout.addWidget(self._ipv6_input)

        layout.addWidget(group)

    def _validate(self) -> str:
        if not self._file_selector.get_path():
            return "Please select a PCAP file"
        if not self._ipv6_input.get_address():
            return "Please enter an IPv6 address"
        return ""

    def _get_params(self) -> dict:
        return {
            "pcap": self._file_selector.get_path(),
            "ipv6_address": self._ipv6_input.get_address(),
        }
