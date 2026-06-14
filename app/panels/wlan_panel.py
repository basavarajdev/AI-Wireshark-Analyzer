"""WLAN / Wi-Fi Analysis panel."""

from PyQt6.QtWidgets import QVBoxLayout, QGroupBox

from app.panels.base_panel import BaseAnalysisPanel
from app.widgets.inputs import FileSelector, MacAddressInput


class WlanPanel(BaseAnalysisPanel):
    TITLE = "WLAN / Wi-Fi Analysis"
    SUBTITLE = "Full 802.11 analysis — WPA2/WPA3/SAE authentication, connection failures, beacon loss, scan patterns"
    TASK_NAME = "wlan"
    INPUT_GUIDE = "Start with a wireless capture, then optionally scope the report to a single device. Use this panel when you need root-cause detail for association, authentication, roaming, signal, and retry problems."

    def _build_inputs(self, layout: QVBoxLayout):
        group = QGroupBox("Capture Scope")
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(12)

        self._file_selector = FileSelector(label="PCAP File:")
        group_layout.addWidget(self._file_selector)

        self._mac_input = MacAddressInput(
            label="MAC Filter:",
            placeholder="Filter to single client MAC (optional), e.g. AA:BB:CC:DD:EE:FF",
            description="Optional. Use this when the capture contains multiple stations and you want a single-client diagnosis."
        )
        group_layout.addWidget(self._mac_input)

        layout.addWidget(group)

    def _validate(self) -> str:
        if not self._file_selector.get_path():
            return "Please select a PCAP file"
        return ""

    def _get_params(self) -> dict:
        return {
            "pcap": self._file_selector.get_path(),
            "mac": self._mac_input.get_mac(),
        }
