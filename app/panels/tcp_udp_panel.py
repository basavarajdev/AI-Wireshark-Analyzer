"""TCP/UDP Application Diagnostics panel."""

from PyQt6.QtWidgets import QVBoxLayout, QGroupBox, QLabel, QLineEdit, QGridLayout, QFrame

from app.panels.base_panel import BaseAnalysisPanel
from app.widgets.inputs import FileSelector


class TcpUdpPanel(BaseAnalysisPanel):
    TITLE = "TCP/UDP Application Diagnostics"
    SUBTITLE = "Zero-window stalls, retransmissions, RST events, UDP flows, QUIC detection"
    TASK_NAME = "tcp_udp"
    INPUT_GUIDE = "Use this panel for application slowdowns, print failures, and unstable sessions. Pick a capture file and optionally filter by IP address and/or TCP/UDP port."

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

        # Filters group
        filter_group = QGroupBox("2. Optional Filters")
        filter_layout = QGridLayout(filter_group)
        filter_layout.setHorizontalSpacing(12)
        filter_layout.setVerticalSpacing(8)

        ip_label = QLabel("IP Address:")
        ip_label.setObjectName("fieldLabel")
        filter_layout.addWidget(ip_label, 0, 0)

        self._ip_filter = QLineEdit()
        self._ip_filter.setPlaceholderText("e.g. 192.168.1.1 (both src and dst)")
        filter_layout.addWidget(self._ip_filter, 0, 1)

        ip_help = QLabel("Optional. Filter by IP address (source or destination)")
        ip_help.setObjectName("fieldHelp")
        filter_layout.addWidget(ip_help, 1, 0, 1, 2)

        port_label = QLabel("TCP/UDP Port:")
        port_label.setObjectName("fieldLabel")
        filter_layout.addWidget(port_label, 2, 0)

        self._port_filter = QLineEdit()
        self._port_filter.setPlaceholderText("e.g. 80,443,8080 or 22")
        filter_layout.addWidget(self._port_filter, 2, 1)

        port_help = QLabel("Optional. Filter by port (source or destination). Comma-separated for multiple ports")
        port_help.setObjectName("fieldHelp")
        filter_layout.addWidget(port_help, 3, 0, 1, 2)

        layout.addWidget(group)
        layout.addWidget(filter_group)

    def _validate(self) -> str:
        if not self._file_selector.get_path():
            return "Please select a PCAP file"
        
        # Validate IP filter if provided
        ip_filter = self._ip_filter.text().strip()
        if ip_filter:
            ip_parts = ip_filter.split('.')
            if len(ip_parts) != 4:
                return "Invalid IP address format. Use format: 192.168.1.1"
            try:
                for part in ip_parts:
                    if not (0 <= int(part) <= 255):
                        return "Invalid IP address: octets must be 0-255"
            except ValueError:
                return "Invalid IP address: all octets must be numeric"
        
        # Validate port filter if provided
        port_filter = self._port_filter.text().strip()
        if port_filter:
            ports = port_filter.split(',')
            for port in ports:
                port = port.strip()
                try:
                    port_num = int(port)
                    if not (1 <= port_num <= 65535):
                        return f"Invalid port {port_num}: must be between 1 and 65535"
                except ValueError:
                    return f"Invalid port value: '{port}' is not a number"
        
        return ""

    def _get_params(self) -> dict:
        return {
            "pcap": self._file_selector.get_path(),
            "ip_filter": self._ip_filter.text().strip() or None,
            "port_filter": self._port_filter.text().strip() or None,
        }

