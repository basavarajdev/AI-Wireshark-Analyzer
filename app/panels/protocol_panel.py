"""Protocol Analyzers panel — TCP, UDP, DNS, HTTP, HTTPS, ICMP, DHCP."""

from PyQt6.QtWidgets import QVBoxLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QGridLayout

from app.panels.base_panel import BaseAnalysisPanel
from app.widgets.inputs import FileSelector, ProtocolSelector, FilterInput


class ProtocolPanel(BaseAnalysisPanel):
    TITLE = "Protocol Analyzers"
    SUBTITLE = "Security threat detection — SYN floods, DNS tunneling, SQL injection, port scans, DHCP attacks"
    TASK_NAME = "protocol"
    INPUT_GUIDE = "Use this panel when you want a focused protocol deep-dive. Start with a capture, choose one protocol or all protocols, and optionally apply IP/port filters for targeted analysis."

    def _build_inputs(self, layout: QVBoxLayout):
        group = QGroupBox("Capture Scope")
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(12)

        self._file_selector = FileSelector(label="PCAP File:")
        group_layout.addWidget(self._file_selector)

        self._protocol_selector = ProtocolSelector(label="Protocol:")
        group_layout.addWidget(self._protocol_selector)

        # Filter options
        filter_group = QGroupBox("2. Optional Filters (for IP-based protocols)")
        filter_layout = QGridLayout(filter_group)
        filter_layout.setHorizontalSpacing(12)
        filter_layout.setVerticalSpacing(8)

        # Wireshark display filter
        wireshark_label = QLabel("Wireshark Filter:")
        wireshark_label.setObjectName("fieldLabel")
        filter_layout.addWidget(wireshark_label, 0, 0)

        self._filter_input = FilterInput(
            label="",
            placeholder='e.g. ip.addr==192.168.1.1 or tcp.port==80'
        )
        filter_layout.addWidget(self._filter_input, 0, 1)

        wireshark_help = QLabel("Use standard Wireshark display filter syntax")
        wireshark_help.setObjectName("fieldHelp")
        filter_layout.addWidget(wireshark_help, 1, 0, 1, 2)

        # IP filter
        ip_label = QLabel("IP Address:")
        ip_label.setObjectName("fieldLabel")
        filter_layout.addWidget(ip_label, 2, 0)

        self._ip_filter = QLineEdit()
        self._ip_filter.setPlaceholderText("e.g. 192.168.1.1")
        filter_layout.addWidget(self._ip_filter, 2, 1)

        ip_help = QLabel("Filter by IP address (source or destination)")
        ip_help.setObjectName("fieldHelp")
        filter_layout.addWidget(ip_help, 3, 0, 1, 2)

        # Port filter
        port_label = QLabel("TCP/UDP Port:")
        port_label.setObjectName("fieldLabel")
        filter_layout.addWidget(port_label, 4, 0)

        self._port_filter = QLineEdit()
        self._port_filter.setPlaceholderText("e.g. 80,443,8080")
        filter_layout.addWidget(self._port_filter, 4, 1)

        port_help = QLabel("Filter by port (source or destination). Comma-separated for multiple ports")
        port_help.setObjectName("fieldHelp")
        filter_layout.addWidget(port_help, 5, 0, 1, 2)

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
            "protocol": self._protocol_selector.get_protocol(),
            "filter": self._filter_input.get_filter(),
            "ip_filter": self._ip_filter.text().strip() or None,
            "port_filter": self._port_filter.text().strip() or None,
        }

