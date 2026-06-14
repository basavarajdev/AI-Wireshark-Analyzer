"""Reusable widgets: PCAP file selector, MAC entry, results viewer."""

from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QComboBox
)
from PyQt6.QtCore import pyqtSignal


class FileSelector(QWidget):
    """PCAP/PCAPNG file selector with browse button."""

    file_changed = pyqtSignal(str)

    def __init__(self, label: str = "PCAP File:", placeholder: str = "Select a .pcap or .pcapng file...",
                 description: str = "Required. Select the capture file that will be parsed for this analysis.",
                 parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        if label:
            lbl = QLabel(label)
            lbl.setObjectName("fieldLabel")
            layout.addWidget(lbl)

        if description:
            hint = QLabel(description)
            hint.setObjectName("fieldHelp")
            hint.setWordWrap(True)
            layout.addWidget(hint)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(placeholder)
        self.path_edit.setReadOnly(True)
        row.addWidget(self.path_edit, 1)

        self.browse_btn = QPushButton("Browse")
        self.browse_btn.setObjectName("btnBrowse")
        self.browse_btn.clicked.connect(self._browse)
        row.addWidget(self.browse_btn)

        layout.addLayout(row)

    def _browse(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select PCAP File",
            str(Path.home()),
            "Packet Captures (*.pcap *.pcapng *.cap);;All Files (*)"
        )
        if file_path:
            self.path_edit.setText(file_path)
            self.file_changed.emit(file_path)

    def get_path(self) -> str:
        return self.path_edit.text().strip()

    def set_path(self, path: str):
        self.path_edit.setText(path)


class MacAddressInput(QWidget):
    """MAC address input field with validation hint."""

    def __init__(self, label: str = "MAC Filter:", placeholder: str = "e.g. AA:BB:CC:DD:EE:FF (optional)",
                 description: str = "Optional. Narrow the report to a single client or station MAC address.",
                 parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        if label:
            lbl = QLabel(label)
            lbl.setObjectName("fieldLabel")
            layout.addWidget(lbl)

        if description:
            hint = QLabel(description)
            hint.setObjectName("fieldHelp")
            hint.setWordWrap(True)
            layout.addWidget(hint)

        self.mac_edit = QLineEdit()
        self.mac_edit.setPlaceholderText(placeholder)
        self.mac_edit.setMaxLength(17)
        layout.addWidget(self.mac_edit)

    def get_mac(self) -> str:
        return self.mac_edit.text().strip()


class IPv6Input(QWidget):
    """IPv6 address input field."""

    def __init__(self, label: str = "IPv6 Address:", placeholder: str = "e.g. 2408:8a04:e001:0:faed:fcff:fefe:10c1",
                 description: str = "Required. Enter the exact IPv6 address you want to inspect inside the capture.",
                 parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        if label:
            lbl = QLabel(label)
            lbl.setObjectName("fieldLabel")
            layout.addWidget(lbl)

        if description:
            hint = QLabel(description)
            hint.setObjectName("fieldHelp")
            hint.setWordWrap(True)
            layout.addWidget(hint)

        self.ipv6_edit = QLineEdit()
        self.ipv6_edit.setPlaceholderText(placeholder)
        layout.addWidget(self.ipv6_edit)

    def get_address(self) -> str:
        return self.ipv6_edit.text().strip()


class ProtocolSelector(QWidget):
    """Protocol dropdown selector."""

    def __init__(self, label: str = "Protocol:",
                 description: str = "Choose a focused protocol report or scan all protocols for a broader security summary.",
                 parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        if label:
            lbl = QLabel(label)
            lbl.setObjectName("fieldLabel")
            layout.addWidget(lbl)

        if description:
            hint = QLabel(description)
            hint.setObjectName("fieldHelp")
            hint.setWordWrap(True)
            layout.addWidget(hint)

        self.combo = QComboBox()
        self.combo.addItems(["All Protocols", "TCP", "UDP", "DNS", "HTTP", "HTTPS", "ICMP", "DHCP", "WLAN"])
        layout.addWidget(self.combo)

    def get_protocol(self) -> str:
        val = self.combo.currentText()
        return "all" if val == "All Protocols" else val.lower()


class FilterInput(QWidget):
    """Wireshark display filter input."""

    def __init__(self, label: str = "Filter:", placeholder: str = 'e.g. ip.addr==192.168.1.1 (optional)',
                 description: str = "Optional Wireshark display filter applied before the report is generated.",
                 parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        if label:
            lbl = QLabel(label)
            lbl.setObjectName("fieldLabel")
            layout.addWidget(lbl)

        if description:
            hint = QLabel(description)
            hint.setObjectName("fieldHelp")
            hint.setWordWrap(True)
            layout.addWidget(hint)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(placeholder)
        layout.addWidget(self.filter_edit)

    def get_filter(self) -> str:
        return self.filter_edit.text().strip()
