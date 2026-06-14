"""WPA/WPA2/WPA3 Decryption panel."""

from PyQt6.QtWidgets import (
    QVBoxLayout, QGroupBox, QHBoxLayout, QLabel, QComboBox, QCheckBox,
    QLineEdit, QFrame
)

from app.panels.base_panel import BaseAnalysisPanel
from app.widgets.inputs import FileSelector, MacAddressInput


class DecryptPanel(BaseAnalysisPanel):
    TITLE = "WPA/WPA2/WPA3 Decryption"
    SUBTITLE = "Decrypt 802.11 wireless captures using network keys — supports wpa-pwd (passphrase) and wpa-psk (PMK) decryption, with inner-protocol analysis"
    TASK_NAME = "decrypt"
    INPUT_GUIDE = "Provide the capture, then supply either the Wi-Fi passphrase with SSID or a 64-character PMK. Use the optional MAC filter when you want decrypted traffic for one client only."

    def _build_option_card(self, title: str, value: str, description: str):
        card = QFrame()
        card.setObjectName("optionCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 14, 14, 14)
        card_layout.setSpacing(4)

        title_label = QLabel(title)
        title_label.setObjectName("optionTitle")
        card_layout.addWidget(title_label)

        value_label = QLabel(value)
        value_label.setObjectName("optionValue")
        card_layout.addWidget(value_label)

        desc_label = QLabel(description)
        desc_label.setObjectName("fieldHelp")
        desc_label.setWordWrap(True)
        card_layout.addWidget(desc_label)
        return card

    def _build_inputs(self, layout: QVBoxLayout):
        group1 = QGroupBox("Capture Scope")
        group1_layout = QVBoxLayout(group1)
        group1_layout.setSpacing(12)

        self._file_selector = FileSelector(label="PCAP File:")
        group1_layout.addWidget(self._file_selector)

        self._mac_input = MacAddressInput(
            label="MAC Filter:",
            placeholder="Filter to single client MAC (optional), e.g. AA:BB:CC:DD:EE:FF",
            description="Optional. Restrict decryption analysis and the report output to one wireless client."
        )
        group1_layout.addWidget(self._mac_input)

        layout.addWidget(group1)

        mode_group = QGroupBox("Decryption Modes")
        mode_layout = QVBoxLayout(mode_group)
        mode_layout.setSpacing(12)
        mode_layout.addWidget(
            self._build_option_card(
                "Recommended for",
                "wpa-pwd",
                "Use your Wi-Fi SSID and passphrase. Best for normal home, office, and lab captures."
            )
        )
        mode_layout.addWidget(
            self._build_option_card(
                "Advanced mode",
                "wpa-psk",
                "Use a 64-character PMK when you already derived the key externally or need repeatable automation."
            )
        )
        layout.addWidget(mode_group)

        group2 = QGroupBox("Credentials")
        group2_layout = QVBoxLayout(group2)
        group2_layout.setSpacing(12)

        key_type_lbl = QLabel("Key Type")
        key_type_lbl.setObjectName("fieldLabel")
        group2_layout.addWidget(key_type_lbl)

        key_type_help = QLabel("Choose the credential mode that matches your capture and available secrets.")
        key_type_help.setObjectName("fieldHelp")
        key_type_help.setWordWrap(True)
        group2_layout.addWidget(key_type_help)

        self._key_type_combo = QComboBox()
        self._key_type_combo.addItem("wpa-pwd", "wpa-pwd")
        self._key_type_combo.addItem("wpa-psk", "wpa-psk")
        self._key_type_combo.currentIndexChanged.connect(self._on_key_type_changed)
        group2_layout.addWidget(self._key_type_combo)

        key_label = QLabel("Passphrase or PMK")
        key_label.setObjectName("fieldLabel")
        group2_layout.addWidget(key_label)

        key_help = QLabel("For wpa-pwd, enter the Wi-Fi password. For wpa-psk, enter the full 64-character hexadecimal PMK.")
        key_help.setObjectName("fieldHelp")
        key_help.setWordWrap(True)
        group2_layout.addWidget(key_help)

        self._key_edit = QLineEdit()
        self._key_edit.setPlaceholderText("Wi-Fi password or 64-character PMK")
        group2_layout.addWidget(self._key_edit)

        ssid_label = QLabel("Network SSID")
        ssid_label.setObjectName("fieldLabel")
        group2_layout.addWidget(ssid_label)

        self._ssid_help = QLabel("Required only for wpa-pwd. This must exactly match the network name in the capture.")
        self._ssid_help.setObjectName("fieldHelp")
        self._ssid_help.setWordWrap(True)
        group2_layout.addWidget(self._ssid_help)

        self._ssid_edit = QLineEdit()
        self._ssid_edit.setPlaceholderText("e.g. Lab-SSID-5G")
        group2_layout.addWidget(self._ssid_edit)

        layout.addWidget(group2)

        group3 = QGroupBox("Options")
        group3_layout = QVBoxLayout(group3)
        group3_layout.setSpacing(10)

        option_help = QLabel("Choose whether to keep the decrypted capture for later packet-by-packet inspection in Wireshark.")
        option_help.setObjectName("fieldHelp")
        option_help.setWordWrap(True)
        group3_layout.addWidget(option_help)

        self._check_save_pcap = QCheckBox("Save decrypted PCAP to results folder")
        self._check_save_pcap.setChecked(False)
        group3_layout.addWidget(self._check_save_pcap)

        layout.addWidget(group3)

    def _on_key_type_changed(self, index: int):
        """Show/hide SSID field based on key type."""
        key_type = self._key_type_combo.currentData()
        show_ssid = key_type == "wpa-pwd"
        self._ssid_edit.setVisible(show_ssid)
        self._ssid_help.setVisible(show_ssid)

    def _validate(self) -> str:
        if not self._file_selector.get_path():
            return "Please select a PCAP file"
        key_type = self._key_type_combo.currentData()
        if not self._key_edit.text().strip():
            return f"Please enter a password/PMK for {key_type}"
        if key_type == "wpa-pwd" and not self._ssid_edit.text().strip():
            return "Please enter the network SSID for wpa-pwd decryption"
        if key_type == "wpa-psk":
            pmk = self._key_edit.text().strip()
            if len(pmk) != 64 or not all(c in "0123456789abcdefABCDEF" for c in pmk):
                return "PMK must be exactly 64 hexadecimal characters"
        return ""

    def _get_params(self) -> dict:
        return {
            "pcap": self._file_selector.get_path(),
            "key_type": self._key_type_combo.currentData(),
            "password": self._key_edit.text().strip(),
            "ssid": self._ssid_edit.text().strip(),
            "mac": self._mac_input.get_mac(),
            "save_decrypted_pcap": self._check_save_pcap.isChecked(),
        }
