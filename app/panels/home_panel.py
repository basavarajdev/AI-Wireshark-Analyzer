"""Home / Welcome panel."""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGridLayout,
    QFrame, QScrollArea, QStyle
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon, QPixmap
from app.resources import get_resource_path


class FeatureCard(QFrame):
    """Clickable feature card for the home screen."""

    clicked = pyqtSignal(str)

    def __init__(self, title: str, description: str, theme_icon: str,
                 fallback_icon: QStyle.StandardPixmap, nav_key: str, parent=None):
        super().__init__(parent)
        self._nav_key = nav_key
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setObjectName("featureCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(8)

        icon = QIcon.fromTheme(theme_icon, self.style().standardIcon(fallback_icon))
        icon_lbl = QLabel()
        icon_lbl.setPixmap(icon.pixmap(28, 28))
        icon_lbl.setStyleSheet("background: transparent;")
        layout.addWidget(icon_lbl, alignment=Qt.AlignmentFlag.AlignLeft)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("font-size: 14px; font-weight: 700; color: #f4f8ff; background: transparent;")
        layout.addWidget(title_lbl)

        desc_lbl = QLabel(description)
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("font-size: 11px; color: #9cb0c6; line-height: 1.45; background: transparent;")
        layout.addWidget(desc_lbl)

        layout.addStretch()

    def mousePressEvent(self, event):
        self.clicked.emit(self._nav_key)
        super().mousePressEvent(event)


class _InfoCard(QFrame):
    """Non-clickable info card for guidance and benefits."""

    def __init__(self, theme_icon: str, fallback_icon: QStyle.StandardPixmap,
                 title: str, description: str, parent=None):
        super().__init__(parent)
        self.setObjectName("infoCard")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        icon = QIcon.fromTheme(theme_icon, self.style().standardIcon(fallback_icon))
        icon_lbl = QLabel()
        icon_lbl.setPixmap(icon.pixmap(24, 24))
        icon_lbl.setStyleSheet("background: transparent;")
        icon_lbl.setFixedWidth(32)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(icon_lbl)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(4)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("font-size: 12px; font-weight: 700; color: #eef5ff; background: transparent;")
        text_layout.addWidget(title_lbl)

        desc_lbl = QLabel(description)
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("font-size: 11px; color: #9cb0c6; line-height: 1.45; background: transparent;")
        text_layout.addWidget(desc_lbl)

        layout.addLayout(text_layout, 1)


class HomePanel(QWidget):
    """Welcome screen with project overview, advantages, and quick navigation."""

    navigate_to = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        outer.addWidget(scroll)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(18)
        scroll.setWidget(container)

        hero = QFrame()
        hero.setObjectName("heroCard")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(24, 24, 24, 24)
        hero_layout.setSpacing(10)

        brand_row = QHBoxLayout()
        brand_row.setSpacing(14)

        app_icon = QLabel()
        app_icon.setObjectName("heroAppIcon")
        icon_path = get_resource_path("installer", "app_icon.png")
        if icon_path.exists():
            pixmap = QPixmap(str(icon_path))
            scaled_pixmap = pixmap.scaled(
                88,
                88,
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation,
            )
            app_icon.setPixmap(scaled_pixmap)
        else:
            fallback = self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
            app_icon.setPixmap(fallback.pixmap(88, 88))
        app_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        app_icon.setFixedSize(88, 88)
        brand_row.addWidget(app_icon)

        brand_text = QVBoxLayout()
        brand_text.setSpacing(2)
        app_name = QLabel("AI-Wireshark Analyzer")
        app_name.setObjectName("heroAppName")
        brand_text.addWidget(app_name)

        app_sub = QLabel("Smart diagnostics for packet captures")
        app_sub.setObjectName("heroAppSub")
        brand_text.addWidget(app_sub)
        developer = QLabel("Developed by Basavaraj Bidnal (basavaraj.bidnal@hp.com)")
        developer.setObjectName("fieldHelp")
        brand_text.addWidget(developer)
        brand_row.addLayout(brand_text, 1)
        hero_layout.addLayout(brand_row)

        eyebrow = QLabel("AI-assisted packet diagnostics")
        eyebrow.setObjectName("sectionEyebrow")
        hero_layout.addWidget(eyebrow)

        title = QLabel("Analyze captures faster, with cleaner evidence and clearer actions")
        title.setObjectName("heading")
        title.setWordWrap(True)
        hero_layout.addWidget(title)

        tagline = QLabel(
            "The application turns Wi-Fi, transport, IPv6, protocol, and anomaly investigations into guided workflows with exportable HTML reports."
        )
        tagline.setObjectName("sectionCopy")
        tagline.setWordWrap(True)
        hero_layout.addWidget(tagline)

        chips_row = QHBoxLayout()
        chips_row.setSpacing(8)
        for chip_text in ["7 analysis paths", "Standalone desktop app", "HTML + JSON output", "CLI + GUI workflows"]:
            chip = QLabel(chip_text)
            chip.setObjectName("chip")
            chips_row.addWidget(chip)
        chips_row.addStretch()
        hero_layout.addLayout(chips_row)

        metrics = QGridLayout()
        metrics.setSpacing(10)
        for index, (label_text, value_text) in enumerate([
            ("Primary workflow", "Capture -> Run -> Report"),
            ("Best for", "Wi-Fi defects, RF health, protocol triage"),
            ("Requirements", "tshark installed locally"),
        ]):
            metric_card = QFrame()
            metric_card.setObjectName("metricStripCard")
            metric_layout = QVBoxLayout(metric_card)
            metric_layout.setContentsMargins(14, 14, 14, 14)
            metric_layout.setSpacing(4)
            metric_label = QLabel(label_text)
            metric_label.setObjectName("fieldHelp")
            metric_layout.addWidget(metric_label)
            metric_value = QLabel(value_text)
            metric_value.setStyleSheet("font-size: 13px; font-weight: 700; color: #f4f8ff; background: transparent;")
            metric_value.setWordWrap(True)
            metric_layout.addWidget(metric_value)
            metrics.addWidget(metric_card, 0, index)
        hero_layout.addLayout(metrics)
        layout.addWidget(hero)

        prep_title = QLabel("Before you run an analysis")
        prep_title.setObjectName("sectionTitle")
        layout.addWidget(prep_title)

        prep_grid = QGridLayout()
        prep_grid.setSpacing(10)
        prep_cards = [
            ("document-open", QStyle.StandardPixmap.SP_DialogOpenButton, "Load the right capture",
             "Use .pcap, .pcapng, or .cap files. Large mixed captures are easier to read when you scope them to one client, IP, or protocol."),
            ("preferences-system", QStyle.StandardPixmap.SP_FileDialogInfoView, "Choose the right panel",
             "WLAN and Channel are for wireless investigations, TCP/UDP is for stalled apps, IPv6 is for one-node diagnostics, and Protocol is for targeted security checks."),
            ("text-html", QStyle.StandardPixmap.SP_FileDialogContentsView, "Expect report output",
             "Each run produces structured JSON and an HTML report you can open directly or share with engineering and support teams."),
        ]
        for i, (theme_icon, fallback, card_title, card_desc) in enumerate(prep_cards):
            prep_grid.addWidget(_InfoCard(theme_icon, fallback, card_title, card_desc), 0, i)
        layout.addLayout(prep_grid)

        nav_title = QLabel("Launch an analysis")
        nav_title.setObjectName("sectionTitle")
        layout.addWidget(nav_title)

        grid = QGridLayout()
        grid.setSpacing(12)
        for col in range(3):
            grid.setColumnStretch(col, 1)

        cards = [
            ("network-wireless", QStyle.StandardPixmap.SP_DriveNetIcon, "WLAN / Wi-Fi Analysis", "Authentication, roaming, beacon loss, retry patterns, and wireless root cause.", "wlan"),
            ("document-decrypt", QStyle.StandardPixmap.SP_DialogApplyButton, "WPA Decryption", "Decrypt WPA/WPA2/WPA3 captures and inspect inner DNS, HTTP, IP, and port activity.", "decrypt"),
            ("view-grid", QStyle.StandardPixmap.SP_FileDialogDetailedView, "Channel & Network Map", "Survey RF utilization, client activity tiers, station spotlight, and combined channel dashboards.", "channel"),
            ("network-server", QStyle.StandardPixmap.SP_ComputerIcon, "TCP/UDP Diagnostics", "Find zero-window stalls, retransmissions, RST bursts, UDP floods, and QUIC-heavy sessions.", "tcp_udp"),
            ("network-workgroup", QStyle.StandardPixmap.SP_DirIcon, "IPv6 Analysis", "Focus on one IPv6 node to review TCP, UDP, ICMPv6, NDP, and SNMP behavior.", "ipv6"),
            ("security-high", QStyle.StandardPixmap.SP_MessageBoxWarning, "Protocol Analyzers", "Run targeted protocol checks for DNS tunneling, SYN floods, DHCP attacks, and other threats.", "protocol"),
            ("applications-science", QStyle.StandardPixmap.SP_CommandLink, "ML Anomaly Detection", "Score captures with Isolation Forest or Autoencoder models for unusual traffic behavior.", "anomaly"),
        ]

        for i, (theme_icon, fallback_icon, title_text, desc, key) in enumerate(cards):
            card = FeatureCard(title_text, desc, theme_icon, fallback_icon, key)
            card.clicked.connect(self._on_card_clicked)
            grid.addWidget(card, i // 3, i % 3)

        layout.addLayout(grid)

        benefits_title = QLabel("Why teams use this tool")
        benefits_title.setObjectName("sectionTitle")
        layout.addWidget(benefits_title)

        benefits_grid = QGridLayout()
        benefits_grid.setSpacing(10)
        benefit_cards = [
            ("preferences-desktop-remote-desktop", QStyle.StandardPixmap.SP_BrowserReload, "Reduce manual Wireshark time",
             "Move from raw packet inspection to guided evidence faster, especially for repeated regression or field-support cases."),
            ("dialog-information", QStyle.StandardPixmap.SP_MessageBoxInformation, "Make reports easier to share",
             "HTML reports surface findings, severity, and evidence in a format that support, QA, and engineering can all review."),
            ("folder-network", QStyle.StandardPixmap.SP_DriveHDIcon, "Handle broad capture sets",
             "Wireless, transport, protocol, and anomaly workflows live in one app instead of separate scripts and ad hoc notes."),
            ("preferences-system-network", QStyle.StandardPixmap.SP_FileDialogListView, "Keep scope under control",
             "Optional MAC, protocol, and IPv6 filters make large captures easier to read and prevent crowded output."),
        ]
        for i, (theme_icon, fallback, card_title, card_desc) in enumerate(benefit_cards):
            benefits_grid.addWidget(_InfoCard(theme_icon, fallback, card_title, card_desc), i // 2, i % 2)
        layout.addLayout(benefits_grid)

        cli_note = QLabel(
            "Need command examples and execution flow? Open the CLI & Workflow tab in the left navigation for full usage guidance."
        )
        cli_note.setWordWrap(True)
        cli_note.setObjectName("fieldHelp")
        layout.addWidget(cli_note)

        footer = QLabel(
            "Select an analysis from the sidebar or cards above. tshark must be installed locally. Reports are written to the results directory as HTML plus JSON output."
        )
        footer.setWordWrap(True)
        footer.setObjectName("fieldHelp")
        layout.addWidget(footer)

    def _on_card_clicked(self, nav_key: str):
        self.navigate_to.emit(nav_key)
