"""Main application window with sidebar navigation."""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel, QStackedWidget, QFrame, QStatusBar, QStyle
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon

from app.panels.home_panel import HomePanel
from app.panels.wlan_panel import WlanPanel
from app.panels.tcp_udp_panel import TcpUdpPanel
from app.panels.ipv6_panel import IPv6Panel
from app.panels.channel_panel import ChannelPanel
from app.panels.protocol_panel import ProtocolPanel
from app.panels.anomaly_panel import AnomalyPanel
from app.panels.decrypt_panel import DecryptPanel
from app.panels.cli_info_panel import CliInfoPanel
from app.panels.about_panel import AboutPanel
from app.resources import get_resource_path


class MainWindow(QMainWindow):
    """Main application window with sidebar navigation and stacked panels."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI-Wireshark Analyzer")
        self.setMinimumSize(1280, 780)
        self.resize(1480, 900)

        # Set window icon
        _icon_path = get_resource_path("installer", "app_icon_orig.png")
        if _icon_path.exists():
            self.setWindowIcon(QIcon(str(_icon_path)))

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ─── Sidebar ───
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(12, 0, 12, 12)
        sidebar_layout.setSpacing(8)

        # App title in sidebar
        title_label = QLabel("AI-Wireshark Analyzer")
        title_label.setObjectName("sidebarTitle")
        title_label.setWordWrap(True)
        sidebar_layout.addWidget(title_label)

        subtitle_label = QLabel("Desktop diagnostics for Wi-Fi, protocol, and traffic analysis")
        subtitle_label.setObjectName("sidebarSubtitle")
        subtitle_label.setWordWrap(True)
        sidebar_layout.addWidget(subtitle_label)

        meta_label = QLabel("Standalone app • HTML reports • tshark powered")
        meta_label.setObjectName("sidebarMeta")
        meta_label.setWordWrap(True)
        sidebar_layout.addWidget(meta_label)

        # Navigation buttons
        self._nav_buttons = {}
        nav_items = [
            ("home", "Home", "go-home", QStyle.StandardPixmap.SP_DirHomeIcon),
            ("wlan", "WLAN / Wi-Fi", "network-wireless", QStyle.StandardPixmap.SP_DriveNetIcon),
            ("decrypt", "WPA Decrypt", "document-decrypt", QStyle.StandardPixmap.SP_DialogApplyButton),
            ("channel", "Channel & Network Map", "view-grid", QStyle.StandardPixmap.SP_FileDialogDetailedView),
            ("tcp_udp", "TCP/UDP Diagnostics", "network-server", QStyle.StandardPixmap.SP_ComputerIcon),
            ("ipv6", "IPv6 Analysis", "network-workgroup", QStyle.StandardPixmap.SP_DirIcon),
            ("protocol", "Protocol Analyzers", "security-high", QStyle.StandardPixmap.SP_MessageBoxWarning),
            ("anomaly", "ML Anomaly", "applications-science", QStyle.StandardPixmap.SP_CommandLink),
            ("cli", "CLI & Workflow", "utilities-terminal", QStyle.StandardPixmap.SP_FileDialogListView),
            ("about", "About", "help-about", QStyle.StandardPixmap.SP_MessageBoxInformation),
        ]

        for key, label, theme_icon, fallback_icon in nav_items:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setAutoExclusive(True)
            btn.setIcon(QIcon.fromTheme(theme_icon, self.style().standardIcon(fallback_icon)))
            btn.setIconSize(QSize(18, 18))
            btn.clicked.connect(lambda checked, k=key: self._navigate(k))
            sidebar_layout.addWidget(btn)
            self._nav_buttons[key] = btn

        sidebar_layout.addStretch()

        # Version info at bottom of sidebar
        ver_label = QLabel("Python • PyQt6 • tshark")
        ver_label.setObjectName("sidebarFooter")
        sidebar_layout.addWidget(ver_label)

        main_layout.addWidget(sidebar)

        # ─── Content Stack ───
        self._stack = QStackedWidget()
        self._stack.setObjectName("contentArea")
        main_layout.addWidget(self._stack, 1)

        # Create panels
        self._panels = {}
        self._home = HomePanel()
        self._home.navigate_to.connect(self._navigate)
        self._stack.addWidget(self._home)
        self._panels["home"] = self._home

        panel_classes = {
            "wlan": WlanPanel,
            "decrypt": DecryptPanel,
            "tcp_udp": TcpUdpPanel,
            "ipv6": IPv6Panel,
            "channel": ChannelPanel,
            "protocol": ProtocolPanel,
            "anomaly": AnomalyPanel,
            "cli": CliInfoPanel,
            "about": AboutPanel,
        }

        for key, cls in panel_classes.items():
            panel = cls()
            self._stack.addWidget(panel)
            self._panels[key] = panel

        # Status bar
        status = QStatusBar()
        self.setStatusBar(status)
        status.showMessage("Ready — Select an analysis type to begin")

        # Default to home
        self._navigate("home")

    def _navigate(self, key: str):
        """Switch to the specified panel."""
        if key in self._panels:
            self._stack.setCurrentWidget(self._panels[key])
            if key in self._nav_buttons:
                self._nav_buttons[key].setChecked(True)
            self.statusBar().showMessage(f"Active: {self._panels[key].TITLE}" if hasattr(self._panels[key], 'TITLE') else "Home")
