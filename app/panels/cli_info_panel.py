"""Command-line usage, app flow, and AI tools reference panel."""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGridLayout,
    QFrame, QScrollArea, QStyle
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon


class _StepCard(QFrame):
    """Vertical step card for app workflow."""

    def __init__(self, step_num: str, title: str, description: str, parent=None):
        super().__init__(parent)
        self.setObjectName("stepCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(6)

        step_lbl = QLabel(step_num)
        step_lbl.setObjectName("stepNumber")
        layout.addWidget(step_lbl)

        title_lbl = QLabel(title)
        title_lbl.setObjectName("stepTitle")
        layout.addWidget(title_lbl)

        desc_lbl = QLabel(description)
        desc_lbl.setWordWrap(True)
        desc_lbl.setObjectName("stepDesc")
        layout.addWidget(desc_lbl)


class _AIToolCard(QFrame):
    """Card for AI/ML tools used."""

    def __init__(self, icon_char: str, tool_name: str, description: str, parent=None):
        super().__init__(parent)
        self.setObjectName("aiToolCard")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        icon_lbl = QLabel(icon_char)
        icon_lbl.setObjectName("aiToolIcon")
        icon_lbl.setFixedWidth(40)
        layout.addWidget(icon_lbl, alignment=Qt.AlignmentFlag.AlignTop)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(3)

        name_lbl = QLabel(tool_name)
        name_lbl.setObjectName("aiToolName")
        text_layout.addWidget(name_lbl)

        desc_lbl = QLabel(description)
        desc_lbl.setWordWrap(True)
        desc_lbl.setObjectName("aiToolDesc")
        text_layout.addWidget(desc_lbl)

        layout.addLayout(text_layout, 1)


class CliInfoPanel(QWidget):
    """Panel showing CLI usage, app workflow, and AI tools information."""

    TITLE = "CLI & Workflow"

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
        layout.setSpacing(24)
        scroll.setWidget(container)

        # ─── Header ───────────────────────────────────────────────────────
        title = QLabel("CLI Usage & Workflow")
        title.setObjectName("panelHeading")
        layout.addWidget(title)

        subtitle = QLabel("Launch from command line, integrate into CI/CD pipelines, or script batch analyses")
        subtitle.setObjectName("panelSubheading")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        # ─── App Workflow ──────────────────────────────────────────────────
        flow_title = QLabel("Application Flow")
        flow_title.setObjectName("sectionTitle")
        layout.addWidget(flow_title)

        workflow_grid = QGridLayout()
        workflow_grid.setSpacing(12)

        steps = [
            ("1️⃣", "Load Capture", "Select a .pcap or .pcapng file\ncaptured from Wireshark or tcpdump"),
            ("2️⃣", "Choose Analysis", "Pick a panel: WLAN, Channel Monitor,\nTCP/UDP, IPv6, Protocol, or Anomaly"),
            ("3️⃣", "Set Parameters", "Add optional filters (MAC, IP, protocol)\nand configure analysis options"),
            ("4️⃣", "Run Analysis", "Click Run to process the capture\nwith tshark and AI models"),
            ("5️⃣", "View Report", "Open interactive HTML report\nin browser with findings & recommendations"),
            ("6️⃣", "Export & Share", "JSON + HTML files saved to results/\nready for sharing and archival"),
        ]

        for i, (icon, title_text, desc) in enumerate(steps):
            step_card = _StepCard(icon, title_text, desc)
            workflow_grid.addWidget(step_card, i // 3, i % 3)

        layout.addLayout(workflow_grid)

        # ─── Command Line Usage ────────────────────────────────────────────
        cli_title = QLabel("Command Line Usage")
        cli_title.setObjectName("sectionTitle")
        layout.addWidget(cli_title)

        cli_intro = QLabel(
            "All analysis scripts support CLI mode for automation, CI/CD integration, and batch processing. "
            "Each script accepts input/output paths and optional parameters."
        )
        cli_intro.setWordWrap(True)
        cli_intro.setObjectName("sectionCopy")
        layout.addWidget(cli_intro)

        # GUI Launch
        gui_frame = QFrame()
        gui_frame.setObjectName("cliCommandCard")
        gui_layout = QVBoxLayout(gui_frame)
        gui_layout.setContentsMargins(16, 16, 16, 16)
        gui_layout.setSpacing(8)

        gui_label = QLabel("Launch Desktop GUI")
        gui_label.setObjectName("cliCommandLabel")
        gui_layout.addWidget(gui_label)

        gui_cmd = QLabel("python -m app.main")
        gui_cmd.setObjectName("cliCommandCode")
        gui_cmd.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        gui_layout.addWidget(gui_cmd)

        layout.addWidget(gui_frame)

        # WLAN Analysis
        wlan_frame = QFrame()
        wlan_frame.setObjectName("cliCommandCard")
        wlan_layout = QVBoxLayout(wlan_frame)
        wlan_layout.setContentsMargins(16, 16, 16, 16)
        wlan_layout.setSpacing(8)

        wlan_label = QLabel("WLAN / Wi-Fi Analysis")
        wlan_label.setObjectName("cliCommandLabel")
        wlan_layout.addWidget(wlan_label)

        wlan_cmds = [
            "# Basic analysis",
            "python scripts/run_wlan_analysis.py capture.pcapng",
            "",
            "# With MAC filter",
            "python scripts/run_wlan_analysis.py capture.pcapng 00:11:22:33:44:55 results/",
        ]
        wlan_cmd = QLabel("\n".join(wlan_cmds))
        wlan_cmd.setObjectName("cliCommandCode")
        wlan_cmd.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        wlan_layout.addWidget(wlan_cmd)

        layout.addWidget(wlan_frame)

        # Channel Monitor
        channel_frame = QFrame()
        channel_frame.setObjectName("cliCommandCard")
        channel_layout = QVBoxLayout(channel_frame)
        channel_layout.setContentsMargins(16, 16, 16, 16)
        channel_layout.setSpacing(8)

        channel_label = QLabel("Channel Monitor & Survey")
        channel_label.setObjectName("cliCommandLabel")
        channel_layout.addWidget(channel_label)

        channel_cmds = [
            "# Survey all channels",
            "python scripts/run_channel_monitor.py --pcap capture.pcapng --out results/survey",
            "",
            "# Specific channel and duration",
            "python scripts/run_channel_monitor.py --pcap capture.pcapng --channel 6 --duration 120 --out results/",
        ]
        channel_cmd = QLabel("\n".join(channel_cmds))
        channel_cmd.setObjectName("cliCommandCode")
        channel_cmd.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        channel_layout.addWidget(channel_cmd)

        layout.addWidget(channel_frame)

        # TCP/UDP Analysis
        tcp_frame = QFrame()
        tcp_frame.setObjectName("cliCommandCard")
        tcp_layout = QVBoxLayout(tcp_frame)
        tcp_layout.setContentsMargins(16, 16, 16, 16)
        tcp_layout.setSpacing(8)

        tcp_label = QLabel("TCP/UDP Diagnostics")
        tcp_label.setObjectName("cliCommandLabel")
        tcp_layout.addWidget(tcp_label)

        tcp_cmds = [
            "# Generate report in results/",
            "python scripts/analyze_tcp_udp.py capture.pcapng",
            "",
            "# Custom output path",
            "python scripts/analyze_tcp_udp.py capture.pcapng results/my_tcp_analysis_report.html",
        ]
        tcp_cmd = QLabel("\n".join(tcp_cmds))
        tcp_cmd.setObjectName("cliCommandCode")
        tcp_cmd.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        tcp_layout.addWidget(tcp_cmd)

        layout.addWidget(tcp_frame)

        # IPv6 Analysis
        ipv6_frame = QFrame()
        ipv6_frame.setObjectName("cliCommandCard")
        ipv6_layout = QVBoxLayout(ipv6_frame)
        ipv6_layout.setContentsMargins(16, 16, 16, 16)
        ipv6_layout.setSpacing(8)

        ipv6_label = QLabel("IPv6 Address Analysis")
        ipv6_label.setObjectName("cliCommandLabel")
        ipv6_layout.addWidget(ipv6_label)

        ipv6_cmds = [
            "# Analyze specific IPv6 address",
            "python scripts/run_ipv6_analysis.py capture.pcapng 2408:8a04:e001:0:faed:fcff:fefe:10c1",
            "",
            "# Custom output directory",
            "python scripts/run_ipv6_analysis.py capture.pcapng fe80::1 results/ipv6/",
        ]
        ipv6_cmd = QLabel("\n".join(ipv6_cmds))
        ipv6_cmd.setObjectName("cliCommandCode")
        ipv6_cmd.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        ipv6_layout.addWidget(ipv6_cmd)

        layout.addWidget(ipv6_frame)

        # ─── AI Tools ──────────────────────────────────────────────────────
        ai_title = QLabel("AI & ML Technologies")
        ai_title.setObjectName("sectionTitle")
        layout.addWidget(ai_title)

        ai_intro = QLabel(
            "This application combines rule-based packet analysis with machine learning models to identify patterns, anomalies, and potential issues that traditional filtering alone might miss."
        )
        ai_intro.setWordWrap(True)
        ai_intro.setObjectName("sectionCopy")
        layout.addWidget(ai_intro)

        ai_grid = QGridLayout()
        ai_grid.setSpacing(12)

        ai_tools = [
            ("🔍", "tshark / Wireshark",
             "Low-level packet parsing engine. Extracts frame-by-frame details: MAC, IP, TCP sequence numbers, flags, payload inspection."),
            ("🤖", "Isolation Forest",
             "Unsupervised ML algorithm that detects anomalous traffic patterns by identifying outliers in statistical distributions."),
            ("🧠", "Autoencoder Neural Network",
             "Deep learning model trained on normal network behavior. Flags captures with unusual patterns based on reconstruction error."),
            ("📊", "Statistical Analysis",
             "Calculates retry rates, zero-window stalls, retransmission thresholds, and protocol deviation metrics."),
            ("🎯", "Rule Engine",
             "Curated logic for known Wi-Fi, IPv6, and security issues: WPA failures, deauth storms, DNS tunneling, port scanning."),
            ("📈", "Report Generation",
             "PyQt6 + Jinja2 templates produce interactive HTML with clickable findings, evidence links, and remediation guidance."),
        ]

        for i, (icon, tool_name, description) in enumerate(ai_tools):
            ai_card = _AIToolCard(icon, tool_name, description)
            ai_grid.addWidget(ai_card, i // 2, i % 2)

        layout.addLayout(ai_grid)

        # ─── Footer ────────────────────────────────────────────────────────
        footer = QLabel(
            "For more details, see docs/architecture.md. All analysis scripts support --help flag for parameter documentation."
        )
        footer.setWordWrap(True)
        footer.setObjectName("fieldHelp")
        layout.addWidget(footer)
