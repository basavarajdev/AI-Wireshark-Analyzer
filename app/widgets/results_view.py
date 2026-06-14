"""Results viewer widget — native summary + embedded HTML report."""

import json
import tempfile
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QLabel,
    QTextBrowser, QPushButton, QGridLayout, QFrame, QScrollArea
)
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices

try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    HAS_WEBENGINE = True
except ImportError:
    HAS_WEBENGINE = False


class SeverityBadge(QLabel):
    """Colored severity badge label."""

    COLORS = {
        "critical": ("#f38ba8", "#1e1e2e"),
        "high": ("#fab387", "#1e1e2e"),
        "medium": ("#f9e2af", "#1e1e2e"),
        "low": ("#a6e3a1", "#1e1e2e"),
        "info": ("#89b4fa", "#1e1e2e"),
    }

    def __init__(self, severity: str, parent=None):
        super().__init__(severity.upper(), parent)
        bg, fg = self.COLORS.get(severity.lower(), ("#6c7086", "#cdd6f4"))
        self.setStyleSheet(
            f"background-color: {bg}; color: {fg}; border-radius: 4px; "
            f"padding: 3px 10px; font-weight: 700; font-size: 11px;"
        )
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)


class MetricCard(QFrame):
    """Small card displaying a metric label + value."""

    def __init__(self, label: str, value: str, color: str = "#cdd6f4", parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            "QFrame { background-color: #18283b; border: 1px solid #30465e; border-radius: 12px; padding: 14px; }"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(6)

        lbl = QLabel(label)
        lbl.setStyleSheet("color: #9eb2c8; font-size: 12px; font-weight: 600; background: transparent;")
        layout.addWidget(lbl)

        val = QLabel(str(value))
        val.setStyleSheet(f"color: {color}; font-size: 21px; font-weight: 800; background: transparent;")
        layout.addWidget(val)


class ResultsViewer(QWidget):
    """Combined results viewer with Summary and HTML Report tabs."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._html_path = None
        self._json_data = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header with actions
        header = QHBoxLayout()
        self._title = QLabel("Analysis Results")
        self._title.setObjectName("heading")
        header.addWidget(self._title)
        header.addStretch()

        self._btn_open_browser = QPushButton("Open in Browser")
        self._btn_open_browser.setObjectName("btnSecondary")
        self._btn_open_browser.clicked.connect(self._open_in_browser)
        self._btn_open_browser.setEnabled(False)
        header.addWidget(self._btn_open_browser)

        layout.addLayout(header)

        # Tab widget
        self._tabs = QTabWidget()
        layout.addWidget(self._tabs)

        # Tab 1: Native Summary
        self._summary_scroll = QScrollArea()
        self._summary_scroll.setWidgetResizable(True)
        self._summary_widget = QWidget()
        self._summary_layout = QVBoxLayout(self._summary_widget)
        self._summary_layout.setContentsMargins(10, 10, 10, 10)
        self._summary_layout.setSpacing(14)
        self._summary_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._summary_scroll.setWidget(self._summary_widget)
        self._tabs.addTab(self._summary_scroll, "Summary")

        # Tab 2: HTML Report
        if HAS_WEBENGINE:
            self._web_view = QWebEngineView()
            self._web_view.setUrl(QUrl("about:blank"))
            self._tabs.addTab(self._web_view, "HTML Report")
        else:
            placeholder = QLabel("HTML Report viewer requires PyQt6-WebEngine.\nUse 'Open in Browser' button instead.")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._tabs.addTab(placeholder, "HTML Report")

        # Tab 3: Raw JSON
        self._json_view = QTextBrowser()
        self._tabs.addTab(self._json_view, "Raw Data")

    def clear(self):
        """Clear all results."""
        self._html_path = None
        self._json_data = None
        self._btn_open_browser.setEnabled(False)
        self._json_view.clear()
        # Clear summary cards
        while self._summary_layout.count():
            item = self._summary_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if HAS_WEBENGINE:
            self._web_view.setUrl(QUrl("about:blank"))

    def show_results(self, json_data: dict = None, html_path: str = None, title: str = "Analysis Results"):
        """Display analysis results."""
        self.clear()
        self._title.setText(title)
        self._json_data = json_data
        self._html_path = html_path

        # Show HTML report
        if html_path and Path(html_path).exists():
            self._btn_open_browser.setEnabled(True)
            if HAS_WEBENGINE:
                self._web_view.setUrl(QUrl.fromLocalFile(str(Path(html_path).resolve())))

        # Show JSON
        if json_data:
            formatted = json.dumps(json_data, indent=2, default=str)
            self._json_view.setPlainText(formatted)
            self._build_summary(json_data)

        # Switch to summary tab
        self._tabs.setCurrentIndex(0)

    def _build_summary(self, data: dict):
        """Build native summary cards from analysis JSON."""
        # Extract common keys
        total_packets = data.get("total_packets", data.get("frame_count", "N/A"))
        duration = data.get("duration_s", data.get("capture_duration_s", "N/A"))
        threats = data.get("threats", {})
        critical_issues = data.get("critical_issues", [])

        # Overall metrics grid
        metrics_grid = QGridLayout()
        metrics_grid.setSpacing(12)

        cards = []
        if total_packets != "N/A":
            cards.append(MetricCard("Total Packets", f"{total_packets:,}" if isinstance(total_packets, int) else str(total_packets)))
        if duration != "N/A":
            dur_str = f"{float(duration):.1f}s" if duration else "N/A"
            cards.append(MetricCard("Duration", dur_str))

        # Count threats by severity
        threat_count = 0
        critical_count = 0
        high_count = 0

        if isinstance(threats, dict):
            for name, info in threats.items():
                if isinstance(info, dict) and info.get("detected"):
                    threat_count += 1
                    sev = info.get("severity", "").lower()
                    if sev == "critical":
                        critical_count += 1
                    elif sev == "high":
                        high_count += 1
        elif isinstance(threats, list):
            threat_count = len(threats)

        if isinstance(critical_issues, list) and critical_issues:
            critical_count = max(critical_count, len(critical_issues))

        if threat_count > 0:
            color = "#f38ba8" if critical_count > 0 else "#fab387" if high_count > 0 else "#f9e2af"
            cards.append(MetricCard("Threats Detected", str(threat_count), color))
        else:
            cards.append(MetricCard("Threats Detected", "0", "#a6e3a1"))

        if critical_count > 0:
            cards.append(MetricCard("Critical Issues", str(critical_count), "#f38ba8"))

        # Additional protocol-specific metrics
        for key in ["tcp_count", "udp_count", "rst_total", "zero_window",
                    "retransmissions_print", "data_sent_mb"]:
            if key in data and data[key]:
                label = key.replace("_", " ").title()
                val = data[key]
                if isinstance(val, float):
                    val = f"{val:.2f}"
                cards.append(MetricCard(label, str(val)))

        # WLAN specific
        for key in ["connection_failures", "sae_failures", "beacon_losses",
                    "wpa3_issues", "retry_rate"]:
            if key in data and data[key]:
                label = key.replace("_", " ").title()
                cards.append(MetricCard(label, str(data[key])))

        # Layout cards in grid (3 columns)
        for i, card in enumerate(cards[:12]):
            metrics_grid.addWidget(card, i // 3, i % 3)

        metrics_container = QWidget()
        metrics_container.setLayout(metrics_grid)
        self._summary_layout.addWidget(metrics_container)

        # Critical issues section
        if critical_issues:
            issues_label = QLabel("Critical Issues:")
            issues_label.setStyleSheet("color: #ec6a7a; font-size: 16px; font-weight: 700; margin-top: 18px;")
            self._summary_layout.addWidget(issues_label)

            for issue in critical_issues[:20]:
                issue_text = issue if isinstance(issue, str) else str(issue)
                issue_lbl = QLabel(f"  • {issue_text}")
                issue_lbl.setStyleSheet("color: #ffd8df; font-size: 13px; padding: 3px 0;")
                issue_lbl.setWordWrap(True)
                self._summary_layout.addWidget(issue_lbl)

        # Threats detail
        if isinstance(threats, dict):
            detected = {k: v for k, v in threats.items() if isinstance(v, dict) and v.get("detected")}
            if detected:
                threats_label = QLabel("Detected Threats:")
                threats_label.setStyleSheet("color: #ff9b5d; font-size: 16px; font-weight: 700; margin-top: 18px;")
                self._summary_layout.addWidget(threats_label)

                for name, info in list(detected.items())[:15]:
                    severity = info.get("severity", "info")
                    row = QHBoxLayout()
                    badge = SeverityBadge(severity)
                    row.addWidget(badge)
                    threat_lbl = QLabel(name.replace("_", " ").title())
                    threat_lbl.setStyleSheet("font-size: 13px; padding-left: 8px;")
                    row.addWidget(threat_lbl)
                    row.addStretch()
                    row_widget = QWidget()
                    row_widget.setLayout(row)
                    self._summary_layout.addWidget(row_widget)

        self._summary_layout.addStretch()

    def _open_in_browser(self):
        """Open the HTML report in the default browser."""
        if self._html_path and Path(self._html_path).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(self._html_path).resolve())))
