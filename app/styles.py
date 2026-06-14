"""Application stylesheet."""

DARK_STYLESHEET = """
QWidget {
    background-color: #0f1723;
    color: #e6edf7;
    font-family: "Inter", "IBM Plex Sans", "Noto Sans", "Segoe UI", "Ubuntu", sans-serif;
}

QMainWindow {
    background-color: #0f1723;
}

#sidebar {
    background-color: #111b2a;
    border-right: 1px solid #223247;
    min-width: 276px;
    max-width: 276px;
}

#sidebarTitle {
    color: #f6fbff;
    font-size: 18px;
    font-weight: 700;
    line-height: 1.2;
    padding: 20px 16px 6px 16px;
}

#sidebarSubtitle {
    color: #8ea4bf;
    font-size: 11px;
    line-height: 1.4;
    padding: 0 16px 2px 16px;
}

#sidebarMeta {
    color: #5fc7c8;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.4px;
    text-transform: uppercase;
    padding: 4px 16px 14px 16px;
}

#sidebarFooter {
    color: #6f839d;
    font-size: 10px;
    padding: 10px 12px 6px 12px;
}

#sidebar QPushButton {
    background-color: rgba(255, 255, 255, 0.02);
    color: #bfd0e5;
    border: 1px solid #1f3248;
    border-radius: 12px;
    padding: 11px 12px;
    text-align: left;
    font-size: 13px;
    font-weight: 600;
}

#sidebar QPushButton:hover {
    background-color: #18283b;
    border-color: #28415c;
    color: #eff7ff;
}

#sidebar QPushButton:checked {
    background-color: #17324a;
    border-color: #255174;
    color: #78d1d2;
}

#contentArea {
    background-color: #0f1723;
    padding: 0;
}

QFrame#heroCard,
QFrame#infoCard,
QFrame#featureCard,
QFrame#metricStripCard,
QFrame#stepCard,
QFrame#aiToolCard,
QFrame#cliCommandCard {
    background-color: #121d2c;
    border: 1px solid #223247;
    border-radius: 16px;
}

QFrame#heroCard {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #14273e, stop:0.5 #16314b, stop:1 #1a3c57);
    border: 1px solid #2f5f84;
}

QLabel {
    color: #e6edf7;
    font-size: 13px;
}

QLabel#heading { font-size: 30px; font-weight: 750; color: #f8fbff; }
QLabel#panelHeading { font-size: 28px; font-weight: 760; color: #ffffff; }
QLabel#panelSubheading { font-size: 15px; color: #c3dbef; }
QLabel#sectionTitle { color: #f8fbff; font-size: 20px; font-weight: 700; }
QLabel#sectionCopy, QLabel#fieldHelp { color: #c7d9ea; font-size: 13px; }
QLabel#heroAppName { font-size: 22px; font-weight: 760; color: #ffffff; }
QLabel#heroAppSub { font-size: 12px; color: #b9f0ed; font-weight: 600; }

QLabel#heroAppIcon {
    background-color: #0f4f82;
    border: 1px solid #5fb0e6;
    border-radius: 12px;
    padding: 0px;
}

QLabel#heroAppName,
QLabel#heroAppSub,
QLabel#sectionEyebrow,
QLabel#heading,
QLabel#sectionCopy,
QLabel#chip,
QLabel#fieldHelp {
    background-color: rgba(23, 82, 127, 0.70);
    border-radius: 6px;
    padding: 2px 6px;
}

QLabel#heading {
    padding: 4px 8px;
}

QLabel#chip {
    background-color: rgba(35, 104, 157, 0.90);
    border: 1px solid #5aa9db;
}

QLabel#commandBlock,
QLabel#cliCommandCode {
    background-color: rgba(189, 230, 255, 0.16);
    border: 1px solid rgba(146, 206, 255, 0.56);
    border-radius: 8px;
    color: #f1faff;
    font-family: "JetBrains Mono", "Fira Code", "Cascadia Mono", "DejaVu Sans Mono", monospace;
    font-size: 13px;
    line-height: 1.6;
    padding: 12px;
}

QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
    background-color: #0d1521;
    border: 1px solid #30465e;
    border-radius: 10px;
    padding: 10px 12px;
    color: #eef5ff;
    font-size: 13px;
}

QPushButton {
    background-color: #5fc7c8;
    color: #081018;
    border: 1px solid #5fc7c8;
    border-radius: 12px;
    padding: 10px 18px;
    font-weight: 700;
    font-size: 13px;
}

QPushButton:hover {
    background-color: #79d8d9;
    border-color: #79d8d9;
}

QPushButton#btnSuccess {
    background-color: #16324a;
    color: #eef7ff;
    border: 1px solid #2e5f84;
    border-radius: 10px;
    padding: 9px 16px;
    font-size: 13px;
    font-weight: 700;
}

QPushButton#btnSuccess:hover {
    background-color: #1c4464;
    border-color: #4d86b1;
}

QPushButton#btnSuccess:disabled {
    background-color: #132131;
    color: #8ea4bf;
    border-color: #25384c;
}

QScrollBar:vertical {
    background-color: #0f1723;
    width: 12px;
    margin: 0;
    border: none;
}

QScrollBar::handle:vertical {
    background-color: #244766;
    min-height: 28px;
    border-radius: 6px;
}

QScrollBar::handle:vertical:hover {
    background-color: #2f5f84;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical,
QScrollBar::add-page:vertical,
QScrollBar::sub-page:vertical {
    background: transparent;
    height: 0;
}

QStatusBar {
    background-color: #111b2a;
    border-top: 1px solid #223247;
    color: #9db1c7;
    font-size: 11px;
    padding: 4px 12px;
}
"""
