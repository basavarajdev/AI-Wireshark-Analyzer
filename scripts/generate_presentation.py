#!/usr/bin/env python3
"""Generate a management presentation for AI-Wireshark-Analyzer."""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
import os

# ── Colour palette ──────────────────────────────────────────────────────────
DARK_BG      = RGBColor(0x1B, 0x1F, 0x3B)   # deep navy
ACCENT_BLUE  = RGBColor(0x00, 0x9E, 0xF7)   # bright blue
ACCENT_GREEN = RGBColor(0x00, 0xC9, 0x83)   # green
ACCENT_ORANGE= RGBColor(0xFF, 0x8C, 0x00)   # orange
WHITE        = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT_GRAY   = RGBColor(0xBB, 0xBB, 0xCC)
CARD_BG      = RGBColor(0x24, 0x29, 0x4E)   # slightly lighter navy

prs = Presentation()
prs.slide_width  = Inches(13.333)
prs.slide_height = Inches(7.5)

SLIDE_W = prs.slide_width
SLIDE_H = prs.slide_height


# ── Helper functions ────────────────────────────────────────────────────────

def set_slide_bg(slide, color):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color


def add_shape(slide, left, top, width, height, fill_color=None, line_color=None, line_width=None):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color or CARD_BG
    if line_color:
        shape.line.color.rgb = line_color
        shape.line.width = line_width or Pt(1)
    else:
        shape.line.fill.background()
    # Smaller corner rounding
    shape.adjustments[0] = 0.05
    return shape


def add_text(slide, left, top, width, height, text, font_size=14, bold=False,
             color=WHITE, alignment=PP_ALIGN.LEFT, font_name='Calibri'):
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.bold = bold
    p.font.color.rgb = color
    p.font.name = font_name
    p.alignment = alignment
    return txBox


def add_rich_text(slide, left, top, width, height, lines, default_size=13):
    """lines: list of (text, size, bold, color) tuples."""
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    for i, (text, size, bold, color) in enumerate(lines):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = text
        p.font.size = Pt(size or default_size)
        p.font.bold = bold
        p.font.color.rgb = color or WHITE
        p.font.name = 'Calibri'
        p.space_after = Pt(4)
    return txBox


def add_icon_card(slide, left, top, width, height, icon_text, title, bullets, accent_color):
    """Card with coloured icon circle + title + bullets."""
    card = add_shape(slide, left, top, width, height, fill_color=CARD_BG, line_color=accent_color, line_width=Pt(1.5))

    # Icon circle
    circle = slide.shapes.add_shape(MSO_SHAPE.OVAL, left + Inches(0.25), top + Inches(0.22), Inches(0.5), Inches(0.5))
    circle.fill.solid()
    circle.fill.fore_color.rgb = accent_color
    circle.line.fill.background()
    tf = circle.text_frame
    tf.word_wrap = False
    p = tf.paragraphs[0]
    p.text = icon_text
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = WHITE
    p.alignment = PP_ALIGN.CENTER

    # Title
    add_text(slide, left + Inches(0.9), top + Inches(0.18), width - Inches(1.1), Inches(0.45),
             title, font_size=16, bold=True, color=accent_color)

    # Bullets
    txBox = slide.shapes.add_textbox(left + Inches(0.3), top + Inches(0.72), width - Inches(0.5), height - Inches(0.85))
    tf = txBox.text_frame
    tf.word_wrap = True
    for i, bullet in enumerate(bullets):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = f"▸ {bullet}"
        p.font.size = Pt(12)
        p.font.color.rgb = LIGHT_GRAY
        p.font.name = 'Calibri'
        p.space_after = Pt(3)


def add_stat_box(slide, left, top, width, height, number, label, accent):
    box = add_shape(slide, left, top, width, height, fill_color=CARD_BG, line_color=accent, line_width=Pt(2))
    add_text(slide, left, top + Inches(0.1), width, Inches(0.55),
             number, font_size=28, bold=True, color=accent, alignment=PP_ALIGN.CENTER)
    add_text(slide, left, top + Inches(0.6), width, Inches(0.4),
             label, font_size=11, color=LIGHT_GRAY, alignment=PP_ALIGN.CENTER)


# ═════════════════════════════════════════════════════════════════════════════
# SLIDE 1 — Title & Value Proposition
# ═════════════════════════════════════════════════════════════════════════════
slide1 = prs.slides.add_slide(prs.slide_layouts[6])  # blank
set_slide_bg(slide1, DARK_BG)

# Accent bar at top
bar = slide1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, Inches(0.06))
bar.fill.solid(); bar.fill.fore_color.rgb = ACCENT_BLUE; bar.line.fill.background()

# Title
add_text(slide1, Inches(0.8), Inches(0.8), Inches(11), Inches(0.8),
         "AI-Wireshark-Analyzer", font_size=40, bold=True, color=WHITE)

# Subtitle
add_text(slide1, Inches(0.8), Inches(1.55), Inches(11), Inches(0.5),
         "Automated Network Traffic Analysis & Security Threat Detection",
         font_size=20, color=ACCENT_BLUE)

# Divider line
div = slide1.shapes.add_shape(MSO_SHAPE.RECTANGLE,
    Inches(0.8), Inches(2.2), Inches(3), Inches(0.04))
div.fill.solid(); div.fill.fore_color.rgb = ACCENT_GREEN; div.line.fill.background()

# Value proposition
add_rich_text(slide1, Inches(0.8), Inches(2.5), Inches(5.5), Inches(2.5), [
    ("What It Does", 18, True, ACCENT_GREEN),
    ("Analyses Wireshark packet captures (PCAP/PCAPNG) using rule-based", 14, False, LIGHT_GRAY),
    ("protocol inspection and Machine Learning to detect network threats,", 14, False, LIGHT_GRAY),
    ("diagnose connectivity issues, and generate actionable reports.", 14, False, LIGHT_GRAY),
    ("", 8, False, WHITE),
    ("Why It Matters", 18, True, ACCENT_GREEN),
    ("Turns hours of manual Wireshark analysis into automated,", 14, False, LIGHT_GRAY),
    ("repeatable diagnostics with one command — no Wireshark", 14, False, LIGHT_GRAY),
    ("expertise needed by the end user.", 14, False, LIGHT_GRAY),
])

# Right side — key stats
add_stat_box(slide1, Inches(7.5), Inches(2.5), Inches(2.4), Inches(1.0), "8", "Protocol Analyzers", ACCENT_BLUE)
add_stat_box(slide1, Inches(10.2), Inches(2.5), Inches(2.4), Inches(1.0), "3", "ML/DL Models", ACCENT_GREEN)
add_stat_box(slide1, Inches(7.5), Inches(3.8), Inches(2.4), Inches(1.0), "50+", "Threat Signatures", ACCENT_ORANGE)
add_stat_box(slide1, Inches(10.2), Inches(3.8), Inches(2.4), Inches(1.0), "32", "WLAN Fields Extracted", ACCENT_BLUE)

# Bottom — tech stack ribbon
ribbon = add_shape(slide1, Inches(0.5), Inches(5.6), Inches(12.3), Inches(0.55), fill_color=CARD_BG)
add_text(slide1, Inches(0.7), Inches(5.63), Inches(12), Inches(0.5),
         "Python  •  tshark  •  PyShark  •  scikit-learn  •  TensorFlow  •  FastAPI  •  Click/Rich  •  Matplotlib",
         font_size=13, color=LIGHT_GRAY, alignment=PP_ALIGN.CENTER)

# Footer
add_text(slide1, Inches(0.8), Inches(6.8), Inches(5), Inches(0.4),
         "v1.2.0  |  May 2026", font_size=11, color=RGBColor(0x66, 0x66, 0x88))

# ═════════════════════════════════════════════════════════════════════════════
# SLIDE 2 — Capabilities & Coverage
# ═════════════════════════════════════════════════════════════════════════════
slide2 = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide2, DARK_BG)

bar2 = slide2.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, Inches(0.06))
bar2.fill.solid(); bar2.fill.fore_color.rgb = ACCENT_BLUE; bar2.line.fill.background()

add_text(slide2, Inches(0.6), Inches(0.3), Inches(10), Inches(0.6),
         "What We Analyse", font_size=30, bold=True, color=WHITE)
add_text(slide2, Inches(0.6), Inches(0.85), Inches(10), Inches(0.35),
         "Comprehensive protocol coverage from Layer 2 (Wi-Fi) to Layer 7 (HTTP/DNS)",
         font_size=14, color=LIGHT_GRAY)

# Row 1 — 3 cards
card_w = Inches(3.85)
card_h = Inches(2.65)
gap = Inches(0.35)
x_start = Inches(0.55)
y1 = Inches(1.5)

add_icon_card(slide2, x_start, y1, card_w, card_h, "📡", "Wi-Fi / WLAN (802.11)", [
    "WPA2 & WPA3/SAE auth failure diagnosis",
    "Per-client connection flow reconstruction",
    "Beacon loss, probe failures, weak signal",
    "Invalid password detection (EAPOL stall)",
    "40+ IEEE reason/status codes decoded",
], ACCENT_BLUE)

add_icon_card(slide2, x_start + card_w + gap, y1, card_w, card_h, "🔒", "Network Security", [
    "SYN flood, RST storm, port scan detection",
    "DNS tunneling & DGA domain detection",
    "SQL injection & XSS in HTTP traffic",
    "ICMP flood, Smurf, Ping of Death",
    "DHCP starvation & rogue server",
], ACCENT_ORANGE)

add_icon_card(slide2, x_start + 2*(card_w + gap), y1, card_w, card_h, "⚙️", "Application Diagnostics", [
    "TCP zero-window stalls & retransmissions",
    "RST event catalogue with burst detection",
    "UDP flow analysis, QUIC detection",
    "IPv6 per-address traffic deep-dive",
    "Print job failure diagnosis (port 9100)",
], ACCENT_GREEN)

# Row 2 — ML + Output strip
y2 = Inches(4.5)
ml_w = Inches(5.8)
out_w = Inches(6.2)

add_icon_card(slide2, x_start, y2, ml_w, Inches(2.3), "🧠", "Machine Learning & AI", [
    "Isolation Forest — unsupervised anomaly detection (no labels needed)",
    "Autoencoder (TensorFlow) — deep-learning anomaly scoring",
    "Random Forest — supervised attack classification",
    "50+ engineered features: IP, port, protocol, statistical, DNS, HTTP",
], ACCENT_BLUE)

add_icon_card(slide2, x_start + ml_w + gap, y2, out_w, Inches(2.3), "📊", "Output & Reporting", [
    "Self-contained HTML reports with charts & severity badges",
    "JSON results for programmatic consumption / dashboards",
    "REST API (FastAPI) — upload PCAP, get results",
    "CLI with Rich formatting — single-command analysis",
], ACCENT_GREEN)


# ═════════════════════════════════════════════════════════════════════════════
# SLIDE 3 — How to Use It (Workflows)
# ═════════════════════════════════════════════════════════════════════════════
slide3 = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide3, DARK_BG)

bar3 = slide3.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, Inches(0.06))
bar3.fill.solid(); bar3.fill.fore_color.rgb = ACCENT_BLUE; bar3.line.fill.background()

add_text(slide3, Inches(0.6), Inches(0.3), Inches(10), Inches(0.6),
         "How Teams Use It", font_size=30, bold=True, color=WHITE)
add_text(slide3, Inches(0.6), Inches(0.85), Inches(10), Inches(0.35),
         "One command, full analysis — no Wireshark expertise required",
         font_size=14, color=LIGHT_GRAY)

# Workflow cards (horizontal)
wf_y = Inches(1.5)
wf_h = Inches(2.2)
wf_w = Inches(3.85)

# Card 1 — Wi-Fi Troubleshooting
add_shape(slide3, Inches(0.55), wf_y, wf_w, wf_h, fill_color=CARD_BG, line_color=ACCENT_BLUE, line_width=Pt(1.5))
add_text(slide3, Inches(0.75), wf_y + Inches(0.15), wf_w, Inches(0.35),
         "🔍  Wi-Fi Troubleshooting", font_size=16, bold=True, color=ACCENT_BLUE)
add_rich_text(slide3, Inches(0.75), wf_y + Inches(0.55), wf_w - Inches(0.4), Inches(1.5), [
    ("Command:", 11, True, LIGHT_GRAY),
    ("python3 scripts/run_wlan_analysis.py", 12, False, ACCENT_GREEN),
    ("  capture.pcapng  c8:5a:cf:66:2e:1e", 12, False, ACCENT_GREEN),
    ("", 6, False, WHITE),
    ("→ Diagnoses auth failures, weak signal,", 12, False, LIGHT_GRAY),
    ("   EAPOL stalls, generates HTML report", 12, False, LIGHT_GRAY),
])

# Card 2 — Security Audit
x2 = Inches(0.55) + wf_w + Inches(0.35)
add_shape(slide3, x2, wf_y, wf_w, wf_h, fill_color=CARD_BG, line_color=ACCENT_ORANGE, line_width=Pt(1.5))
add_text(slide3, x2 + Inches(0.2), wf_y + Inches(0.15), wf_w, Inches(0.35),
         "🛡️  Security Threat Scan", font_size=16, bold=True, color=ACCENT_ORANGE)
add_rich_text(slide3, x2 + Inches(0.2), wf_y + Inches(0.55), wf_w - Inches(0.4), Inches(1.5), [
    ("Command:", 11, True, LIGHT_GRAY),
    ("python3 src/api/cli.py analyze", 12, False, ACCENT_GREEN),
    ("  -i traffic.pcap -p all", 12, False, ACCENT_GREEN),
    ("", 6, False, WHITE),
    ("→ Scans all protocols: TCP, UDP, DNS,", 12, False, LIGHT_GRAY),
    ("   HTTP, ICMP — reports all threats found", 12, False, LIGHT_GRAY),
])

# Card 3 — IPv6 / App Diagnostics
x3 = x2 + wf_w + Inches(0.35)
add_shape(slide3, x3, wf_y, wf_w, wf_h, fill_color=CARD_BG, line_color=ACCENT_GREEN, line_width=Pt(1.5))
add_text(slide3, x3 + Inches(0.2), wf_y + Inches(0.15), wf_w, Inches(0.35),
         "📈  App / IPv6 Diagnostics", font_size=16, bold=True, color=ACCENT_GREEN)
add_rich_text(slide3, x3 + Inches(0.2), wf_y + Inches(0.55), wf_w - Inches(0.4), Inches(1.5), [
    ("Command:", 11, True, LIGHT_GRAY),
    ("python3 scripts/run_ipv6_analysis.py", 12, False, ACCENT_GREEN),
    ("  capture.pcapng  <ipv6_address>", 12, False, ACCENT_GREEN),
    ("", 6, False, WHITE),
    ("→ TCP retransmissions, zero-window,", 12, False, LIGHT_GRAY),
    ("   RST events, UDP flows, SNMP analysis", 12, False, LIGHT_GRAY),
])

# Bottom section — real results showcase
y_results = Inches(4.1)
add_text(slide3, Inches(0.6), y_results, Inches(10), Inches(0.5),
         "Real Analyses Completed", font_size=20, bold=True, color=WHITE)

# Results table as cards
results_data = [
    ("Invalid Password (LEBI)", "WLAN", "Detected EAPOL Msg1 stall → client deauth", "c8:5a:cf:66:2e:1e", ACCENT_ORANGE),
    ("WPA3/SAE Mixed-Mode", "WLAN", "SAE Commit/Confirm + fallback diagnosis", "f8:ed:fc:fe:00:e9", ACCENT_BLUE),
    ("PMF Invalid Password (MARS)", "WLAN", "PMF-protected auth failure root-cause", "02:ba:d0:01:23:45", ACCENT_ORANGE),
    ("IPv6 Device Analysis", "IPv6", "TCP/UDP/ICMPv6/SNMP full breakdown", "2408:8a04:...", ACCENT_GREEN),
    ("Print Job Stalls", "TCP/UDP", "Zero-window stalls + RST burst timeline", "—", ACCENT_BLUE),
]

tbl_y = y_results + Inches(0.5)
# Header
hdr_bg = add_shape(slide3, Inches(0.55), tbl_y, Inches(12.2), Inches(0.35), fill_color=RGBColor(0x30, 0x35, 0x5A))
add_text(slide3, Inches(0.7), tbl_y + Inches(0.03), Inches(3.2), Inches(0.3),
         "Scenario", font_size=11, bold=True, color=ACCENT_BLUE)
add_text(slide3, Inches(3.9), tbl_y + Inches(0.03), Inches(0.8), Inches(0.3),
         "Type", font_size=11, bold=True, color=ACCENT_BLUE)
add_text(slide3, Inches(5.0), tbl_y + Inches(0.03), Inches(4.5), Inches(0.3),
         "Finding", font_size=11, bold=True, color=ACCENT_BLUE)
add_text(slide3, Inches(10.0), tbl_y + Inches(0.03), Inches(2.5), Inches(0.3),
         "Filter", font_size=11, bold=True, color=ACCENT_BLUE)

for i, (scenario, typ, finding, filt, accent) in enumerate(results_data):
    row_y = tbl_y + Inches(0.38) + Inches(i * 0.33)
    bg_color = CARD_BG if i % 2 == 0 else RGBColor(0x20, 0x25, 0x48)
    add_shape(slide3, Inches(0.55), row_y, Inches(12.2), Inches(0.32), fill_color=bg_color)
    add_text(slide3, Inches(0.7), row_y + Inches(0.02), Inches(3.2), Inches(0.28),
             scenario, font_size=11, color=WHITE)
    add_text(slide3, Inches(3.9), row_y + Inches(0.02), Inches(0.8), Inches(0.28),
             typ, font_size=10, bold=True, color=accent)
    add_text(slide3, Inches(5.0), row_y + Inches(0.02), Inches(4.8), Inches(0.28),
             finding, font_size=11, color=LIGHT_GRAY)
    add_text(slide3, Inches(10.0), row_y + Inches(0.02), Inches(2.5), Inches(0.28),
             filt, font_size=10, color=RGBColor(0x88, 0x99, 0xBB))


# ═════════════════════════════════════════════════════════════════════════════
# SLIDE 4 — Impact & Next Steps
# ═════════════════════════════════════════════════════════════════════════════
slide4 = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide4, DARK_BG)

bar4 = slide4.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, Inches(0.06))
bar4.fill.solid(); bar4.fill.fore_color.rgb = ACCENT_BLUE; bar4.line.fill.background()

add_text(slide4, Inches(0.6), Inches(0.3), Inches(10), Inches(0.6),
         "Impact & Road Ahead", font_size=30, bold=True, color=WHITE)

# Left column — Effectiveness
left_x = Inches(0.55)
eff_y = Inches(1.2)

add_text(slide4, left_x, eff_y, Inches(6), Inches(0.45),
         "Proven Effectiveness", font_size=20, bold=True, color=ACCENT_GREEN)

benefits = [
    ("⏱️  Hours → Seconds", "Full WLAN connection diagnosis in <10 seconds vs hours of manual Wireshark inspection"),
    ("🎯  Root-Cause Precision", "Pinpoints exact failure step — e.g., 'EAPOL Msg1 received, client deauth'd (wrong password)'"),
    ("📋  Actionable Reports", "Self-contained HTML reports with severity badges and remediation — shareable with non-experts"),
    ("🔄  Repeatable & Consistent", "Same analysis every time — eliminates human variability in packet interpretation"),
    ("🔌  Zero External Dependencies", "Runs locally with just Python + tshark — no cloud, no subscriptions, no data leaving the network"),
]

for i, (title, desc) in enumerate(benefits):
    by = eff_y + Inches(0.55) + Inches(i * 0.75)
    add_shape(slide4, left_x, by, Inches(6.2), Inches(0.68), fill_color=CARD_BG)
    add_text(slide4, left_x + Inches(0.15), by + Inches(0.05), Inches(5.9), Inches(0.28),
             title, font_size=14, bold=True, color=WHITE)
    add_text(slide4, left_x + Inches(0.15), by + Inches(0.33), Inches(5.9), Inches(0.32),
             desc, font_size=11, color=LIGHT_GRAY)

# Right column — Roadmap
right_x = Inches(7.2)

add_text(slide4, right_x, eff_y, Inches(5.5), Inches(0.45),
         "What's Next", font_size=20, bold=True, color=ACCENT_BLUE)

roadmap_items = [
    ("Live Capture Mode", "Real-time monitoring with tshark pipe — alert on threats as they happen"),
    ("AI-Powered Summary", "LLM-generated plain-English diagnosis — 'Your Wi-Fi fails because...'"),
    ("Dashboard Integration", "Feed JSON results into Grafana / ELK for team-wide visibility"),
    ("Expanded Protocols", "Bluetooth, Zigbee, industrial (Modbus/DNP3) protocol support"),
]

for i, (title, desc) in enumerate(roadmap_items):
    ry = eff_y + Inches(0.55) + Inches(i * 0.85)
    # Timeline dot
    dot = slide4.shapes.add_shape(MSO_SHAPE.OVAL,
        right_x, ry + Inches(0.08), Inches(0.18), Inches(0.18))
    dot.fill.solid(); dot.fill.fore_color.rgb = ACCENT_BLUE; dot.line.fill.background()
    # Vertical connector line
    if i < len(roadmap_items) - 1:
        line = slide4.shapes.add_shape(MSO_SHAPE.RECTANGLE,
            right_x + Inches(0.075), ry + Inches(0.28), Inches(0.03), Inches(0.6))
        line.fill.solid(); line.fill.fore_color.rgb = RGBColor(0x44, 0x4C, 0x70)
        line.line.fill.background()
    add_text(slide4, right_x + Inches(0.35), ry + Inches(0.02), Inches(5), Inches(0.28),
             title, font_size=14, bold=True, color=WHITE)
    add_text(slide4, right_x + Inches(0.35), ry + Inches(0.32), Inches(5), Inches(0.45),
             desc, font_size=11, color=LIGHT_GRAY)

# Bottom tagline
add_text(slide4, Inches(0.5), Inches(6.7), Inches(12.3), Inches(0.5),
         "AI-Wireshark-Analyzer  —  Automated  •  Actionable  •  Accurate",
         font_size=18, bold=True, color=ACCENT_BLUE, alignment=PP_ALIGN.CENTER)


# ── Save ────────────────────────────────────────────────────────────────────
out_path = os.path.join(os.path.dirname(__file__), '..', 'results', 'AI_Wireshark_Analyzer_Presentation.pptx')
out_path = os.path.abspath(out_path)
prs.save(out_path)
print(f"Presentation saved: {out_path}")
