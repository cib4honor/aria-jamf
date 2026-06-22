#!/usr/bin/env python3
"""
ARIA v4.0 User Manual — PDF Generator
Generates ARIA_User_Manual_v7.pdf using ReportLab.
"""

import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable, ListFlowable, ListItem,
    Frame, PageTemplate, BaseDocTemplate, NextPageTemplate
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Line
from reportlab.graphics import renderPDF
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ── Colors ──────────────────────────────────────────────────────
DARK_BG       = colors.HexColor("#060d08")
GREEN_ACCENT  = colors.HexColor("#16a34a")
GREEN_DARK    = colors.HexColor("#0d7a36")
GREEN_LIGHT   = colors.HexColor("#d1fae5")
GREEN_MUTED   = colors.HexColor("#22c55e")
WHITE         = colors.white
BLACK         = colors.black
GRAY_LIGHT    = colors.HexColor("#f3f4f6")
GRAY_MED      = colors.HexColor("#9ca3af")
GRAY_DARK     = colors.HexColor("#374151")
GRAY_BORDER   = colors.HexColor("#e5e7eb")
TIP_BG        = colors.HexColor("#d1fae5")
TIP_BORDER    = colors.HexColor("#16a34a")
WARN_BG       = colors.HexColor("#fef3c7")
WARN_BORDER   = colors.HexColor("#f59e0b")
NOTE_BG       = colors.HexColor("#dbeafe")
NOTE_BORDER   = colors.HexColor("#3b82f6")
HIGH_RED      = colors.HexColor("#dc2626")
MED_AMBER     = colors.HexColor("#f59e0b")
LOW_BLUE      = colors.HexColor("#3b82f6")

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ARIA_User_Manual_v7.pdf")

# ── Styles ──────────────────────────────────────────────────────
styles = getSampleStyleSheet()

styles.add(ParagraphStyle(
    name="SectionTitle",
    fontName="Helvetica-Bold",
    fontSize=20,
    leading=26,
    textColor=GREEN_DARK,
    spaceBefore=12,
    spaceAfter=8,
))
styles.add(ParagraphStyle(
    name="SubSection",
    fontName="Helvetica-Bold",
    fontSize=14,
    leading=18,
    textColor=GRAY_DARK,
    spaceBefore=12,
    spaceAfter=6,
))
styles.add(ParagraphStyle(
    name="SubSubSection",
    fontName="Helvetica-Bold",
    fontSize=11,
    leading=14,
    textColor=GRAY_DARK,
    spaceBefore=8,
    spaceAfter=4,
))
styles.add(ParagraphStyle(
    name="Body",
    fontName="Helvetica",
    fontSize=10,
    leading=14,
    textColor=GRAY_DARK,
    alignment=TA_JUSTIFY,
    spaceBefore=2,
    spaceAfter=4,
))
styles.add(ParagraphStyle(
    name="BodyBold",
    fontName="Helvetica-Bold",
    fontSize=10,
    leading=14,
    textColor=GRAY_DARK,
    spaceBefore=2,
    spaceAfter=4,
))
styles.add(ParagraphStyle(
    name="TableHeader",
    fontName="Helvetica-Bold",
    fontSize=9,
    leading=12,
    textColor=WHITE,
    alignment=TA_CENTER,
))
styles.add(ParagraphStyle(
    name="TableCell",
    fontName="Helvetica",
    fontSize=9,
    leading=12,
    textColor=GRAY_DARK,
))
styles.add(ParagraphStyle(
    name="TableCellCenter",
    fontName="Helvetica",
    fontSize=9,
    leading=12,
    textColor=GRAY_DARK,
    alignment=TA_CENTER,
))
styles.add(ParagraphStyle(
    name="CalloutText",
    fontName="Helvetica",
    fontSize=9,
    leading=13,
    textColor=GRAY_DARK,
))
styles.add(ParagraphStyle(
    name="CalloutTitle",
    fontName="Helvetica-Bold",
    fontSize=9,
    leading=13,
    textColor=GRAY_DARK,
))
styles.add(ParagraphStyle(
    name="StepNumber",
    fontName="Helvetica-Bold",
    fontSize=10,
    leading=14,
    textColor=WHITE,
    alignment=TA_CENTER,
))
styles.add(ParagraphStyle(
    name="StepText",
    fontName="Helvetica",
    fontSize=10,
    leading=14,
    textColor=GRAY_DARK,
))
styles.add(ParagraphStyle(
    name="Footer",
    fontName="Helvetica",
    fontSize=7,
    leading=9,
    textColor=GRAY_MED,
))
styles.add(ParagraphStyle(
    name="TOCEntry",
    fontName="Helvetica",
    fontSize=11,
    leading=20,
    textColor=GRAY_DARK,
    leftIndent=20,
))
styles.add(ParagraphStyle(
    name="CodeBlock",
    fontName="Courier",
    fontSize=8,
    leading=11,
    textColor=GRAY_DARK,
    backColor=GRAY_LIGHT,
    borderPadding=6,
    spaceBefore=4,
    spaceAfter=4,
))

# ── Helper Functions ────────────────────────────────────────────

def make_callout(callout_type, text):
    """Create a colored callout box (tip, warn, note)."""
    config = {
        "tip":  {"bg": TIP_BG,  "border": TIP_BORDER,  "icon": "TIP",     "title_color": GREEN_DARK},
        "warn": {"bg": WARN_BG, "border": WARN_BORDER,  "icon": "WARNING", "title_color": colors.HexColor("#92400e")},
        "note": {"bg": NOTE_BG, "border": NOTE_BORDER,  "icon": "NOTE",    "title_color": colors.HexColor("#1e40af")},
    }
    c = config[callout_type]
    title_style = ParagraphStyle("cTitle", parent=styles["CalloutTitle"], textColor=c["title_color"])
    body_style  = ParagraphStyle("cBody", parent=styles["CalloutText"])
    data = [[Paragraph(f"<b>{c['icon']}</b>", title_style),
             Paragraph(text, body_style)]]
    t = Table(data, colWidths=[55, 415])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), c["bg"]),
        ("BOX",         (0,0), (-1,-1), 1.5, c["border"]),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING",(0,0), (-1,-1), 8),
        ("TOPPADDING",  (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
    ]))
    return KeepTogether([Spacer(1, 4), t, Spacer(1, 4)])


def make_steps(steps_list):
    """Create numbered step boxes with green circles."""
    elements = []
    for i, (title, desc) in enumerate(steps_list, 1):
        num_style = ParagraphStyle("sNum", parent=styles["StepNumber"])
        txt = f"<b>Step {i}: {title}</b><br/>{desc}"
        data = [[
            Paragraph(f"<b>{i}</b>", num_style),
            Paragraph(txt, styles["StepText"])
        ]]
        t = Table(data, colWidths=[36, 434])
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (0,0), GREEN_ACCENT),
            ("BACKGROUND",   (1,0), (1,0), GRAY_LIGHT),
            ("BOX",          (0,0), (-1,-1), 0.5, GRAY_BORDER),
            ("LEFTPADDING",  (0,0), (-1,-1), 8),
            ("RIGHTPADDING", (0,0), (-1,-1), 8),
            ("TOPPADDING",   (0,0), (-1,-1), 6),
            ("BOTTOMPADDING",(0,0), (-1,-1), 6),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("ROUNDEDCORNERS", [4,4,4,4]),
        ]))
        elements.append(Spacer(1, 3))
        elements.append(t)
    return elements


def make_table(headers, rows, col_widths=None):
    """Create a professional styled table."""
    header_paras = [Paragraph(h, styles["TableHeader"]) for h in headers]
    data = [header_paras]
    for row in rows:
        data.append([Paragraph(str(cell), styles["TableCell"]) for cell in row])
    if col_widths is None:
        col_widths = [470 / len(headers)] * len(headers)
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND",    (0,0), (-1,0), GREEN_DARK),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0), 9),
        ("BOTTOMPADDING", (0,0), (-1,0), 6),
        ("TOPPADDING",    (0,0), (-1,0), 6),
        ("GRID",          (0,0), (-1,-1), 0.5, GRAY_BORDER),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("RIGHTPADDING",  (0,0), (-1,-1), 6),
        ("TOPPADDING",    (0,1), (-1,-1), 4),
        ("BOTTOMPADDING", (0,1), (-1,-1), 4),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), GRAY_LIGHT))
    t.setStyle(TableStyle(style_cmds))
    return t


def section_title(number, title):
    return Paragraph(f"{number}. {title}", styles["SectionTitle"])

def subsection(title):
    return Paragraph(title, styles["SubSection"])

def subsubsection(title):
    return Paragraph(title, styles["SubSubSection"])

def body(text):
    return Paragraph(text, styles["Body"])

def body_bold(text):
    return Paragraph(text, styles["BodyBold"])

def bullet_list(items):
    elements = []
    for item in items:
        elements.append(Paragraph(f"&#8226;  {item}", ParagraphStyle(
            "bullet", parent=styles["Body"], leftIndent=20, firstLineIndent=-12
        )))
    return elements

def spacer(h=6):
    return Spacer(1, h)


# ── Page Templates ──────────────────────────────────────────────

def cover_page(canvas, doc):
    """Draw the dark cover page."""
    canvas.saveState()
    w, h = letter
    # Dark background
    canvas.setFillColor(DARK_BG)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)
    # Green accent bar at top
    canvas.setFillColor(GREEN_ACCENT)
    canvas.rect(0, h - 8, w, 8, fill=1, stroke=0)
    # Green accent bar at bottom
    canvas.rect(0, 0, w, 8, fill=1, stroke=0)
    # ARIA title
    canvas.setFillColor(GREEN_ACCENT)
    canvas.setFont("Helvetica-Bold", 96)
    canvas.drawCentredString(w/2, h - 240, "ARIA")
    # Subtitle
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica", 16)
    canvas.drawCentredString(w/2, h - 280, "Automated Resolution & Incident Assistant")
    # Version box
    canvas.setFillColor(GREEN_ACCENT)
    canvas.roundRect(w/2 - 60, h - 330, 120, 30, 4, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 14)
    canvas.drawCentredString(w/2, h - 322, "Version 4.0")
    # Description
    canvas.setFillColor(GRAY_MED)
    canvas.setFont("Helvetica", 12)
    canvas.drawCentredString(w/2, h - 380, "User Manual & Administration Guide")
    canvas.drawCentredString(w/2, h - 400, "AI-Powered Jamf Pro Troubleshooting Assistant")
    # Divider line
    canvas.setStrokeColor(GREEN_ACCENT)
    canvas.setLineWidth(0.5)
    canvas.line(w/2 - 100, h - 430, w/2 + 100, h - 430)
    # Organization
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 14)
    canvas.drawCentredString(w/2, h - 465, "Three Rivers School District")
    canvas.setFillColor(GRAY_MED)
    canvas.setFont("Helvetica", 11)
    canvas.drawCentredString(w/2, h - 485, "Technology Department  ·  Grants Pass, Oregon")
    # Date
    canvas.setFont("Helvetica", 10)
    canvas.drawCentredString(w/2, h - 520, datetime.now().strftime("Generated %B %d, %Y"))
    # Confidential
    canvas.setFillColor(colors.HexColor("#4b5563"))
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(w/2, 40, "CONFIDENTIAL — TRSD Internal Use Only")
    canvas.restoreState()


def header_footer(canvas, doc):
    """Draw header and footer on content pages."""
    canvas.saveState()
    w, h = letter
    # Header bar
    canvas.setFillColor(GREEN_DARK)
    canvas.rect(0, h - 36, w, 36, fill=1, stroke=0)
    # ARIA in header
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(50, h - 25, "ARIA")
    canvas.setFont("Helvetica", 8)
    canvas.drawString(82, h - 25, "v4.0 User Manual")
    # Page number in header
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(w - 50, h - 25, f"Page {doc.page}")
    # Footer line
    canvas.setStrokeColor(GRAY_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(50, 38, w - 50, 38)
    # Footer text
    canvas.setFillColor(GRAY_MED)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(50, 26, "CONFIDENTIAL — TRSD Internal Use Only")
    canvas.drawRightString(w - 50, 26, "Three Rivers School District — Technology Department")
    canvas.restoreState()


# ── Build Document ──────────────────────────────────────────────

def build_manual():
    doc = BaseDocTemplate(
        OUTPUT_PATH,
        pagesize=letter,
        leftMargin=55,
        rightMargin=55,
        topMargin=55,
        bottomMargin=55,
        title="ARIA v4.0 User Manual",
        author="Three Rivers School District — Technology Department",
    )

    content_frame = Frame(
        doc.leftMargin, doc.bottomMargin + 10,
        doc.width, doc.height - 30,
        id="content"
    )
    cover_frame = Frame(0, 0, letter[0], letter[1], id="cover")

    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[cover_frame], onPage=cover_page),
        PageTemplate(id="Content", frames=[content_frame], onPage=header_footer),
    ])

    story = []

    # ── Cover Page ──
    story.append(NextPageTemplate("Content"))
    story.append(PageBreak())

    # ── Table of Contents Page ──
    story.append(Spacer(1, 10))
    story.append(Paragraph("Table of Contents", ParagraphStyle(
        "TOCTitle", parent=styles["SectionTitle"], fontSize=24, textColor=GREEN_DARK
    )))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN_ACCENT))
    story.append(Spacer(1, 12))

    toc_entries = [
        ("1", "Introduction & Overview"),
        ("2", "Getting Started"),
        ("3", "Device Lookup"),
        ("4", "The Device Panel"),
        ("5", "Analyze"),
        ("6", "MDM Actions"),
        ("7", "Fleet Panel"),
        ("8", "Handoff Log"),
        ("9", "Email Compose"),
        ("10", "ConnectWise Remote"),
        ("11", "Escalate to Bob"),
        ("12", "Admin Panel"),
        ("13", "Session Summary"),
        ("14", "Troubleshooting"),
        ("15", "Quick Reference Card"),
    ]
    for num, title in toc_entries:
        story.append(Paragraph(
            f'<b>{num}.</b>  {title}',
            styles["TOCEntry"]
        ))
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY_BORDER))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Document version 7.0  ·  Generated {datetime.now().strftime('%B %d, %Y')}  ·  ARIA v4.0",
        ParagraphStyle("tocFootNote", parent=styles["Footer"], alignment=TA_CENTER, fontSize=8)
    ))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 1: Introduction & Overview
    # ════════════════════════════════════════════════════════════
    story.append(section_title("1", "Introduction & Overview"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "<b>ARIA</b> (Automated Resolution &amp; Incident Assistant) is a self-hosted, AI-powered "
        "troubleshooting tool built exclusively for <b>Three Rivers School District (TRSD)</b>. "
        "It provides Mac technicians with a conversational interface backed by live Jamf Pro data, "
        "fleet-wide health queries, MDM actions, and AI-generated diagnostic summaries — all running "
        "on TRSD's own hardware with district-managed API credentials."
    ))
    story.append(spacer())
    story.append(subsection("TRSD Fleet at a Glance"))
    story.append(make_table(
        ["Metric", "Value"],
        [
            ["Total Managed Macs", "~963"],
            ["Jamf Pro Sites", "25"],
            ["Active Technicians", "7"],
            ["ARIA Server", "Bob's Mac (HTTPS, port 5001)"],
            ["AI Engine", "Anthropic Claude (Haiku for Analyze, Sonnet for Chat)"],
        ],
        col_widths=[180, 290]
    ))
    story.append(spacer(8))
    story.append(subsection("Connected Systems"))
    story.append(body("ARIA integrates with five external systems to provide comprehensive device management:"))
    story.append(spacer(4))
    story.append(make_table(
        ["System", "Purpose", "Integration Method"],
        [
            ["Jamf Pro", "Device inventory, MDM commands, policy history, group membership", "REST API (Bearer token, OAuth client credentials)"],
            ["Jamf Protect", "Security alerts, threat status, compliance insights", "Jamf Pro API (Protect data exposed via Jamf Pro)"],
            ["Claude AI (Anthropic)", "AI chat, Analyze summaries, natural language troubleshooting", "Anthropic API (API key)"],
            ["Slack", "Escalation notifications to the ARIA admin (Bob)", "Incoming Webhook"],
            ["ConnectWise ScreenConnect", "Remote control sessions for hands-on troubleshooting", "Deep link URL (Host view)"],
        ],
        col_widths=[90, 180, 200]
    ))
    story.append(spacer(6))
    story.append(make_callout("note",
        "ARIA runs entirely on-premises. Your Jamf credentials, API keys, and fleet data never leave the district network. "
        "Only outbound API calls to Anthropic and Slack traverse the internet."
    ))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 2: Getting Started
    # ════════════════════════════════════════════════════════════
    story.append(section_title("2", "Getting Started"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))

    story.append(subsection("Accessing ARIA"))
    story.append(body(
        "ARIA is accessible from any device on the TRSD network. Open your browser and navigate to:"
    ))
    story.append(Paragraph(
        "<b>https://aria.local:5001</b>  or  <b>https://&lt;server-ip&gt;:5001</b>",
        ParagraphStyle("url", parent=styles["Body"], alignment=TA_CENTER, fontSize=12,
                       textColor=GREEN_DARK, spaceBefore=8, spaceAfter=8)
    ))
    story.append(make_callout("tip",
        "Bookmark the URL for quick access. ARIA works best in Chrome or Safari. "
        "The HTTPS certificate is self-signed — you may need to accept the browser warning on first visit."
    ))
    story.append(spacer(6))

    story.append(subsection("Logging In"))
    story.extend(make_steps([
        ("Open ARIA", "Navigate to the ARIA URL in your browser. You will see the login screen with the ARIA logo."),
        ("Enter Credentials", "Type your <b>username</b> (e.g., <font face='Courier'>scott</font>) and <b>password</b>. "
         "If this is your first login, use the temporary password provided by your admin."),
        ("Change Temp Password", "If you received a temporary password, ARIA will immediately prompt you to set a new one. "
         "Choose a strong password — this is stored as a bcrypt hash on the server."),
        ("Begin Working", "After authentication, you'll land on the main ARIA interface with the device lookup bar at the top."),
    ]))
    story.append(spacer(8))

    story.append(subsection("Session & Rate Limiting"))
    story.append(make_table(
        ["Setting", "Value", "Details"],
        [
            ["Session Length", "8 hours", "JWT-based. After expiry, you must log in again."],
            ["Rate Limit", "Per-endpoint", "Prevents accidental API flooding to Jamf Pro."],
            ["Concurrent Sessions", "Unlimited", "Multiple techs can be logged in simultaneously."],
        ],
        col_widths=[120, 100, 250]
    ))
    story.append(spacer(8))

    story.append(subsection("User Roles"))
    story.append(make_table(
        ["Role", "Capabilities"],
        [
            ["<b>tech</b>", "Device lookup, Analyze, MDM actions, Fleet panel, Handoff log, Email compose, "
             "ConnectWise remote, Escalate, Session summary, AI chat"],
            ["<b>admin</b>", "All tech capabilities <b>plus</b>: User management (add/remove/reset/role change), "
             "audit log viewing, system configuration"],
        ],
        col_widths=[80, 390]
    ))
    story.append(spacer(6))

    story.append(subsection("Current ARIA Users"))
    story.append(make_table(
        ["Username", "Role", "Status"],
        [
            ["bob", "admin", "Primary administrator"],
            ["scott", "tech", "Technician"],
            ["deanna", "tech", "Technician"],
            ["michal", "tech", "Technician"],
            ["danica", "tech", "Technician"],
            ["robert", "tech", "Technician"],
        ],
        col_widths=[120, 80, 270]
    ))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 3: Device Lookup
    # ════════════════════════════════════════════════════════════
    story.append(section_title("3", "Device Lookup"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "The device lookup bar is the primary entry point for troubleshooting. It sits at the top of the ARIA interface "
        "and supports three lookup methods:"
    ))
    story.append(spacer(6))
    story.append(make_table(
        ["Method", "Format", "Example", "Behavior"],
        [
            ["Serial Number", "Exact match", "<font face='Courier'>C02FV3XXMD6T</font>",
             "Loads exact device from Jamf Pro"],
            ["Username", "first.last format", "<font face='Courier'>john.smith</font>",
             "Searches Jamf for devices assigned to this user"],
            ["Wildcard", "Partial match with *", "<font face='Courier'>john.*</font> or <font face='Courier'>*smith</font>",
             "Returns all matching devices; select from results list"],
        ],
        col_widths=[90, 110, 130, 140]
    ))
    story.append(spacer(8))
    story.extend(make_steps([
        ("Enter Search Term", "Type a serial number, username (first.last), or wildcard pattern into the lookup bar."),
        ("Press Enter or Click Search", "ARIA queries the Jamf Pro API in real time to find matching devices."),
        ("Select Device (if multiple)", "If your search returns multiple results (common with wildcard or username), "
         "click the desired device from the results list."),
        ("View Device Panel", "The full device panel loads with all inventory data, status indicators, and action buttons."),
    ]))
    story.append(spacer(6))
    story.append(make_callout("tip",
        "For the fastest lookups, use the <b>exact serial number</b>. Username searches require an additional "
        "API call to resolve the user to their assigned device(s)."
    ))
    story.append(make_callout("warn",
        "Wildcard searches can return many results on a fleet of ~963 devices. Use the most specific pattern possible "
        "to avoid slow responses."
    ))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 4: The Device Panel
    # ════════════════════════════════════════════════════════════
    story.append(section_title("4", "The Device Panel"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "Once a device is loaded, the Device Panel displays a comprehensive overview of the machine's status. "
        "Fields are organized into logical groups with color-coded status indicators."
    ))
    story.append(spacer(6))

    story.append(subsection("Device Identity"))
    story.append(make_table(
        ["Field", "Description"],
        [
            ["Computer Name", "The name assigned in Jamf Pro"],
            ["Serial Number", "Apple hardware serial number"],
            ["Jamf Pro ID", "Internal Jamf record ID (clickable link to Jamf console)"],
            ["Assigned User", "The user assigned to this device in Jamf inventory"],
            ["Site", "The TRSD site/school this device belongs to"],
            ["Model", "Mac model identifier (e.g., MacBook Air M2)"],
            ["Processor / Architecture", "Intel or Apple Silicon, with specific chip info"],
            ["macOS Version", "Currently installed macOS version and build"],
            ["Last Check-In", "Last time this device communicated with Jamf Pro"],
            ["Last Inventory Update", "Last time a full inventory was submitted"],
        ],
        col_widths=[150, 320]
    ))
    story.append(spacer(8))

    story.append(subsection("Security & Compliance Status"))
    story.append(body("Each security field uses color-coded indicators:"))
    story.append(spacer(4))
    story.append(make_table(
        ["Field", "Green (OK)", "Red (Issue)"],
        [
            ["FileVault", "Enabled — disk is encrypted", "Disabled or not reported"],
            ["Bootstrap Token", "Escrowed to Jamf Pro", "Not escrowed (critical on Apple Silicon)"],
            ["SIP (System Integrity Protection)", "Enabled", "Disabled"],
            ["Gatekeeper", "Enabled", "Disabled"],
            ["Firewall", "Enabled", "Disabled"],
            ["SUPER Version", "5.x installed and current", "Missing, outdated, or not installed"],
            ["Jamf Connect Version", "3.14.0 or newer", "Missing or outdated"],
            ["Jamf Protect", "Installed, checking in, no alerts", "Offline, has alerts, or missing"],
        ],
        col_widths=[155, 155, 160]
    ))
    story.append(spacer(6))
    story.append(make_callout("warn",
        "<b>Bootstrap Token</b> must be escrowed on ALL Apple Silicon Macs. Without it, MDM commands like "
        "enabling FileVault or installing kernel extensions will fail silently."
    ))
    story.append(spacer(4))

    story.append(subsection("Action Buttons"))
    story.append(body(
        "The Device Panel includes quick-action buttons along the bottom. These are covered in detail in their "
        "respective sections:"
    ))
    story.extend(bullet_list([
        "<b>Analyze</b> — Run the full 27+ check diagnostic (Section 5)",
        "<b>Blank Push / Restart / Lock</b> — MDM commands (Section 6)",
        "<b>Handoff Log</b> — Shared notes for this device (Section 8)",
        "<b>Email</b> — Compose from templates (Section 9)",
        "<b>ConnectWise</b> — Remote session (Section 10)",
        "<b>Policy History</b> — View pass/fail policy log with pagination",
    ]))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 5: Analyze
    # ════════════════════════════════════════════════════════════
    story.append(section_title("5", "Analyze"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "The <b>Analyze</b> feature is ARIA's most powerful diagnostic tool. It runs <b>27+ automated checks</b> "
        "across <b>8 categories</b>, then sends the results to Claude AI (Haiku) for a prioritized summary with "
        "severity ratings and actionable recommendations."
    ))
    story.append(spacer(6))

    story.append(subsection("Analysis Categories"))
    story.append(make_table(
        ["Category", "Code", "What It Checks"],
        [
            ["Conflict Detection", "CONFLICT", "Duplicate or conflicting configuration profiles"],
            ["Policy Failures", "POLICY", "Failed policies, policies stopped by user, policies not running"],
            ["Pattern Analysis", "PATTERN", "Cluster failures — multiple policies failing in a pattern"],
            ["MDM Status", "MDM", "Pending MDM commands that haven't executed"],
            ["Security Posture", "SECURITY", "FileVault, SIP, Bootstrap Token, Gatekeeper, Firewall"],
            ["Jamf Protect", "PROTECT", "Protect alerts, offline status, Insights findings"],
            ["Correlation", "CORRELATION", "Cross-field correlations (see detail below)"],
            ["Intelligence", "INTELLIGENCE", "15 deep checks using advanced heuristics"],
        ],
        col_widths=[115, 85, 270]
    ))
    story.append(spacer(8))

    story.append(subsection("CORRELATION Checks"))
    story.append(body("These checks identify issues that only become visible when comparing multiple data points:"))
    story.append(spacer(4))
    story.append(make_table(
        ["Correlation", "What It Means"],
        [
            ["Apple Silicon + No Bootstrap Token", "MDM commands will fail on this machine — critical to fix"],
            ["FileVault Enabled + No Bootstrap Token", "FileVault key escrow may be incomplete"],
            ["Shared Device + Guest Account Enabled", "Security risk in shared-use environments (labs, carts)"],
            ["Protect Offline + Active Alerts", "Device has unresolved threats AND is not reporting to Protect"],
        ],
        col_widths=[200, 270]
    ))
    story.append(spacer(8))

    story.append(subsection("INTELLIGENCE Checks"))
    story.append(body(
        "The Intelligence category runs <b>15 deep checks</b> that go beyond simple field validation. These use "
        "heuristics to identify subtle issues that a manual review might miss — such as devices that check in "
        "but never run policies, machines with mismatched site assignments, or devices showing signs of "
        "incomplete enrollment."
    ))
    story.append(spacer(6))

    story.append(subsection("Severity Levels"))
    sev_data = [
        [Paragraph("<b>HIGH</b>", ParagraphStyle("sevH", parent=styles["TableCell"], textColor=HIGH_RED)),
         Paragraph("Requires immediate attention. Security risk or broken functionality.", styles["TableCell"])],
        [Paragraph("<b>MEDIUM</b>", ParagraphStyle("sevM", parent=styles["TableCell"], textColor=MED_AMBER)),
         Paragraph("Should be addressed soon. Compliance issue or degraded state.", styles["TableCell"])],
        [Paragraph("<b>LOW</b>", ParagraphStyle("sevL", parent=styles["TableCell"], textColor=LOW_BLUE)),
         Paragraph("Informational or minor. Review when convenient.", styles["TableCell"])],
    ]
    sev_header = [
        Paragraph("Severity", styles["TableHeader"]),
        Paragraph("Meaning", styles["TableHeader"]),
    ]
    sev_table = Table([sev_header] + sev_data, colWidths=[100, 370])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), GREEN_DARK),
        ("GRID",          (0,0), (-1,-1), 0.5, GRAY_BORDER),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(sev_table)
    story.append(spacer(8))

    story.append(subsection("AI Summary"))
    story.append(body(
        "After all checks complete, ARIA sends the raw findings to <b>Claude Haiku</b> for summarization. "
        "The AI produces a prioritized, plain-English summary that highlights the most critical issues first, "
        "explains why they matter, and suggests specific remediation steps with <b>Jamf Pro deep links</b> "
        "where applicable."
    ))
    story.append(spacer(6))

    story.append(subsection("Analyze Actions"))
    story.extend(bullet_list([
        "<b>Jamf Deep Links</b> — Click any finding to jump directly to the relevant record in Jamf Pro",
        "<b>Escalate to Bob</b> — Send the full analysis to Bob via Slack (see Section 11)",
        "<b>Copy Report</b> — Copy the full analysis text to your clipboard for pasting into tickets or email",
    ]))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 6: MDM Actions
    # ════════════════════════════════════════════════════════════
    story.append(section_title("6", "MDM Actions"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "ARIA can send MDM commands directly to a loaded device through the Jamf Pro API. All actions are "
        "audit-logged with the technician's username, timestamp, and target device."
    ))
    story.append(spacer(6))

    story.append(make_table(
        ["Action", "MDM Command", "Use Case", "Audit Code"],
        [
            ["Blank Push", "BlankPush (Flush MDM queue)", "Force the device to check in and process pending commands",
             "MDM_FLUSH"],
            ["Restart", "RestartDevice", "Remotely restart the device (e.g., after policy install)",
             "MDM_RESTART"],
            ["Device Lock", "DeviceLock (with PIN)", "Lock the device with a 6-digit PIN — for lost/stolen devices",
             "MDM_LOCK"],
        ],
        col_widths=[75, 120, 175, 100]
    ))
    story.append(spacer(8))

    story.append(subsection("How APNs Works"))
    story.append(body(
        "MDM commands use <b>Apple Push Notification service (APNs)</b> as the delivery mechanism. When ARIA "
        "sends a command via the Jamf Pro API:"
    ))
    story.extend(make_steps([
        ("Command Queued", "Jamf Pro queues the MDM command for the target device."),
        ("APNs Push", "Jamf sends a silent push notification via APNs to wake the device."),
        ("Device Checks In", "The device receives the push, contacts Jamf Pro, and retrieves the queued command."),
        ("Command Executes", "The device executes the command and reports the result back to Jamf."),
    ]))
    story.append(spacer(6))
    story.append(make_callout("warn",
        "<b>Device Lock</b> is irreversible without the PIN or Jamf Pro admin access. Always confirm the correct "
        "device before locking. The PIN is displayed once — record it before closing the dialog."
    ))
    story.append(make_callout("note",
        "If a device is offline, MDM commands will queue and execute when the device next connects to the internet "
        "and receives the APNs notification."
    ))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 7: Fleet Panel
    # ════════════════════════════════════════════════════════════
    story.append(section_title("7", "Fleet Panel"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "The Fleet Panel provides fleet-wide queries across all ~963 managed Macs. Results are cached for "
        "<b>30 minutes</b> to reduce API load on Jamf Pro."
    ))
    story.append(spacer(6))

    story.append(subsection("Available Queries"))
    story.append(make_table(
        ["#", "Query", "Description"],
        [
            ["1", "Stale (7 days)", "Devices not checking in for 7+ days"],
            ["2", "Stale (14 days)", "Devices not checking in for 14+ days"],
            ["3", "Stale (30 days)", "Devices not checking in for 30+ days"],
            ["4", "FileVault Off", "Devices with FileVault disabled"],
            ["5", "Unmanaged", "Devices in Jamf Pro but not MDM-managed"],
            ["6", "SUPER Non-Compliant", "Devices missing or running outdated SUPER"],
            ["7", "Jamf Connect (No Users)", "Devices with Jamf Connect installed but no users assigned"],
            ["8", "Protect Offline", "Devices not reporting to Jamf Protect"],
            ["9", "Protect Alerts", "Devices with active Jamf Protect alerts"],
            ["10", "By Site", "Filter devices by any of the 25 TRSD sites"],
            ["11", "All Devices", "Complete fleet inventory"],
        ],
        col_widths=[30, 140, 300]
    ))
    story.append(spacer(8))

    story.append(subsection("Site Filter"))
    story.append(body(
        "TRSD operates <b>25 Jamf Pro sites</b>, each representing a school or department. The Fleet Panel "
        "displays all sites as clickable filter buttons. Selecting a site narrows the query results to only "
        "devices in that site."
    ))
    story.append(spacer(4))
    story.append(make_callout("tip",
        "Fleet queries are cached for <b>30 minutes</b>. If you need fresh data (e.g., after a mass MDM push), "
        "wait for the cache to expire or reload the page."
    ))
    story.append(spacer(4))

    story.append(subsection("Click-to-Load"))
    story.append(body(
        "Every device in the fleet results list is clickable. Click any row to load that device into the "
        "Device Panel for detailed troubleshooting — no need to retype the serial number."
    ))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 8: Handoff Log
    # ════════════════════════════════════════════════════════════
    story.append(section_title("8", "Handoff Log"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "The Handoff Log is a <b>shared team notepad</b> attached to each device's serial number. "
        "Notes are stored server-side and visible to all technicians — they persist across sessions and never expire."
    ))
    story.append(spacer(6))

    story.append(subsection("Features"))
    story.extend(bullet_list([
        "<b>Add Note</b> — Type a note and click Add. Your username and timestamp are recorded automatically.",
        "<b>Edit Note</b> — Click the edit icon on any note to modify its content.",
        "<b>Delete Note</b> — Click the delete icon to remove a note. This is permanent.",
        "<b>Device-Linked</b> — Notes are keyed to the device serial number, so they follow the device regardless of which tech looks it up.",
        "<b>Team Visibility</b> — All technicians can see and contribute to the same log.",
    ]))
    story.append(spacer(6))
    story.append(make_callout("tip",
        "Use the Handoff Log to leave notes for the next tech who works on a device. Great for multi-day issues, "
        "loaner devices, or tracking ongoing problems."
    ))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 9: Email Compose
    # ════════════════════════════════════════════════════════════
    story.append(section_title("9", "Email Compose"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "ARIA includes an email composition feature with <b>4 pre-built templates</b> for common tech support "
        "communications. Clicking a template opens your default email client via a <font face='Courier'>mailto:</font> link."
    ))
    story.append(spacer(6))

    story.append(subsection("Available Templates"))
    story.append(make_table(
        ["Template", "Use Case"],
        [
            ["macOS Update", "Notify a user that their Mac needs a macOS update"],
            ["Restart Needed", "Ask a user to restart their Mac (e.g., pending policies)"],
            ["Printer Issue", "Follow up on a printer-related support request"],
            ["Device Pickup", "Notify a user that their device is ready for pickup"],
        ],
        col_widths=[150, 320]
    ))
    story.append(spacer(6))
    story.append(body(
        "Each template pre-fills the subject line and body text with relevant details. "
        "You can edit the content before sending in your email client."
    ))
    story.append(make_callout("note",
        "Email compose uses <font face='Courier'>mailto:</font> links — it opens your default mail app (Outlook, Apple Mail, etc.). "
        "ARIA does not send email directly."
    ))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 10: ConnectWise Remote
    # ════════════════════════════════════════════════════════════
    story.append(section_title("10", "ConnectWise Remote"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "The <b>ConnectWise</b> button generates a deep link to ConnectWise ScreenConnect using the device's "
        "<b>Jamf computer name</b>. Clicking the button opens the ScreenConnect Host view for that machine, "
        "allowing you to start a remote control session immediately."
    ))
    story.append(spacer(6))
    story.extend(make_steps([
        ("Load Device", "Look up the device using serial number or username."),
        ("Click ConnectWise", "Click the ConnectWise button in the Device Panel action bar."),
        ("Connect", "ScreenConnect opens to the Host view for that device. Start your remote session."),
    ]))
    story.append(spacer(6))
    story.append(make_callout("note",
        "The deep link uses the Jamf <b>computer name</b> to find the device in ScreenConnect. If the names "
        "don't match between Jamf and ConnectWise, the link may not resolve correctly."
    ))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 11: Escalate to Bob
    # ════════════════════════════════════════════════════════════
    story.append(section_title("11", "Escalate to Bob"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "The <b>Escalate to Bob</b> feature sends a notification to the ARIA administrator (Bob) via "
        "<b>Slack webhook</b>. It appears in the Analyze modal footer and is intended for issues that "
        "require admin intervention."
    ))
    story.append(spacer(6))

    story.extend(make_steps([
        ("Run Analyze", "First, run the Analyze diagnostic on the device to generate a full report."),
        ("Click Escalate to Bob", "In the Analyze results modal, click the 'Escalate to Bob' button at the bottom."),
        ("Confirm", "A confirmation dialog appears — review and confirm before sending. This prevents accidental escalations."),
        ("Notification Sent", "Bob receives a Slack message with the device serial, summary, and key findings."),
    ]))
    story.append(spacer(6))
    story.append(make_callout("warn",
        "Use escalation judiciously — it sends a real-time Slack notification. Reserve it for issues you cannot "
        "resolve independently: persistent MDM failures, security concerns, or admin-level changes needed."
    ))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 12: Admin Panel
    # ════════════════════════════════════════════════════════════
    story.append(section_title("12", "Admin Panel"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "The Admin Panel is accessible only to users with the <b>admin</b> role. It provides user management "
        "and access to the full audit log."
    ))
    story.append(spacer(6))

    story.append(subsection("User Management"))
    story.append(make_table(
        ["Action", "Description"],
        [
            ["Add User", "Create a new ARIA account with a temporary password and assigned role (tech or admin)"],
            ["Reset Password", "Generate a new temporary password for a user — they must change it on next login"],
            ["Change Role", "Promote a tech to admin or demote an admin to tech"],
            ["Remove User", "Permanently delete a user account from ARIA"],
        ],
        col_widths=[130, 340]
    ))
    story.append(spacer(6))

    story.append(subsection("Temporary Password Flow"))
    story.extend(make_steps([
        ("Admin Creates/Resets", "Admin adds a new user or resets an existing user's password. ARIA generates a temp password."),
        ("Admin Shares Password", "Admin communicates the temp password to the user (in person, secure message, etc.)."),
        ("User Logs In", "User logs in with the temp password. ARIA detects it's temporary."),
        ("User Sets New Password", "ARIA immediately prompts the user to choose a new permanent password."),
    ]))
    story.append(spacer(8))

    story.append(subsection("Audit Log"))
    story.append(body(
        "Every significant action in ARIA is recorded in the audit log with a timestamp, username, action code, "
        "and relevant details. The admin panel displays the audit log with search and filter capabilities."
    ))
    story.append(spacer(4))
    story.append(make_table(
        ["Action Code", "Description"],
        [
            ["LOGIN", "User logged in to ARIA"],
            ["LOGOUT", "User logged out"],
            ["MDM_FLUSH", "Blank Push sent to a device"],
            ["MDM_RESTART", "Restart command sent to a device"],
            ["MDM_LOCK", "Device Lock command sent"],
            ["PASSWORD_CHANGE", "User changed their own password"],
            ["PASSWORD_RESET", "Admin reset a user's password"],
            ["USER_ADDED", "New user account created"],
            ["USER_REMOVED", "User account deleted"],
            ["ROLE_CHANGE", "User role changed (tech ↔ admin)"],
            ["EMAIL_COMPOSED", "Email template opened for a device"],
        ],
        col_widths=[140, 330]
    ))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 13: Session Summary
    # ════════════════════════════════════════════════════════════
    story.append(section_title("13", "Session Summary"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "The <b>Session Summary</b> tracks all devices you've looked up during your current session. "
        "It provides a quick reference of your work history for the day."
    ))
    story.append(spacer(6))

    story.append(subsection("Features"))
    story.extend(bullet_list([
        "<b>Device List</b> — Shows all devices you've loaded, with serial number and computer name",
        "<b>Timestamp</b> — When each device was first looked up in this session",
        "<b>Quick Access</b> — Click any device to reload it into the Device Panel",
        "<b>Session Scope</b> — Clears on logout. Each new login starts a fresh session summary.",
    ]))
    story.append(spacer(6))
    story.append(make_callout("tip",
        "Use Session Summary at the end of your shift to review what you worked on, or to quickly "
        "jump back to a device you looked up earlier."
    ))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 14: Troubleshooting
    # ════════════════════════════════════════════════════════════
    story.append(section_title("14", "Troubleshooting"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))
    story.append(body(
        "Common issues and their solutions. If your problem isn't listed here, escalate to Bob."
    ))
    story.append(spacer(6))

    troubleshooting = [
        ("Can't access ARIA (connection refused)",
         "Verify the ARIA server is running on Bob's Mac. Check that you're using HTTPS (not HTTP) on port 5001. "
         "Ensure you're on the TRSD network."),
        ("Certificate warning in browser",
         "ARIA uses a self-signed certificate. Click 'Advanced' → 'Proceed' in Chrome, or add an exception in Safari. "
         "This is expected and safe on the internal network."),
        ("Login fails with correct password",
         "Your account may have been reset. Contact Bob for a new temporary password. Check that Caps Lock is off."),
        ("Device lookup returns no results",
         "Verify the serial number or username format. Serial numbers are case-insensitive. Usernames must be in "
         "first.last format. Check that the device exists in Jamf Pro."),
        ("Analyze shows stale data",
         "ARIA pulls live data from Jamf Pro on each lookup. If the device hasn't checked in recently, "
         "the data in Jamf may be outdated. Try sending a Blank Push first."),
        ("MDM command not executing",
         "The device must be online and reachable via APNs. Check the device's last check-in time. "
         "Verify the device is MDM-managed (not just enrolled). Commands queue until the device comes online."),
        ("Fleet panel loads slowly",
         "Fleet queries cover ~963 devices and may take 10-15 seconds on first load. Subsequent loads use "
         "the 30-minute cache. Be patient on first query."),
        ("AI chat not responding",
         "Check that the Anthropic API key is configured and has available credits. The AI features require "
         "an active internet connection for API calls."),
        ("Escalation not appearing in Slack",
         "Verify the Slack webhook URL is configured in the ARIA .env file. Check that the webhook hasn't been "
         "revoked in Slack admin settings."),
        ("Handoff notes not saving",
         "Check for disk space on the ARIA server. The handoff log is stored in a JSON file on the server. "
         "If the file is locked or corrupted, contact Bob."),
        ("ConnectWise link goes to wrong device",
         "The deep link uses the Jamf computer name. If the name in Jamf doesn't match ScreenConnect, "
         "update the computer name in Jamf Pro to match."),
        ("Session expires too quickly",
         "Sessions last 8 hours. If you're being logged out sooner, check your system clock — JWT validation "
         "is time-sensitive. Also ensure you're not clearing browser cookies."),
        ("Admin panel not visible",
         "Only users with the 'admin' role can see the Admin Panel. If you need admin access, contact Bob "
         "to change your role."),
    ]

    for i, (problem, solution) in enumerate(troubleshooting):
        prob_style = ParagraphStyle("prob", parent=styles["BodyBold"], textColor=HIGH_RED, fontSize=10)
        sol_style = ParagraphStyle("sol", parent=styles["Body"], leftIndent=10)
        data = [[
            Paragraph(f"<b>{i+1}.</b>", ParagraphStyle("tNum", parent=styles["BodyBold"], alignment=TA_CENTER)),
            Paragraph(f"<b>{problem}</b>", prob_style),
        ], [
            "",
            Paragraph(solution, sol_style),
        ]]
        t = Table(data, colWidths=[30, 440])
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), colors.HexColor("#fef2f2")),
            ("BACKGROUND",   (0,1), (-1,1), WHITE),
            ("BOX",          (0,0), (-1,-1), 0.5, GRAY_BORDER),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
            ("TOPPADDING",   (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0), (-1,-1), 4),
            ("VALIGN",       (0,0), (-1,-1), "TOP"),
            ("SPAN",         (0,0), (0,1)),
        ]))
        story.append(KeepTogether([t, Spacer(1, 3)]))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 15: Quick Reference Card
    # ════════════════════════════════════════════════════════════
    story.append(section_title("15", "Quick Reference Card"))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(8))

    # Lookup Formats
    story.append(subsection("Lookup Formats"))
    story.append(make_table(
        ["Input", "Format", "Example"],
        [
            ["Serial Number", "Exact alphanumeric", "C02FV3XXMD6T"],
            ["Username", "first.last", "john.smith"],
            ["Wildcard (prefix)", "text.*", "john.*"],
            ["Wildcard (suffix)", "*text", "*smith"],
        ],
        col_widths=[120, 160, 190]
    ))
    story.append(spacer(8))

    # Analyze Categories
    story.append(subsection("Analyze Categories"))
    story.append(make_table(
        ["Category", "Checks", "Severity Range"],
        [
            ["CONFLICT", "Duplicate profiles", "MEDIUM–HIGH"],
            ["POLICY", "Failures, stopped, not running", "LOW–HIGH"],
            ["PATTERN", "Cluster failures", "MEDIUM–HIGH"],
            ["MDM", "Pending commands", "LOW–MEDIUM"],
            ["SECURITY", "FV, SIP, BT, Gatekeeper, Firewall", "HIGH"],
            ["PROTECT", "Alerts, offline, Insights", "MEDIUM–HIGH"],
            ["CORRELATION", "Cross-field analysis (4 checks)", "HIGH"],
            ["INTELLIGENCE", "Deep heuristics (15 checks)", "LOW–HIGH"],
        ],
        col_widths=[110, 210, 150]
    ))
    story.append(spacer(8))

    # MDM Actions
    story.append(subsection("MDM Actions"))
    story.append(make_table(
        ["Button", "Command", "Audit Code", "Reversible?"],
        [
            ["Blank Push", "Flush MDM Queue", "MDM_FLUSH", "Yes (no impact)"],
            ["Restart", "Restart Device", "MDM_RESTART", "Yes (device reboots)"],
            ["Device Lock", "Lock with PIN", "MDM_LOCK", "No (requires PIN or Jamf admin)"],
        ],
        col_widths=[90, 120, 100, 160]
    ))
    story.append(spacer(8))

    # Fleet Queries
    story.append(subsection("Fleet Queries"))
    story.append(make_table(
        ["Query", "Filter"],
        [
            ["Stale 7d / 14d / 30d", "Devices not checking in"],
            ["FileVault Off", "Encryption disabled"],
            ["Unmanaged", "In Jamf but no MDM profile"],
            ["SUPER Non-Compliant", "Missing or outdated SUPER"],
            ["JC No Users", "Jamf Connect without assigned users"],
            ["Protect Offline / Alerts", "Protect status issues"],
            ["By Site", "25-site filter"],
            ["All Devices", "Full fleet (~963)"],
        ],
        col_widths=[170, 300]
    ))
    story.append(spacer(8))

    # Escalation Decision Tree
    story.append(subsection("Escalation Decision Tree"))
    decision_data = [
        ["Can you resolve it with MDM actions (Blank Push, Restart)?", "→ Do it yourself"],
        ["Is it a password or account issue?", "→ Reset in Admin Panel (if admin) or escalate"],
        ["Is it a security finding (FileVault, SIP, Bootstrap Token)?", "→ Attempt fix; escalate if persistent"],
        ["Is it a policy failure or conflict?", "→ Check Jamf Pro; escalate if systemic"],
        ["Is it affecting multiple devices?", "→ Escalate to Bob — may be fleet-wide"],
        ["Is it a Protect alert or threat?", "→ Escalate to Bob immediately"],
        ["Not sure?", "→ Escalate to Bob with the Analyze report"],
    ]
    story.append(make_table(
        ["Condition", "Action"],
        decision_data,
        col_widths=[310, 160]
    ))
    story.append(spacer(8))

    # TRSD Standards
    story.append(subsection("TRSD Standards"))
    standards_table = make_table(
        ["Standard", "Required Value", "Notes"],
        [
            ["Jamf Connect", "3.14.0+", "Must be installed and current on all managed Macs"],
            ["SUPER", "5.x", "Software Update agent — required for automated patching"],
            ["macOS (Apple Silicon)", "14.x+", "Sonoma or newer on M1/M2/M3 Macs"],
            ["macOS (Intel)", "13.x+", "Ventura or newer on Intel Macs"],
            ["FileVault", "Required (Enabled)", "Full-disk encryption — no exceptions"],
            ["Bootstrap Token", "Escrowed", "Must be escrowed on ALL Apple Silicon Macs"],
            ["SIP", "Enabled", "System Integrity Protection — never disable"],
            ["Gatekeeper", "Enabled", "App verification — never disable"],
            ["Firewall", "Enabled", "macOS firewall must be active"],
        ],
        col_widths=[130, 130, 210]
    )
    story.append(standards_table)
    story.append(spacer(12))

    # Final note
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN_ACCENT))
    story.append(spacer(6))
    story.append(Paragraph(
        "End of ARIA v4.0 User Manual  ·  Questions? Contact Bob  ·  CONFIDENTIAL — TRSD Internal Use Only",
        ParagraphStyle("endNote", parent=styles["Body"], alignment=TA_CENTER, textColor=GRAY_MED, fontSize=9)
    ))

    # ── Build PDF ──
    doc.build(story)
    print(f"PDF generated: {OUTPUT_PATH}")
    print(f"File size: {os.path.getsize(OUTPUT_PATH) / 1024:.0f} KB")


if __name__ == "__main__":
    build_manual()
