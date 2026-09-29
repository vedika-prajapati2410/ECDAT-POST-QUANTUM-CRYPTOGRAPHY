"""
PDF Report Generator
=======================
The second half of "produce a report ... in standardised formats":
CycloneDX JSON is the machine-readable format, this is the
human-readable one -- an actual PDF a CISO can read without needing
the frontend, print, or attach to a compliance filing.

Uses reportlab (pure Python, no external binary dependencies like
wkhtmltopdf, so it works in constrained CI/offline environments).
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

RISK_COLORS = {
    "Critical": colors.HexColor("#B00020"),
    "High": colors.HexColor("#E67E22"),
    "Medium": colors.HexColor("#F1C40F"),
    "Low": colors.HexColor("#3498DB"),
    "Safe": colors.HexColor("#27AE60"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ECDATTitle", fontSize=20, leading=24, spaceAfter=6, textColor=colors.HexColor("#1A237E")))
    styles.add(ParagraphStyle(name="ECDATSubtitle", fontSize=11, textColor=colors.grey, spaceAfter=16))
    styles.add(ParagraphStyle(name="SectionHeading", fontSize=14, spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#1A237E")))
    styles.add(ParagraphStyle(name="Disclaimer", fontSize=8, textColor=colors.grey))
    styles.add(ParagraphStyle(name="CellWrap", fontSize=8, leading=9.5, wordWrap="CJK"))
    return styles


def _wrap(text, style):
    """
    Wrap a table cell's text in a Paragraph so long, hyphen-heavy
    strings (artefact names, file paths, algorithm names) break onto
    multiple lines instead of overflowing into the neighbouring
    column. Plain strings in a reportlab Table only wrap on spaces,
    which artefact names/paths often don't have.
    """
    return Paragraph(str(text), style)


def build_pdf_report(report: dict, output_path: str):
    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    styles = _styles()
    story = []

    # --- Cover ---
    story.append(Paragraph("Enterprise Cryptographic Discovery & Analysis Tool", styles["ECDATTitle"]))
    story.append(Paragraph(f"Scan Report -- ID {report['scan_id']} -- generated {report['created_at']}", styles["ECDATSubtitle"]))

    agility = report["agility_score"]
    summary_rows = [
        ["Metric", "Value"],
        ["Total artefacts scanned", str(report["artefact_count"])],
        ["Crypto-Agility Score", f"{agility['score']} / 100 (Grade {agility['grade']}, {agility.get('maturity_level_name', '')})"],
        ["CRQC planning horizon (Z, years)", str(report["years_to_crqc_assumption"])],
        ["Critical-risk artefacts", str(report["risk_tier_counts"].get("Critical", 0))],
        ["High-risk artefacts", str(report["risk_tier_counts"].get("High", 0))],
        ["Harvest-now-decrypt-later exposure", f"{report['harvest_now_decrypt_later']['total_exposed_gb']} GB"],
    ]
    t = Table(summary_rows, colWidths=[9*cm, 7*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A237E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(
        "Assumption disclosure: the CRQC planning horizon (Z) above is a configurable planning "
        "assumption, not a verified prediction -- see README for its basis. Regulatory framework "
        "flags in this report are automated triage suggestions, not legal determinations.",
        styles["Disclaimer"]
    ))

    # --- Cryptographic Asset Inventory ---
    story.append(PageBreak())
    story.append(Paragraph("1. Cryptographic Asset Inventory", styles["SectionHeading"]))
    class_by_id = {c["artefact_id"]: c for c in report["classifications"]}
    risk_by_id = {r["artefact_id"]: r for r in report["risks"]}

    inv_rows = [["Name", "Algorithm", "Type", "Occurrences", "Risk Tier", "Confidence"]]
    for a in report["cbom"]:
        risk = risk_by_id[a["id"]]
        inv_rows.append([
            _wrap(a["name"], styles["CellWrap"]), _wrap(a["algorithm"], styles["CellWrap"]), a["type"],
            str(a.get("occurrence_count", 1)), risk["risk_tier"], a.get("confidence", "high"),
        ])
    inv_table = Table(inv_rows, colWidths=[4.2*cm, 3.2*cm, 2.3*cm, 2*cm, 2.3*cm, 2*cm], repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A237E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]
    for i, a in enumerate(report["cbom"], start=1):
        tier = risk_by_id[a["id"]]["risk_tier"]
        style_cmds.append(("TEXTCOLOR", (4, i), (4, i), RISK_COLORS.get(tier, colors.black)))
    inv_table.setStyle(TableStyle(style_cmds))
    story.append(inv_table)

    # --- Risk & Recommendations ---
    story.append(PageBreak())
    story.append(Paragraph("2. Risk Assessment & Recommendations", styles["SectionHeading"]))
    rec_by_id = {r["artefact_id"]: r for r in report["recommendations"]}
    rec_rows = [["Name", "Current", "Recommended Replacement", "Priority"]]
    for a in report["cbom"]:
        rec = rec_by_id[a["id"]]
        rec_rows.append([
            _wrap(a["name"], styles["CellWrap"]),
            _wrap(rec["current_algorithm"], styles["CellWrap"]),
            _wrap(rec["recommended_algorithm"], styles["CellWrap"]),
            rec["priority"],
        ])
    rec_table = Table(rec_rows, colWidths=[3.5*cm, 2.8*cm, 6.7*cm, 2*cm], repeatRows=1)
    rec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A237E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(rec_table)

    # --- Migration Roadmap ---
    story.append(PageBreak())
    story.append(Paragraph("3. Phased Migration Roadmap", styles["SectionHeading"]))
    for phase in report["migration_roadmap"]:
        story.append(Paragraph(f"<b>{phase['phase']}</b> -- {phase['artefact_count']} artefact(s)", styles["Normal"]))
        for item in phase["items"][:15]:
            story.append(Paragraph(
                f"&bull; {item['name']} ({item['business_criticality']}): "
                f"{item['current_algorithm']} &rarr; {item['recommended_algorithm']}",
                styles["Normal"]
            ))
        story.append(Spacer(1, 0.3*cm))

    # --- Regulatory flags ---
    if report.get("regulatory_flags"):
        story.append(PageBreak())
        story.append(Paragraph("4. Regulatory / Compliance Triage Flags", styles["SectionHeading"]))
        story.append(Paragraph(
            "Automated triage suggestions only -- confirm with a compliance/legal reviewer.",
            styles["Disclaimer"]
        ))
        flagged = [f for f in report["regulatory_flags"] if f["frameworks"]]
        for f in flagged[:25]:
            story.append(Paragraph(f"&bull; <b>{f['artefact_id']}</b>: {', '.join(f['frameworks'])}", styles["Normal"]))

    doc.build(story)
    return output_path
