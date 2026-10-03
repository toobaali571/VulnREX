"""
report_generator.py
Builds a professional PDF vulnerability + reverse-engineering report
from a VulnREX scan result dict using ReportLab.
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

from vulnrex.utils import risk_rank, timestamp

RISK_COLORS = {
    "Critical": colors.HexColor("#b00020"),
    "High": colors.HexColor("#e65100"),
    "Medium": colors.HexColor("#f9a825"),
    "Low": colors.HexColor("#2e7d32"),
    "Informational": colors.HexColor("#546e7a"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="VulnrexTitle", parent=styles["Title"], fontSize=22,
        textColor=colors.HexColor("#1a237e"),
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader", parent=styles["Heading2"], fontSize=14,
        textColor=colors.HexColor("#1a237e"), spaceBefore=16, spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="Mono", parent=styles["Code"], fontSize=8, leading=10,
    ))
    return styles


def build_report(scan_result: dict, re_findings: list, output_path: str,
                  project_title: str = "VulnREX Assessment Report",
                  analyst: str = ""):
    """
    scan_result: dict as returned by NmapScanner.run_full_scan()
    re_findings: list of dicts from re_module.quick_triage(), one per
                 binary analyzed (may be empty)
    """
    styles = _styles()
    doc = SimpleDocTemplate(
        output_path, pagesize=LETTER,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )
    story = []

    # --- Cover ---
    story.append(Paragraph(project_title, styles["VulnrexTitle"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Target: {scan_result.get('target', 'N/A')}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {timestamp()}", styles["Normal"]))
    if analyst:
        story.append(Paragraph(f"Analyst: {analyst}", styles["Normal"]))
    story.append(Paragraph(
        "This report was produced by VulnREX for authorized security "
        "assessment and educational purposes only.",
        styles["Italic"],
    ))
    story.append(Spacer(1, 20))

    # --- Executive summary ---
    findings = scan_result.get("findings", [])
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        counts[f.get("risk", "Informational")] = counts.get(f.get("risk", "Informational"), 0) + 1

    story.append(Paragraph("Executive Summary", styles["SectionHeader"]))
    summary_rows = [["Risk Level", "Count"]] + [[k, str(v)] for k, v in counts.items()]
    t = Table(summary_rows, colWidths=[2.5 * inch, 1.5 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    # --- Host / port enumeration ---
    story.append(Paragraph("Host & Service Enumeration", styles["SectionHeader"]))
    for host in scan_result.get("hosts", []):
        story.append(Paragraph(
            f"<b>{host['host']}</b> — state: {host['state']}", styles["Normal"]
        ))
        if host.get("os_guesses"):
            os_str = "; ".join(f"{g['name']} ({g['accuracy']}%)" for g in host["os_guesses"])
            story.append(Paragraph(f"OS guess: {os_str}", styles["Normal"]))
        rows = [["Port", "Proto", "State", "Service", "Product/Version"]]
        for p in host.get("ports", []):
            rows.append([
                str(p["port"]), p["protocol"], p["state"], p["service"],
                f"{p.get('product', '')} {p.get('version', '')}".strip(),
            ])
        if len(rows) > 1:
            pt = Table(rows, colWidths=[0.6 * inch, 0.6 * inch, 0.7 * inch, 1.2 * inch, 2.4 * inch])
            pt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ]))
            story.append(pt)
        else:
            story.append(Paragraph("No open ports detected.", styles["Normal"]))
        story.append(Spacer(1, 10))

    # --- Vulnerability findings, sorted by severity ---
    story.append(PageBreak())
    story.append(Paragraph("Vulnerability Findings", styles["SectionHeader"]))
    if not findings:
        story.append(Paragraph("No NSE vulnerability script findings for this target.", styles["Normal"]))
    else:
        sorted_findings = sorted(findings, key=lambda f: risk_rank(f["risk"]), reverse=True)
        for f in sorted_findings:
            risk = f.get("risk", "Informational")
            color = RISK_COLORS.get(risk, colors.grey)
            header = f"{f['host']}:{f['port']}/{f['protocol']} — {f['service']} — {f['script']}"
            story.append(Paragraph(
                f'<font color="{color.hexval()}"><b>[{risk}]</b></font> {header}',
                styles["Normal"],
            ))
            if f.get("cves"):
                story.append(Paragraph("CVEs: " + ", ".join(f["cves"]), styles["Normal"]))
            snippet = f["output"][:1200]
            story.append(Paragraph(snippet.replace("\n", "<br/>"), styles["Mono"]))
            story.append(Spacer(1, 10))

    # --- Reverse engineering section ---
    # re_findings entries come from either re_module.quick_triage() (keys:
    # format, size_bytes, sample_strings) or re_module.run_headless_analysis()
    # via Ghidra (keys: program_name, language, functions, strings) -- handle
    # both shapes gracefully since a binary may have either or both run on it.
    if re_findings:
        story.append(PageBreak())
        story.append(Paragraph("Reverse Engineering Triage", styles["SectionHeader"]))
        for rf in re_findings:
            story.append(Paragraph(f"<b>File:</b> {rf.get('path', '')}", styles["Normal"]))

            if "format" in rf:
                story.append(Paragraph(
                    f"Format: {rf['format']} | Size: {rf.get('size_bytes', 0):,} bytes",
                    styles["Normal"],
                ))
            if "program_name" in rf:
                story.append(Paragraph(
                    f"Ghidra program: {rf.get('program_name', '')} | "
                    f"Language/arch: {rf.get('language', '')}",
                    styles["Normal"],
                ))
            if rf.get("functions"):
                fn_sample = ", ".join(f["name"] for f in rf["functions"][:25])
                story.append(Paragraph(
                    f"Functions identified: {len(rf['functions'])} (sample: {fn_sample})",
                    styles["Normal"],
                ))
            if rf.get("imports"):
                story.append(Paragraph(
                    "Imports (sample): " + ", ".join(rf["imports"][:25]), styles["Normal"]
                ))

            strings_list = rf.get("sample_strings") or rf.get("strings") or []
            if strings_list:
                story.append(Paragraph("Notable strings (sample):", styles["Normal"]))
                strs = "<br/>".join(s.replace("<", "&lt;").replace(">", "&gt;")
                                    for s in strings_list[:20])
                story.append(Paragraph(strs, styles["Mono"]))
            story.append(Spacer(1, 12))

    doc.build(story)
    return output_path
