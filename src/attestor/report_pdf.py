from typing import Any, Dict

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas


def render_pdf(report_json: Dict[str, Any], output_path: str) -> None:
    pdf = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    y = height - inch

    metadata = report_json["metadata"]
    summary = report_json["summary"]["counts"]
    top_changes = report_json["top_changes"]

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(inch, y, "Ghost Utility Change-Only Security Attestation")
    y -= 0.5 * inch

    pdf.setFont("Helvetica", 11)
    pdf.drawString(inch, y, f"Account ID: {metadata['account_id']}")
    y -= 0.3 * inch
    pdf.drawString(inch, y, f"Region: {metadata['region']}")
    y -= 0.3 * inch
    pdf.drawString(inch, y, f"Run timestamp: {metadata['generated_at']}")
    y -= 0.5 * inch

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(inch, y, "What changed since last run")
    y -= 0.3 * inch
    pdf.setFont("Helvetica", 11)
    pdf.drawString(inch, y, f"IAM: {summary['IAM']} | Exposure: {summary['Exposure']} | Logging: {summary['Logging']}")
    y -= 0.5 * inch

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(inch, y, "Top 10 changes")
    y -= 0.3 * inch
    pdf.setFont("Helvetica", 10)
    for change in top_changes:
        line = f"[{change['severity']}] {change['category']} - {change['description']}"
        y = _draw_wrapped_line(pdf, line, inch, y, width - 2 * inch)
        y -= 0.1 * inch
        if y < inch:
            pdf.showPage()
            y = height - inch
            pdf.setFont("Helvetica", 10)

    pdf.showPage()
    _draw_section(pdf, "IAM Changes", report_json["sections"]["iam"])
    _draw_section(pdf, "Exposure Changes", report_json["sections"]["exposure"])
    _draw_section(pdf, "Logging Changes", report_json["sections"]["logging"])

    pdf.showPage()
    _draw_appendix(pdf, report_json["appendix"])

    pdf.save()


def _draw_section(pdf: canvas.Canvas, title: str, changes: list) -> None:
    width, height = letter
    y = height - inch
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(inch, y, title)
    y -= 0.4 * inch
    pdf.setFont("Helvetica", 10)
    if not changes:
        pdf.drawString(inch, y, "No changes detected.")
        return
    for change in changes:
        line = f"[{change['severity']}] {change['description']}"
        y = _draw_wrapped_line(pdf, line, inch, y, width - 2 * inch)
        evidence = f"Evidence: {change['evidence']}"
        y = _draw_wrapped_line(pdf, evidence, inch + 0.2 * inch, y - 0.1 * inch, width - 2.2 * inch)
        y -= 0.2 * inch
        if y < inch:
            pdf.showPage()
            y = height - inch
            pdf.setFont("Helvetica", 10)


def _draw_appendix(pdf: canvas.Canvas, appendix: Dict[str, Any]) -> None:
    width, height = letter
    y = height - inch
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(inch, y, "Appendix")
    y -= 0.4 * inch
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(inch, y, "Current-state summary")
    y -= 0.3 * inch
    pdf.setFont("Helvetica", 10)
    y = _draw_wrapped_line(pdf, str(appendix["current_state_summary"]), inch, y, width - 2 * inch)
    y -= 0.3 * inch

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(inch, y, "Suppressions applied")
    y -= 0.3 * inch
    pdf.setFont("Helvetica", 10)
    suppressions = appendix.get("suppressions_applied", [])
    if suppressions:
        for suppression in suppressions:
            y = _draw_wrapped_line(pdf, str(suppression), inch, y, width - 2 * inch)
            y -= 0.1 * inch
    else:
        pdf.drawString(inch, y, "None")
        y -= 0.2 * inch

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(inch, y, "Limitations")
    y -= 0.3 * inch
    pdf.setFont("Helvetica", 10)
    for limitation in appendix.get("limitations", []):
        y = _draw_wrapped_line(pdf, f"- {limitation}", inch, y, width - 2 * inch)
        y -= 0.1 * inch


def _draw_wrapped_line(pdf: canvas.Canvas, text: str, x: float, y: float, max_width: float) -> float:
    words = text.split()
    line = ""
    for word in words:
        test_line = f"{line} {word}".strip()
        if pdf.stringWidth(test_line, pdf._fontname, pdf._fontsize) > max_width:
            pdf.drawString(x, y, line)
            y -= 0.2 * inch
            line = word
        else:
            line = test_line
    if line:
        pdf.drawString(x, y, line)
    return y
