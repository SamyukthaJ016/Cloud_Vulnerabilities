from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


OUT = Path(__file__).with_name("grc-compliance-one-page-writeup.pdf")


def para(text, style):
    return Paragraph(text, style)


def main():
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#123C36"),
        spaceAfter=5,
    )
    h = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=13,
        textColor=colors.HexColor("#12715F"),
        spaceBefore=4,
        spaceAfter=3,
    )
    body = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8.4,
        leading=10.5,
        textColor=colors.HexColor("#1F2933"),
        spaceAfter=3,
    )
    small = ParagraphStyle(
        "Small",
        parent=body,
        fontSize=7.7,
        leading=9.5,
    )

    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=A4,
        rightMargin=14 * mm,
        leftMargin=14 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
    )

    story = []
    story.append(para("Compliance and Governance: GRC Layer with Cloud Scanner Evidence", title))
    story.append(para("Objective", h))
    story.append(para(
        "Create a central GRC layer that converts technical findings into control status, risk visibility, remediation ownership, and audit-ready evidence. CloudGuard acts as a technical evidence source for cloud, Kubernetes, and IaC controls.",
        body,
    ))

    story.append(para("Highlights", h))
    highlights = [
        ["GRC function", "Policies, controls, risks, audits, exceptions, remediation, and evidence in one governance view."],
        ["Evidence sources", "LogManthan, infrastructure scanners, asset inventory, SAST, DAST/Burp, Keycloak/IAM, DPDP inputs, and CloudGuard cloud scanners."],
        ["Cloud scanner role", "AWS, GCP, Kubernetes, and IaC scan results are normalized into control evidence."],
        ["Control mapping", "Findings map to DPDP, ISO 27001, CIS, NIST, OWASP, Kubernetes benchmark, and internal policies."],
    ]
    table = Table(
        [[para(a, small), para(b, small)] for a, b in highlights],
        colWidths=[35 * mm, 130 * mm],
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8F7F2")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0B5E4F")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8D8D0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)
    story.append(Spacer(1, 3 * mm))

    story.append(para("Technical Summary", h))
    story.append(para(
        "The architecture uses a connector-based evidence pipeline. Each scanner or source system sends normalized evidence to an ingestion API. The ingestion layer validates the payload, stores raw artifacts in object storage, stores metadata and mappings in PostgreSQL, and updates the GRC dashboard. Scanner jobs remain decoupled from the portal through worker containers so heavy scans do not block the dashboard.",
        body,
    ))

    story.append(para("Setup View", h))
    setup = [
        ["Public routes", "app.cloudscanner.com for dashboard, api.cloudscanner.com for APIs, ingest.cloudscanner.com for evidence ingestion."],
        ["Runtime", "Docker Compose stack managed through Dokploy on a VM for the PoC."],
        ["Core services", "Backend/API, PostgreSQL, object storage, scheduler worker, scan worker, evidence connector."],
        ["Expected output", "Compliance dashboard, control status, evidence trail, remediation owner, audit report, and executive summary."],
    ]
    setup_table = Table(
        [[para(a, small), para(b, small)] for a, b in setup],
        colWidths=[35 * mm, 130 * mm],
    )
    setup_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#FFF4DC")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#805700")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E4C887")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(setup_table)

    story.append(Spacer(1, 3 * mm))
    story.append(para(
        "<b>One-line summary:</b> The GRC layer gives leadership, auditors, and engineering teams one common view of compliance posture by converting scanner outputs and manual evidence into control-mapped, traceable, and actionable governance records.",
        body,
    ))

    doc.build(story)
    print(OUT)


if __name__ == "__main__":
    main()
