import os

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from database import get_db_connection


def generate_pdf_report(scan_id):

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # ---------------------------------
    # Scan Details
    # ---------------------------------

    cursor.execute("""
        SELECT *
        FROM scans
        WHERE scan_id=%s
    """, (scan_id,))

    scan = cursor.fetchone()

    if not scan:

        cursor.close()
        connection.close()

        return None

    # ---------------------------------
    # Vulnerabilities
    # ---------------------------------

    cursor.execute("""
        SELECT *
        FROM vulnerabilities
        WHERE scan_id=%s
        ORDER BY cvss_score DESC
    """, (scan_id,))

    vulnerabilities = cursor.fetchall()

    cursor.close()
    connection.close()

    # ---------------------------------
    # Output Folder
    # ---------------------------------

    output_folder = os.path.join(
        os.getcwd(),
        "reports",
        "generated"
    )

    os.makedirs(output_folder, exist_ok=True)

    pdf_path = os.path.join(
        output_folder,
        f"SecureScanPRO_Report_{scan_id}.pdf"
    )

    # ---------------------------------
    # PDF Document
    # ---------------------------------

    document = SimpleDocTemplate(pdf_path)

    styles = getSampleStyleSheet()

    story = []

    # ---------------------------------
    # Title
    # ---------------------------------

    story.append(
        Paragraph(
            "<b><font size=18 color='blue'>SecureScanPRO</font></b>",
            styles["Title"]
        )
    )

    story.append(
        Paragraph(
            "Website Vulnerability Scan Report",
            styles["Heading2"]
        )
    )

    story.append(Spacer(1, 20))

    # ---------------------------------
    # Scan Information
    # ---------------------------------

    story.append(
        Paragraph(
            "<b>Scan Information</b>",
            styles["Heading2"]
        )
    )

    info = [

        ["Scan ID", str(scan["scan_id"])],

        ["Target URL", scan["target_url"]],

        ["Scan Type", scan["scan_type"]],

        ["Status", scan["status"]],

        ["Scan Date", str(scan["scan_date"])]

    ]

    table = Table(info, colWidths=[120, 360])

    table.setStyle(

        TableStyle([

            ("GRID", (0, 0), (-1, -1), 1, colors.black),

            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),

            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),

            ("BOTTOMPADDING", (0, 0), (-1, -1), 8)

        ])

    )

    story.append(table)

    story.append(Spacer(1, 20))

    # ---------------------------------
    # Summary
    # ---------------------------------

    critical = 0
    high = 0
    medium = 0
    low = 0

    for vuln in vulnerabilities:

        if vuln["severity"] == "Critical":
            critical += 1

        elif vuln["severity"] == "High":
            high += 1

        elif vuln["severity"] == "Medium":
            medium += 1

        else:
            low += 1

    summary = [

        ["Total Vulnerabilities", len(vulnerabilities)],

        ["Critical", critical],

        ["High", high],

        ["Medium", medium],

        ["Low", low]

    ]

    story.append(
        Paragraph(
            "<b>Summary</b>",
            styles["Heading2"]
        )
    )

    table = Table(summary, colWidths=[220, 100])

    table.setStyle(

        TableStyle([

            ("GRID", (0, 0), (-1, -1), 1, colors.black),

            ("BACKGROUND", (0, 0), (0, -1), colors.beige)

        ])

    )

    story.append(table)

    story.append(Spacer(1, 20))

    # ---------------------------------
    # Vulnerabilities
    # ---------------------------------

    story.append(
        Paragraph(
            "<b>Detected Vulnerabilities</b>",
            styles["Heading2"]
        )
    )

    data = [[

        "#",

        "Vulnerability",

        "Severity",

        "CVSS"

    ]]

    for i, vuln in enumerate(vulnerabilities, start=1):

        data.append([

            str(i),

            vuln["vulnerability_type"],

            vuln["severity"],

            str(vuln["cvss_score"])

        ])

    vuln_table = Table(
        data,
        colWidths=[40, 250, 90, 70]
    )

    vuln_table.setStyle(

        TableStyle([

            ("GRID", (0, 0), (-1, -1), 1, colors.black),

            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),

            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

            ("ALIGN", (0, 0), (-1, -1), "CENTER"),

            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),

            ("BOTTOMPADDING", (0, 0), (-1, 0), 8)

        ])

    )

    story.append(vuln_table)

    story.append(Spacer(1, 20))

    # ---------------------------------
    # Detailed Findings
    # ---------------------------------

    story.append(
        Paragraph(
            "<b>Detailed Findings</b>",
            styles["Heading2"]
        )
    )

    for index, vuln in enumerate(vulnerabilities, start=1):

        story.append(
            Paragraph(
                f"<b>{index}. {vuln['vulnerability_type']}</b>",
                styles["Heading3"]
            )
        )

        story.append(
            Paragraph(
                f"<b>URL:</b> {vuln['url']}",
                styles["BodyText"]
            )
        )

        story.append(
            Paragraph(
                f"<b>Severity:</b> {vuln['severity']}",
                styles["BodyText"]
            )
        )

        story.append(
            Paragraph(
                f"<b>Description:</b> {vuln['description']}",
                styles["BodyText"]
            )
        )

        story.append(
            Paragraph(
                f"<b>Recommendation:</b> {vuln['recommendation']}",
                styles["BodyText"]
            )
        )

        story.append(Spacer(1, 12))

    # ---------------------------------
    # Footer
    # ---------------------------------

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "<b>Generated by SecureScanPRO</b>",
            styles["Heading3"]
        )
    )

    story.append(
        Paragraph(
            "Automated Website Vulnerability Scanner",
            styles["Normal"]
        )
    )

    # ---------------------------------
    # Build PDF
    # ---------------------------------

    document.build(story)

    return pdf_path