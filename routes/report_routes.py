from flask import (
    Blueprint,
    render_template,
    session,
    redirect,
    url_for,
    send_file,
    flash
)

from database import get_db_connection
from reports.pdf_generator import generate_pdf_report

report_bp = Blueprint("reports", __name__)


# ==========================================================
# Scan History
# ==========================================================

@report_bp.route("/history")
def history():

    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT *
        FROM scans
        WHERE user_id = %s
        ORDER BY scan_date DESC
    """, (session["user_id"],))

    scans = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "history.html",
        scans=scans
    )


# ==========================================================
# Scan Results
# ==========================================================

@report_bp.route("/results/<int:scan_id>")
def results(scan_id):

    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # -----------------------------------
    # Get Scan Information
    # -----------------------------------

    cursor.execute("""
        SELECT *
        FROM scans
        WHERE scan_id=%s
    """, (scan_id,))

    scan = cursor.fetchone()

    if not scan:

        cursor.close()
        connection.close()

        flash("Scan not found.", "danger")

        return redirect(url_for("reports.history"))

    # -----------------------------------
    # Get Vulnerabilities
    # -----------------------------------

    cursor.execute("""
        SELECT *
        FROM vulnerabilities
        WHERE scan_id=%s
        ORDER BY cvss_score DESC
    """, (scan_id,))

    vulnerabilities = cursor.fetchall()

    severity = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for vuln in vulnerabilities:

        if vuln["severity"] in severity:
            severity[vuln["severity"]] += 1

    cursor.close()
    connection.close()

    return render_template(
        "results.html",
        scan=scan,
        vulnerabilities=vulnerabilities,
        severity=severity,
        total_vulnerabilities=len(vulnerabilities)
    )


# ==========================================================
# Download PDF Report
# ==========================================================

@report_bp.route("/download/<int:scan_id>")
def download_report(scan_id):

    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    pdf_file = generate_pdf_report(scan_id)

    if pdf_file is None:

        flash("Unable to generate PDF report.", "danger")

        return redirect(
            url_for(
                "reports.results",
                scan_id=scan_id
            )
        )

    return send_file(
        pdf_file,
        as_attachment=True,
        download_name=f"SecureScanPRO_Report_{scan_id}.pdf",
        mimetype="application/pdf"
    )