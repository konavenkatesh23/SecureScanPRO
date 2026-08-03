from flask import Blueprint, render_template, session, redirect, url_for
from database import get_db_connection

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    user_id = session["user_id"]

    # Total Scans
    cursor.execute(
        "SELECT COUNT(*) AS total FROM scans WHERE user_id=%s",
        (user_id,)
    )
    total_scans = cursor.fetchone()["total"]

    # Total Vulnerabilities
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM vulnerabilities v
        INNER JOIN scans s
        ON v.scan_id=s.scan_id
        WHERE s.user_id=%s
    """, (user_id,))
    total_vulnerabilities = cursor.fetchone()["total"]

    # Total Reports
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM reports r
        INNER JOIN scans s
        ON r.scan_id=s.scan_id
        WHERE s.user_id=%s
    """, (user_id,))
    total_reports = cursor.fetchone()["total"]

    # Recent Scans
    cursor.execute("""
        SELECT *
        FROM scans
        WHERE user_id=%s
        ORDER BY scan_date DESC
        LIMIT 10
    """, (user_id,))

    recent_scans = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        total_scans=total_scans,
        total_vulnerabilities=total_vulnerabilities,
        total_reports=total_reports,
        recent_scans=recent_scans,
        risk_score=round(total_vulnerabilities * 5, 1)
    )