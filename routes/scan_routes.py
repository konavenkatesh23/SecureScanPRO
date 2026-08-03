from flask import Blueprint, render_template, request, redirect, url_for, session, flash

from database import get_db_connection

from scanner.url_validator import validate_url
from scanner.crawler import crawl_website
from scanner.endpoint_discovery import discover_endpoints
from scanner.header_scanner import scan_headers
from scanner.sql_scanner import scan_sql_injection
from scanner.xss_scanner import scan_xss

scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/scan")
def scan():

    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    return render_template("scan.html")


@scan_bp.route("/start_scan", methods=["POST"])
def start_scan():

    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    target_url = request.form.get("target_url", "").strip()
    scan_type = request.form.get("scan_type", "Full")

    # ----------------------------------
    # URL Validation
    # ----------------------------------

    if not validate_url(target_url):

        flash("Invalid URL!", "danger")
        return redirect(url_for("scan.scan"))

    # ----------------------------------
    # Crawl Website
    # ----------------------------------

    print("\nStarting Website Crawl...")

    links = crawl_website(target_url)

    # If crawler finds nothing,
    # scan the submitted URL itself.

    if not links:
        links = [target_url]

    print(f"Discovered {len(links)} URLs")

    # ----------------------------------
    # Endpoint Discovery
    # ----------------------------------

    print("\nRunning Endpoint Discovery...")

    endpoints = discover_endpoints(links)

    interesting = 0

    # ----------------------------------
    # Header Scanner
    # ----------------------------------

    print("\nRunning HTTP Security Header Scan...")

    header_results = scan_headers(links)

    # ----------------------------------
    # SQL Injection Scanner
    # ----------------------------------

    print("\nRunning SQL Injection Scan...")

    sql_results = []

    for url in links:

        try:

            findings = scan_sql_injection(url)

            if findings:
                sql_results.extend(findings)

        except Exception as e:

            print(f"SQL Scan Error ({url}) : {e}")

    # ----------------------------------
    # XSS Scanner
    # ----------------------------------

    print("\nRunning XSS Scan...")

    xss_results = []

    for url in links:

        try:

            findings = scan_xss(url)

            if findings:
                xss_results.extend(findings)

        except Exception as e:

            print(f"XSS Scan Error ({url}) : {e}")

    # ----------------------------------
    # Database
    # ----------------------------------

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        # ----------------------------------
        # Save Scan
        # ----------------------------------

        cursor.execute("""
            INSERT INTO scans
            (
                user_id,
                target_url,
                scan_type,
                status
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s
            )
        """,
        (
            session["user_id"],
            target_url,
            scan_type,
            "Completed"
        ))

        connection.commit()

        scan_id = cursor.lastrowid

        # ----------------------------------
        # Save Header Vulnerabilities
        # ----------------------------------

        for vuln in header_results:

            cursor.execute("""
                INSERT INTO vulnerabilities
                (
                    scan_id,
                    url,
                    vulnerability_type,
                    severity,
                    cvss_score,
                    description,
                    recommendation
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
            """,
            (
                scan_id,
                vuln["url"],
                vuln["header"],
                vuln["severity"],
                vuln["cvss_score"],
                vuln["description"],
                vuln["recommendation"]
            ))

        connection.commit()

        # ----------------------------------
        # Save SQL Injection Findings
        # ----------------------------------

        for vuln in sql_results:

            cursor.execute("""
                INSERT INTO vulnerabilities
                (
                    scan_id,
                    url,
                    vulnerability_type,
                    severity,
                    cvss_score,
                    description,
                    recommendation
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
            """,
            (
                scan_id,
                vuln["url"],
                vuln["vulnerability_type"],
                vuln["severity"],
                vuln["cvss_score"],
                vuln["description"],
                vuln["recommendation"]
            ))

        connection.commit()

        # ----------------------------------
        # Save XSS Findings
        # ----------------------------------

        for vuln in xss_results:

            cursor.execute("""
                INSERT INTO vulnerabilities
                (
                    scan_id,
                    url,
                    vulnerability_type,
                    severity,
                    cvss_score,
                    description,
                    recommendation
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
            """,
            (
                scan_id,
                vuln["url"],
                vuln["vulnerability_type"],
                vuln["severity"],
                vuln["cvss_score"],
                vuln["description"],
                vuln["recommendation"]
            ))

            connection.commit()

    except Exception as e:

        if connection:
            connection.rollback()

        print("\nDatabase Error:", e)

        flash("Error while saving scan results.", "danger")

        return redirect(url_for("scan.scan"))

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()
    # ----------------------------------
    # Console Output
    # ----------------------------------

    print("\n")
    print("=" * 80)
    print("                    SecureScanPRO Scan Report")
    print("=" * 80)

    print(f"\nTarget URL : {target_url}")
    print(f"Scan Type  : {scan_type}")
    print(f"Total URLs : {len(links)}")

    # ----------------------------------
    # Endpoint Discovery
    # ----------------------------------

    print("\n")
    print("=" * 80)
    print("Endpoint Discovery")
    print("=" * 80)

    for category, urls in endpoints.items():

        if urls:

            print(f"\n{category} ({len(urls)})")

            for url in urls:
                print("   ", url)

            interesting += len(urls)

    print("\nInteresting Endpoints :", interesting)

    # ----------------------------------
    # Header Scan Results
    # ----------------------------------

    print("\n")
    print("=" * 80)
    print("HTTP Security Header Scan")
    print("=" * 80)

    if not header_results:

        print("\nNo Header Vulnerabilities Found.")

    else:

        for vuln in header_results:

            print("\nURL            :", vuln["url"])
            print("Header         :", vuln["header"])
            print("Severity       :", vuln["severity"])
            print("CVSS Score     :", vuln["cvss_score"])
            print("Description    :", vuln["description"])
            print("Recommendation :", vuln["recommendation"])

    # ----------------------------------
    # SQL Injection Results
    # ----------------------------------

    print("\n")
    print("=" * 80)
    print("SQL Injection Scan")
    print("=" * 80)

    if not sql_results:

        print("\nNo SQL Injection Vulnerabilities Found.")

    else:

        for vuln in sql_results:

            print("\nURL            :", vuln["url"])
            print("Vulnerability  :", vuln["vulnerability_type"])
            print("Severity       :", vuln["severity"])
            print("CVSS Score     :", vuln["cvss_score"])
            print("Description    :", vuln["description"])
            print("Recommendation :", vuln["recommendation"])

    # ----------------------------------
    # XSS Results
    # ----------------------------------

    print("\n")
    print("=" * 80)
    print("Cross-Site Scripting (XSS) Scan")
    print("=" * 80)

    if not xss_results:

        print("\nNo XSS Vulnerabilities Found.")

    else:

        for vuln in xss_results:

            print("\nURL            :", vuln["url"])
            print("Vulnerability  :", vuln["vulnerability_type"])
            print("Severity       :", vuln["severity"])
            print("CVSS Score     :", vuln["cvss_score"])
            print("Description    :", vuln["description"])
            print("Recommendation :", vuln["recommendation"])

    # ----------------------------------
    # Final Summary
    # ----------------------------------

    header_count = len(header_results)
    sql_count = len(sql_results)
    xss_count = len(xss_results)

    total_vulnerabilities = (
        header_count +
        sql_count +
        xss_count
    )

    print("\n")
    print("=" * 80)
    print("Scan Summary")
    print("=" * 80)

    print(f"Header Vulnerabilities : {header_count}")
    print(f"SQL Injection Findings : {sql_count}")
    print(f"XSS Findings           : {xss_count}")
    print("-" * 80)
    print(f"Total Vulnerabilities  : {total_vulnerabilities}")
    print("=" * 80)

    flash("Scan Completed Successfully!", "success")

    # ----------------------------------
    # Redirect to Results
    # ----------------------------------

    return redirect(
        url_for(
            "reports.results",
            scan_id=scan_id
        )
    )