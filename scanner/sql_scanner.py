import requests
from scanner.cvss_calculator import calculate_cvss
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SQL Injection Payloads
SQL_PAYLOADS = [
    "'",
    "\"",
    "'--",
    "\"--",
    "'#",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
    "' UNION SELECT NULL--",
    "' AND 1=1--",
    "' AND 1=2--",
    "admin'--"
]

# SQL Error Signatures
SQL_ERRORS = [

    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysqli",
    "mysql_num_rows",

    # PostgreSQL
    "postgresql",
    "pg_query",
    "pg_fetch",
    "pg_exec",

    # SQL Server
    "microsoft sql server",
    "odbc sql server driver",
    "unclosed quotation mark",
    "incorrect syntax",

    # Oracle
    "ora-",
    "oracle database",
    "quoted string not properly terminated",

    # SQLite
    "sqlite",
    "sqlite3",

    # Generic
    "sql syntax",
    "database error",
    "fatal error",
    "sqlstate",
    "jdbc",
    "syntax error"
]


def scan_sql_injection(url):

    findings = []

    parsed = urlparse(url)

    parameters = parse_qs(parsed.query)

    # Skip URLs without query parameters
    if not parameters:
        return findings

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecureScanPRO/1.0"
    }

    detected_urls = set()

    for parameter in parameters:

        original_value = parameters[parameter][0]

        for payload in SQL_PAYLOADS:

            test_params = parameters.copy()

            test_params[parameter] = original_value + payload

            test_query = urlencode(test_params, doseq=True)

            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                test_query,
                parsed.fragment
            ))

            print(f"[SQL] Testing: {test_url}")

            try:

                response = requests.get(
                    test_url,
                    headers=headers,
                    timeout=10,
                    verify=False,
                    allow_redirects=True
                )

                page = response.text.lower()

                # HTTP 500 detection
                if response.status_code == 500:

                    if test_url not in detected_urls:

                        detected_urls.add(test_url)

                        findings.append({

                            "url": test_url,

                            "vulnerability_type": "Possible SQL Injection",

                            "severity": "High",

                            "cvss_score": 8.5,

                            "description": "Server returned HTTP 500 after SQL Injection payload.",

                            "recommendation": "Validate user input and use prepared statements."

                        })

                # SQL Error Detection
                for error in SQL_ERRORS:

                    if error in page:

                        if test_url not in detected_urls:

                            detected_urls.add(test_url)

                            findings.append({

                                "url": test_url,

                                "vulnerability_type": "SQL Injection",

                                "severity": "Critical",

                                "cvss_score": calculate_cvss("SQL Injection"),

                                "description": f"Possible SQL Injection detected using payload '{payload}'.",

                                "recommendation": "Use prepared statements, parameterized queries, and validate all user input."

                            })

                        break

            except requests.exceptions.RequestException as e:

                print(f"[SQL] Request Failed: {e}")

                continue

    return findings