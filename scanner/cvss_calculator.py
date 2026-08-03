"""
SecureScanPRO CVSS Calculator

Returns a default CVSS score for each supported vulnerability.
"""


def calculate_cvss(vulnerability_type):

    cvss_scores = {

        # Injection
        "SQL Injection": 9.8,
        "Cross-Site Scripting (XSS)": 8.0,

        # HTTP Headers
        "Content-Security-Policy": 7.5,
        "Strict-Transport-Security": 7.5,
        "X-Frame-Options": 6.5,
        "X-Content-Type-Options": 5.5,
        "Referrer-Policy": 3.5,
        "Permissions-Policy": 3.5,

        # Future Modules
        "Directory Traversal": 8.6,
        "Command Injection": 9.8,
        "Open Redirect": 6.1,
        "CSRF": 6.5,
        "Sensitive File Exposure": 5.3,
        "Information Disclosure": 5.0,
        "Weak Cookies": 4.5

    }

    return cvss_scores.get(vulnerability_type, 0.0)