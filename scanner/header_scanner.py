import requests

from scanner.cvss_calculator import calculate_cvss

# Security headers to check
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Missing Content Security Policy (CSP) header. This may increase the risk of Cross-Site Scripting (XSS).",
        "recommendation": "Implement a Content-Security-Policy header."
    },

    "Strict-Transport-Security": {
        "severity": "High",
        "description": "Missing HSTS header. Users may be vulnerable to SSL stripping attacks.",
        "recommendation": "Enable Strict-Transport-Security."
    },

    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Missing X-Frame-Options header. Website may be vulnerable to Clickjacking.",
        "recommendation": "Use X-Frame-Options: DENY or SAMEORIGIN."
    },

    "X-Content-Type-Options": {
        "severity": "Medium",
        "description": "Missing X-Content-Type-Options header.",
        "recommendation": "Use X-Content-Type-Options: nosniff."
    },

    "Referrer-Policy": {
        "severity": "Low",
        "description": "Missing Referrer-Policy header.",
        "recommendation": "Configure a Referrer-Policy."
    },

    "Permissions-Policy": {
        "severity": "Low",
        "description": "Missing Permissions-Policy header.",
        "recommendation": "Restrict unnecessary browser permissions."
    }
}


def scan_headers(urls):

    vulnerabilities = []

    for url in urls:

        try:

            response = requests.get(
                url,
                timeout=5,
                allow_redirects=True
            )

            headers = response.headers

            for header_name, info in SECURITY_HEADERS.items():

                if header_name not in headers:

                    vulnerabilities.append({

                        "url": url,

                        "header": header_name,

                        "severity": info["severity"],

                        "cvss_score": calculate_cvss(header_name),

                        "description": info["description"],

                        "recommendation": info["recommendation"]

                    })

        except Exception as e:

            print(f"Header Scan Error ({url}) : {e}")

    return vulnerabilities