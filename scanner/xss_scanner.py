import requests
from scanner.cvss_calculator import calculate_cvss
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Common XSS payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>"
]


def scan_xss(url):
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    for param in params:

        for payload in XSS_PAYLOADS:

            test_params = params.copy()
            test_params[param] = payload

            new_query = urlencode(test_params, doseq=True)

            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))

            try:
                response = requests.get(test_url, timeout=5)

                # Reflected XSS Detection
                if payload in response.text:

                    findings.append({
                        "url": test_url,
                        "vulnerability_type": "Cross-Site Scripting (XSS)",
                        "severity": "High",
                        "cvss_score": calculate_cvss("Cross-Site Scripting (XSS)"),
                        "description": f"Possible Reflected XSS detected using payload '{payload}'.",
                        "recommendation": "Validate user input and encode output before rendering HTML."
                    })

            except Exception:
                pass

    return findings