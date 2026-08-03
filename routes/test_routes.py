from flask import Blueprint, request

test_bp = Blueprint("test", __name__)


@test_bp.route("/test-sqli")
def test_sqli():

    user_id = request.args.get("id", "")

    # Common SQL Injection Payloads
    sql_payloads = [
        "'",
        '"',
        "--",
        "#",
        "/*",
        "*/",
        "union",
        "select",
        "or",
        "and",
        "sleep",
        "benchmark"
    ]

    # Simulate SQL Error
    for payload in sql_payloads:

        if payload.lower() in user_id.lower():

            return """
            <html>
            <head>
                <title>Database Error</title>
            </head>
            <body>

                <h2>Database Error</h2>

                <pre>
You have an error in your SQL syntax;
check the manual that corresponds to your MySQL server version
for the right syntax to use near ...
                </pre>

            </body>
            </html>
            """

    return f"""
    <html>
    <head>
        <title>SQL Injection Test</title>
    </head>
    <body>

        <h1>SecureScanPRO Test Page</h1>

        <p>User ID : {user_id}</p>

        <p>No SQL Injection detected.</p>

    </body>
    </html>
    """