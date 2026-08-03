from flask import Blueprint, request

xss_test_bp = Blueprint("xss_test", __name__)


@xss_test_bp.route("/test-xss")
def test_xss():

    name = request.args.get("name", "")

    return f"""
    <html>
        <head>
            <title>XSS Test</title>
        </head>
        <body>

            <h2>Welcome</h2>

            {name}

        </body>
    </html>
    """