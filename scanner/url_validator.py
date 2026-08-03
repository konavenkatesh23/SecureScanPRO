from urllib.parse import urlparse


def validate_url(url):
    """
    Validate the target URL.
    Returns True if the URL is valid, otherwise False.
    """

    try:
        result = urlparse(url)

        return all([
            result.scheme in ("http", "https"),
            result.netloc
        ])

    except Exception:
        return False