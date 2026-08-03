import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


# File extensions to ignore
IGNORE_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico",
    ".css", ".js",
    ".pdf", ".zip", ".rar", ".7z",
    ".exe", ".msi", ".dmg", ".iso",
    ".mp3", ".wav", ".mp4", ".avi", ".mov",
    ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx",
    ".tar", ".gz", ".tgz",
    ".apk", ".bin", ".chm"
)


MAX_LINKS = 100


def crawl_website(target_url):

    visited = set()

    try:

        headers = {
            "User-Agent": "SecureScanPRO Scanner"
        }

        response = requests.get(
            target_url,
            headers=headers,
            timeout=10
        )

        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        domain = urlparse(target_url).netloc

        visited.add(target_url.rstrip("/"))

        for link in soup.find_all("a", href=True):

            href = link["href"].strip()

            absolute_url = urljoin(target_url, href)

            parsed = urlparse(absolute_url)

            # Only HTTP/HTTPS
            if parsed.scheme not in ("http", "https"):
                continue

            # Ignore external domains
            if parsed.netloc != domain:
                continue

            # Ignore query strings
            clean_url = parsed.scheme + "://" + parsed.netloc + parsed.path

            clean_url = clean_url.rstrip("/")

            # Ignore downloads/files
            if clean_url.lower().endswith(IGNORE_EXTENSIONS):
                continue

            # Ignore FTP folders
            if "/ftp/" in clean_url.lower():
                continue

            # Ignore duplicate URLs
            if clean_url in visited:
                continue

            visited.add(clean_url)

            # Limit crawl size
            if len(visited) >= MAX_LINKS:
                break

        return sorted(list(visited))

    except Exception as e:

        print("Crawler Error:", e)

        return []