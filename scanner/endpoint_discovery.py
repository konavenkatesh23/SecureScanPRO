"""
SecureScanPRO
Endpoint Discovery Module
"""

from urllib.parse import urlparse


KEYWORDS = {

    "Login": [
        "login",
        "signin",
        "logon"
    ],

    "Register": [
        "register",
        "signup",
        "create-account"
    ],

    "Admin": [
        "admin",
        "administrator",
        "manage"
    ],

    "Dashboard": [
        "dashboard",
        "home"
    ],

    "API": [
        "api",
        "graphql",
        "rest"
    ],

    "Search": [
        "search",
        "find",
        "query"
    ],

    "Upload": [
        "upload",
        "file",
        "attachment"
    ],

    "Download": [
        "download",
        "export"
    ],

    "Profile": [
        "profile",
        "account",
        "user",
        "member"
    ],

    "Authentication": [
        "auth",
        "oauth",
        "token"
    ],

    "Password Reset": [
        "forgot",
        "reset",
        "reset-password"
    ]
}


def discover_endpoints(urls):

    discovered = {}

    for category in KEYWORDS:
        discovered[category] = []

    for url in urls:

        path = urlparse(url).path.lower()

        for category, words in KEYWORDS.items():

            if any(word in path for word in words):
                discovered[category].append(url)

    return discovered