"""
================================================================================
COM5413 — The Benji Protocol
Task 4: The Web Enumerator
File:   web_enum.py
================================================================================

MISSION BRIEF
-------------
The web layer talks too much. Server versions buried in HTTP headers. Developer
notes left in HTML comments. Sensitive paths left exposed because nobody
thought to check. Benji listens. A well-configured web server tells you almost
nothing; most servers are not well-configured.

Your job is to build an HTTP reconnaissance tool that extracts intelligence
from HTTP response headers and HTML source. This is passive reconnaissance —
you are reading what the server is already broadcasting, not probing for
weaknesses directly.

WHAT THIS SCRIPT MUST DO
-------------------------
1. Accept a target URL as a command-line argument.
2. Send an HTTP GET request and analyse the response headers for:
   - Server (e.g., Apache/2.2.8)
   - X-Powered-By (e.g., PHP/5.2.4)
   - Any other headers that reveal technology or version information.
3. Parse the HTML response using BeautifulSoup to extract:
   - All HTML comments (<!-- --> blocks) — flags are often hidden here.
4. Check for the existence of sensitive paths:
   - /robots.txt
   - /admin
   - /phpmyadmin
   - /login
   - /.git
   (Report found/not found for each — do not enumerate further.)
5. Output a structured summary (JSON or formatted plaintext).

CONSTRAINTS
-----------
- Python 3.10+ only.
- Must use requests and beautifulsoup4 (bs4).
- Set a request timeout (default 5s) — never hang.
- Handle redirects gracefully (requests does this by default — be aware of it).
- NO use of input() — all input via argparse.

OUTPUT CONTRACT (auto-grader depends on this)
---------------------------------------------
Print a summary containing at minimum:
    [HEADERS]
    Server: <value or "Not present">
    X-Powered-By: <value or "Not present">

    [COMMENTS]
    Found <n> HTML comment(s):
    1. <comment text>
    2. <comment text>

    [SENSITIVE PATHS]
    /robots.txt       → FOUND (200)
    /admin            → NOT FOUND (404)
    ...

EXAMPLE USAGE
-------------
    python web_enum.py http://192.168.56.101
    python web_enum.py http://192.168.56.101/dvwa --timeout 10

BUILD LOG
---------
Use docs/build.md to record what you find when running against Metasploitable.
HTML comments in particular — document what you find and what it implies.
This intelligence feeds directly into the Vulnerability Hunt diagnosis phase.
================================================================================
"""

# Your imports go here
import argparse
import sys

import requests
from bs4 import BeautifulSoup, Comment

# Sensitive paths to probe
SENSITIVE_PATHS = [
    "/robots.txt",
    "/admin",
    "/phpmyadmin",
    "/login",
    "/.git",
]


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="HTTP enumeration tool - analyze headers, extract comments, probe paths"
    )
    parser.add_argument("url", help="Target URL (e.g., http://127.0.0.1)")
    return parser.parse_args()


def analyse_headers(url: str) -> tuple[dict, str]:
    """
    Send a GET to the target URL.
    Return a dict of security-relevant headers and the response text.
    """
    response = requests.get(url, timeout=5)

    headers = {}
    headers["Server"] = response.headers.get("Server", "Not disclosed")
    headers["X-Powered-By"] = response.headers.get("X-Powered-By", "Not disclosed")

    return headers, response.text


def extract_comments(html: str) -> list[str]:
    """
    Parse HTML and return all comment strings, stripped of whitespace.
    """
    soup = BeautifulSoup(html, "html.parser")
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    return [c.strip() for c in comments]


def check_sensitive_paths(base_url: str, paths: list[str]) -> list[dict]:
    """
    Probe each path appended to the base URL.
    Return a list of dicts: {path, status_code, status}.
    """
    results = []

    for path in paths:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                status = "FOUND"
            elif resp.status_code == 404:
                status = "NOT FOUND"
            elif resp.status_code == 403:
                status = "FORBIDDEN"
            elif resp.status_code in (301, 302):
                status = "REDIRECT"
            else:
                status = f"HTTP {resp.status_code}"

            results.append(
                {
                    "path": path,
                    "status_code": resp.status_code,
                    "status": status,
                }
            )
        except requests.exceptions.RequestException:
            results.append(
                {
                    "path": path,
                    "status_code": None,
                    "status": "ERROR",
                }
            )

    return results


def main() -> None:
    """Coordinate: parse arguments, run analysis, format output."""
    args = parse_arguments()
    url = args.url

    # Phase 1: Headers and page content
    try:
        headers, html = analyse_headers(url)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not connect to {url}: {e}", file=sys.stderr)
        sys.exit(1)

    # Phase 2: Extract comments from page source
    comments = extract_comments(html)

    # Phase 3: Probe sensitive paths
    path_results = check_sensitive_paths(url, SENSITIVE_PATHS)

    # Output — three contracted sections as expected by the test
    print("[HEADERS]")
    for key, value in headers.items():
        print(f"  {key}: {value}")

    print()
    print("[COMMENTS]")
    if comments:
        for c in comments:
            print(f"  {c}")
    else:
        print("  No comments found.")

    print()
    print("[SENSITIVE PATHS]")
    for r in path_results:
        print(f"  {r['path']} — {r['status']} ({r['status_code']})")


if __name__ == "__main__":
    main()  # Only this call is necessary
